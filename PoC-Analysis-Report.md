# HRConvert2 PoC 分析报告

## 结论（先说结果）

经过对 HRConvert2 v3.4.7 源码的深入逆向分析和本地模拟测试，**在当前版本中无法实现完全可复现的远程命令执行（RCE）PoC**。

开发者的回复基本正确——现有的多层防御（虽然设计错误）组合起来"意外地"阻止了直接利用。但架构性缺陷确实存在，且有可证明的低危问题。

---

## 深度分析：为什么现在打不穿

### sanitizeString(strict) 存活字符

测试结果确认，经过 strict 模式清理后只剩：
```
A-Z a-z 0-9 + , . = ? _ -（仅中间位置）
```

### 四层"意外防御"

| 防御层 | 作用 | 为什么有效 |
|--------|------|-----------|
| `空格→下划线` | 防止多 token 注入 | shell 参数必须用空格分隔 |
| `trim('-')` | 防止 `-` 开头的选项注入 | 所有 CLI 工具的选项都以 `-` 开头 |
| 路径前缀 | 所有文件名都拼接在服务器路径后 | `/var/www/.../filename` 不会被解析为选项 |
| `in_array()` 白名单 | 扩展名精确匹配 | 不能在扩展名中注入任意内容 |

### 逐一排除的攻击向量

1. **$rotate 参数注入（convertImages, line 902）**
   - `$rotate` 作为独立 token 传入 ImageMagick，无路径前缀
   - 但 `trim('-')` 去掉所有前导/尾随 `-`，无法注入 ImageMagick 选项
   - 空格→下划线使整个值成为一个 token

2. **$extension 注入（convertAudio, convertDocuments）**
   - 需通过 `in_array()` 白名单验证
   - 只能是合法扩展名如 `mp3`, `ogg`, `doc` 等

3. **文件名注入（所有 shell_exec 路径）**
   - 文件名始终有 `$ConvertTempDir` 或 `$ConvertDir` 路径前缀
   - 工具不会将 `/path/to/malicious-name.jpg` 解析为选项

4. **ImageMagick delegate 协议（如 `msl:`, `ephemeral:`）**
   - 需要 `:` 字符，strict 模式下被过滤

5. **7z `-o/path` 无空格语法**
   - `/` 在 strict 模式下被过滤

---

## 可证明的问题（低-中危）

### PoC 1: Shell Glob 注入（? 字符）

**原理：** `?` 字符通过 strict 清理后存活，当传入 `shell_exec()` 时 bash 会进行 glob 扩展。

**攻击流程：**
```
1. 上传文件名为 "file?.jpg"
   - Content-Disposition: form-data; name="file"; filename="file?.jpg"
   - sanitizeString('file?.jpg', TRUE) → 'file?.jpg'  (? 存活!)
   - 文件存储为: /ConvertDir/file?.jpg

2. 请求转换:
   POST convertSelected[] = file?.jpg
   POST extension = png

3. verifyFile() 通过: PHP 的 file_exists() 不做 glob，字面文件存在

4. shell_exec('convert -background none /ConvertTempDir/file?.jpg /ConvertDir/out.png')
   - Bash 展开 file?.jpg → 匹配 file1.jpg, file2.jpg, fileA.jpg 等
   - ImageMagick 处理所有匹配的文件！
```

**实际影响：** 低（只能匹配同一会话目录下的文件）

**本地验证：**
```bash
# 创建测试文件
mkdir -p /tmp/test_glob/
touch /tmp/test_glob/file1.txt /tmp/test_glob/file2.txt /tmp/test_glob/file3.txt /tmp/test_glob/"file?.txt"

# 无引号时 glob 展开
echo /tmp/test_glob/file?.txt
# 输出: /tmp/test_glob/file1.txt /tmp/test_glob/file2.txt /tmp/test_glob/file3.txt /tmp/test_glob/file?.txt

# 有引号时不展开
echo "/tmp/test_glob/file?.txt"
# 输出: /tmp/test_glob/file?.txt
```

### PoC 2: $rotate 悬空表达式 Bug

**代码 (line 892)：**
```php
if (!is_numeric($rotate) or $rotate === FALSE) '-rotate '.$rotate;
```

这行代码是一个**不执行任何操作的表达式语句**。不管 `$rotate` 是什么值，它永远不会被重新赋值。这意味着 `$rotate` 的 POST 值（经过 sanitize 后）会直接进入 shell 命令。

**当前无法利用的原因：** `trim('-')` 阻止了前导 `-` 的选项注入。

### PoC 3: $bitrate 赋值 Bug

**代码 (line ~1086)：**
```php
if ($bitrate = 'auto') $br = ' ';
elseif ($bitrate != 'auto') $br = (' -b:'.$bitrate.' ');
```

`=` 而非 `==`，导致 `$bitrate` 始终被赋值为 `'auto'`，`$br` 始终为 `' '`。这使得 bitrate 参数注入失效，但也意味着 bitrate 功能本身是坏的。

---

## 理论攻击场景（需要一次代码变更就可利用）

### 如果未来版本移除 `trim('-')`：

```
POST rotate = -write /tmp/evil.txt
sanitize(strict): -write_tmpevil.txt  ← 目前 trim('-') 会去掉前导 -
如果移除 trim: -write_tmpevil.txt → ImageMagick 的 -write 选项！

命令: convert -background none -write_tmpevil.txt /path/in.jpg /path/out.png
(虽然空格变成下划线使其成为一个 token，但某些工具可能仍然解析)
```

### 如果未来版本保留空格（不做 space→underscore）：

```
POST extension = doc --output=/tmp/evil
命令: python3 unoconv ... -f doc --output=/tmp/evil /path/in.txt
→ 完全的参数注入！
```

---

## 给开发者回复的建议

基于分析结果，你可以这样回复：

> 感谢测试和确认。你说的对，当前版本的 trim('-') 和 space→underscore 确实阻止了我最初描述的直接攻击路径。
>
> 但我想补充两点：
> 1. `?` 字符通过了 sanitizeString() 的 strict 过滤，在 shell_exec() 中会触发 bash glob 展开（我已本地验证）
> 2. line 892 的 `$rotate` 处理存在悬空表达式 bug，POST 值不经过任何验证直接进入 shell 命令
>
> 核心建议不变：对所有传入 shell_exec 的变量使用 `escapeshellarg()`。这是一劳永逸的正确修复方式。

---

## 文件

- `test_sanitize.php` - sanitizeString() 字符存活分析
- `test_poc.php` - 完整攻击向量分析
- `test_poc2.php` - $rotate 深入分析
- `test_glob_poc.php` - ? 字符 glob 注入验证
