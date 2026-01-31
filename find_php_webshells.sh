#!/usr/bin/env bash
# Usage: ./find_php_webshells.sh /var/www/html

set -euo pipefail

DOCROOT="${1:-.}"

echo "[+] Scanning PHP application at: $DOCROOT"
echo

# High-risk functions and obfuscation patterns
PATTERN='eval\s*\(|assert\s*\(|system\s*\(|shell_exec\s*\(|exec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(|base64_decode\s*\(|gzinflate\s*\(|gzuncompress\s*\(|str_rot13\s*\('

echo "[*] Searching for suspicious PHP function usage..."
grep -RIn --color=always -E "$PATTERN" "$DOCROOT" \
  --include="*.php" \
  --exclude-dir={vendor,node_modules} \
  > suspicious_functions.txt || true

echo "    -> Results written to suspicious_functions.txt"

echo
echo "[*] Looking for PHP files in common drop locations..."
find "$DOCROOT" \
  \( -path "*/uploads/*" -o -path "*/cache/*" -o -path "*/tmp/*" \) \
  -type f -iname "*.php" \
  > suspicious_locations.txt

echo "    -> Results written to suspicious_locations.txt"

echo
echo "[*] Finding recently modified PHP files (last 7 days)..."
find "$DOCROOT" -type f -iname "*.php" -mtime -7 \
  > recent_php_files.txt

echo "    -> Results written to recent_php_files.txt"

echo
echo "[+] Scan complete."
echo "Review the following files:"
echo "  - suspicious_functions.txt"
echo "  - suspicious_locations.txt"
echo "  - recent_php_files.txt"
