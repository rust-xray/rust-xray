#!/usr/bin/env bash
# Collect Remnawave/XTLS-SDK hints for why the internal API client may use TLS.
# Run inside remnanode: docker exec -it remnanode sh -lc 'bash /path/to/inspect-remna-api-mode.sh'
set -euo pipefail

section() {
  echo ""
  echo "======== $1 ========"
}

section "environment (xray/xtls/grpc/tls/api)"
env | sort | grep -Ei 'xray|xtls|core|grpc|ssl|tls|api|secure|plain|insecure|cert|key' || true

section "process args (node / rw-core / xray)"
ps aux | grep -E 'node|rw-core|xray' | grep -v grep || true

section "supervisord"
if [[ -r /etc/supervisord.conf ]]; then
  cat /etc/supervisord.conf
else
  echo "WARN /etc/supervisord.conf not readable"
fi

section "grep XTLS_API / TLS / grpc in /app /opt /etc (first 200)"
grep -R 'XTLS_API\|TLS\|SSL\|secure\|insecure\|grpc' -n /app /opt /etc 2>/dev/null | head -200 || true

section "node dist files (sample)"
find /app -maxdepth 4 -type f \( -name '*.js' -o -name '*.json' \) 2>/dev/null | head -40 || true

section "grpc/tls credentials in /app/dist (first 100)"
grep -R 'createSsl\|ChannelCredentials\|createInsecure\|grpc\.credentials\|tls' -n /app/dist 2>/dev/null | head -100 || true

section "rust-xray API log tail"
if [[ -r /var/log/supervisor/xray.out.log ]]; then
  tail -80 /var/log/supervisor/xray.out.log
else
  echo "WARN /var/log/supervisor/xray.out.log not found"
fi

section "listener on 61000"
ss -lntp 2>/dev/null | grep 61000 || netstat -lntp 2>/dev/null | grep 61000 || true

echo ""
echo "Done. If TLS_TO_PLAINTEXT_CONFIRMED from check-api.sh, look for createSsl / secure channel above."
