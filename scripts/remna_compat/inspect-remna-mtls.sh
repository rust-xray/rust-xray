#!/usr/bin/env bash
# Inspect Remnawave Node mTLS cert sources for XTLS API (127.0.0.1:61000).
# Run inside remnanode:
#   docker exec -it remnanode sh -lc 'bash /path/to/inspect-remna-mtls.sh'
set -euo pipefail

section() {
  echo ""
  echo "======== $1 ========"
}

section "grep Remnawave mTLS / XTLS SDK hints (first 300 lines)"
grep -R "getClientCerts\|initializeMTLSCerts\|clientKeyPem\|clientCertPem\|caCertPem\|internal\.remnawave\.local\|ChannelCredentials\.createSsl\|getServerCerts\|generateMTLSCertificates" \
  -n /opt/app /app /usr/local/lib/node_modules 2>/dev/null | head -300 || true

section "environment (cert/key/ca/tls/ssl/xray/xtls/api)"
env | sort | grep -Ei 'cert|key|ca|tls|ssl|xray|xtls|api|secret|mtls' || true

section "candidate cert/key/pem files under /run /tmp /opt/app /app"
find /run /tmp /opt/app /app -type f 2>/dev/null | grep -Ei 'cert|key|pem|ca|mtls' || true

section "Remnawave generate-mtls-certs (in-memory store)"
grep -R "mtlsCerts\|getMTLSCerts\|getServerCerts\|getClientCerts" -n /app /opt/app 2>/dev/null | head -80 || true

section "API inbound tlsSettings in live get-config (if curl available)"
if [[ -n "${INTERNAL_SOCKET_PATH:-}" && -n "${INTERNAL_REST_TOKEN:-}" ]]; then
  CONFIG_JSON="$(curl -sS --unix-socket "${INTERNAL_SOCKET_PATH}" \
    "http://localhost/internal/get-config?token=${INTERNAL_REST_TOKEN}" 2>/dev/null || true)"
  if [[ -n "${CONFIG_JSON}" ]]; then
    echo "${CONFIG_JSON}" | grep -E 'tlsSettings|serverCertPem|caCertPem|internal\.remnawave\.local|REMNAWAVE_API_INBOUND' | head -40 || true
  else
    echo "WARN could not fetch internal get-config"
  fi
else
  echo "HINT set INTERNAL_SOCKET_PATH and INTERNAL_REST_TOKEN inside container to dump live tlsSettings"
fi

section "rust-xray API log tail"
if [[ -r /var/log/supervisor/xray.out.log ]]; then
  tail -80 /var/log/supervisor/xray.out.log
else
  echo "WARN /var/log/supervisor/xray.out.log not found"
fi

echo ""
echo "Done."
echo "Expected: Remnawave Node keeps XTLS mTLS CA/server/client PEM in process memory (initializeMTLSCerts)."
echo "Expected: get-config injects server cert/key + verify CA into API inbound streamSettings.tlsSettings."
echo "If no PEM files exist on disk, rust-xray must read tlsSettings from loaded config (not auto-generate unrelated CA)."
