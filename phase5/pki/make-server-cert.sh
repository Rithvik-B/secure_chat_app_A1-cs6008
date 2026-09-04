#!/usr/bin/env bash
# Issue the server certificate: generate the server key, build a CSR, and have
# the CA sign it. SANs bind the cert to chatserver.local and 10.10.0.10.
#   usage: make-server-cert.sh [CN] [days]
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out
CN="${1:-chatserver.local}"
DAYS="${2:-825}"

openssl genrsa -out out/server-key.pem 2048

openssl req -new -key out/server-key.pem \
    -subj "/C=IN/O=CS6008 Secure Chat/CN=$CN" \
    -out out/server.csr

cat > out/server-ext.cnf <<'EOF'
subjectAltName   = DNS:chatserver.local, IP:10.10.0.10
basicConstraints = CA:FALSE
keyUsage         = digitalSignature, keyEncipherment
EOF

openssl x509 -req -in out/server.csr \
    -CA out/ca-cert.pem -CAkey out/ca-key.pem -CAcreateserial \
    -sha256 -days "$DAYS" -extfile out/server-ext.cnf \
    -out out/server-cert.pem

echo "Server certificate issued: out/server-cert.pem  (CN=$CN)"
openssl verify -CAfile out/ca-cert.pem out/server-cert.pem
