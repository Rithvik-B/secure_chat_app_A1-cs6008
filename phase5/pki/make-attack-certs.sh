#!/usr/bin/env bash
# Certificates used only to test that validation rejects bad ones:
#   mallory-*   a self-signed cert with the right name but no CA signature
#   expired-*   a CA-signed cert whose validity window is in the past
#   wrongname-* a CA-signed cert for a different identity
# Requires make-ca.sh to have run first.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out

# 1. Mallory's self-signed cert (correct CN, but not signed by our CA).
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout out/mallory-key.pem -out out/mallory-cert.pem \
    -subj "/C=IN/O=CS6008 Secure Chat/CN=chatserver.local" \
    -addext "subjectAltName = DNS:chatserver.local, IP:10.10.0.10"

# 2. A key Mallory owns, for the stolen-cert attack (she signs with this while
#    presenting the real server-cert.pem she copied but cannot match).
openssl genrsa -out out/mallory-own-key.pem 2048

# 3. Wrong-identity cert: CA-signed and valid, but for a different name.
openssl genrsa -out out/wrongname-key.pem 2048
openssl req -new -key out/wrongname-key.pem \
    -subj "/C=IN/O=CS6008 Secure Chat/CN=evil.example.com" -out out/wrongname.csr
cat > out/wrongname-ext.cnf <<'EOF'
subjectAltName   = DNS:evil.example.com
basicConstraints = CA:FALSE
EOF
openssl x509 -req -in out/wrongname.csr -CA out/ca-cert.pem -CAkey out/ca-key.pem \
    -CAcreateserial -sha256 -days 825 -extfile out/wrongname-ext.cnf \
    -out out/wrongname-cert.pem

# 4. Expired cert: CA-signed but its validity window is in the past. Needs the
#    -not_before/-not_after options (OpenSSL >= 3.2); skipped gracefully if absent.
if openssl x509 -help 2>&1 | grep -q not_after; then
    openssl genrsa -out out/expired-key.pem 2048
    openssl req -new -key out/expired-key.pem \
        -subj "/C=IN/O=CS6008 Secure Chat/CN=chatserver.local" -out out/expired.csr
    openssl x509 -req -in out/expired.csr -CA out/ca-cert.pem -CAkey out/ca-key.pem \
        -CAcreateserial -sha256 -extfile out/server-ext.cnf \
        -not_before 20200101000000Z -not_after 20200102000000Z \
        -out out/expired-cert.pem
    echo "expired-cert.pem created"
else
    echo "note: OpenSSL < 3.2 has no -not_after; expired-cert.pem skipped on this host"
fi

echo "Attack/test certs written to out/"
