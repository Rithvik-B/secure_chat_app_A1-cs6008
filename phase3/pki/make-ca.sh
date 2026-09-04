#!/usr/bin/env bash
# Create the Certificate Authority: a private key and a self-signed root cert.
# The CA key is the trust anchor's secret; only ca-cert.pem is distributed.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out

openssl genrsa -out out/ca-key.pem 4096

openssl req -x509 -new -key out/ca-key.pem -sha256 -days 3650 \
    -subj "/C=IN/O=CS6008 Secure Chat/CN=CS6008 Root CA" \
    -out out/ca-cert.pem

echo "CA created:"
echo "  out/ca-key.pem   (SECRET - never leaves the CA host)"
echo "  out/ca-cert.pem  (trust anchor - distributed to every client)"
