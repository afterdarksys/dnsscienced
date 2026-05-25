#!/usr/bin/env bash
# Generate mTLS certificates for dnsscienced gRPC admin API
#
# Produces:
#   ca.crt              — CA certificate (shared trust anchor)
#   ns1.idoms.net.crt   — server cert for ns1
#   ns1.idoms.net.key   — server key for ns1
#   ns2.idoms.net.crt   — server cert for ns2
#   ns2.idoms.net.key   — server key for ns2
#   client.crt          — client cert for onedns.io
#   client.key          — client key for onedns.io
#
# Deploy:
#   ns1/ns2:    copy ca.crt, nsX.idoms.net.crt, nsX.idoms.net.key to /etc/dnsscienced/tls/
#   onedns.io:  copy ca.crt, client.crt, client.key to /etc/onedns/tls/ (or set env vars)
#
# dnsscienced config (admin section):
#   admin:
#     tls_cert_file: /etc/dnsscienced/tls/nsX.idoms.net.crt
#     tls_key_file:  /etc/dnsscienced/tls/nsX.idoms.net.key
#     tls_client_cas: /etc/dnsscienced/tls/ca.crt
#
# onedns.io env vars:
#   GRPC_CA_CERT=/etc/onedns/tls/ca.crt
#   GRPC_CLIENT_CERT=/etc/onedns/tls/client.crt
#   GRPC_CLIENT_KEY=/etc/onedns/tls/client.key

set -euo pipefail

OUT="${1:-./grpc-certs}"
mkdir -p "$OUT"
cd "$OUT"

DAYS=3650  # 10 years
ORG="AfterDark Systems"

echo "==> Generating CA key + certificate"
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days $DAYS -key ca.key -out ca.crt \
  -subj "/CN=dnsscienced-grpc-ca/O=${ORG}"

gen_server_cert() {
  local HOST="$1"
  echo "==> Generating server cert for $HOST"
  openssl genrsa -out "${HOST}.key" 2048
  openssl req -new -key "${HOST}.key" -out "${HOST}.csr" \
    -subj "/CN=${HOST}/O=${ORG}"
  openssl x509 -req -days $DAYS \
    -in "${HOST}.csr" \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "${HOST}.crt" \
    -extfile <(printf "subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\n" "$HOST")
  rm "${HOST}.csr"
  chmod 600 "${HOST}.key"
}

gen_server_cert "ns1.idoms.net"
gen_server_cert "ns2.idoms.net"

echo "==> Generating client cert for onedns.io"
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "/CN=onedns.io-client/O=${ORG}"
openssl x509 -req -days $DAYS \
  -in client.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt
rm client.csr
chmod 600 client.key ca.key

echo ""
echo "==> Certificates written to: $OUT"
echo ""
echo "--- Deploy to ns1 ---"
echo "  scp -J root@108.165.123.229 ${OUT}/ca.crt ${OUT}/ns1.idoms.net.crt ${OUT}/ns1.idoms.net.key root@166.0.192.27:/etc/dnsscienced/tls/"
echo ""
echo "--- Deploy to ns2 ---"
echo "  scp -J root@108.165.123.229 ${OUT}/ca.crt ${OUT}/ns2.idoms.net.crt ${OUT}/ns2.idoms.net.key root@108.165.120.57:/etc/dnsscienced/tls/"
echo ""
echo "--- Add to /etc/dnsscienced/config.yaml on each server (admin section) ---"
echo "  tls_cert_file: /etc/dnsscienced/tls/nsX.idoms.net.crt"
echo "  tls_key_file:  /etc/dnsscienced/tls/nsX.idoms.net.key"
echo "  tls_client_cas: /etc/dnsscienced/tls/ca.crt"
echo ""
echo "--- Set on onedns.io ---"
echo "  GRPC_CA_CERT=/etc/onedns/tls/ca.crt"
echo "  GRPC_CLIENT_CERT=/etc/onedns/tls/client.crt"
echo "  GRPC_CLIENT_KEY=/etc/onedns/tls/client.key"
