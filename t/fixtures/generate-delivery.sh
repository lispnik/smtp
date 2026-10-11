#!/bin/sh
# Regenerate the certificates for the direct-delivery tests (t/delivery.lisp):
# a CA of their own, a server certificate for the test MX and MTA-STS hosts,
# and one for an unrelated name. Backdated like those of generate.sh.
set -e
cd "$(dirname "$0")"
openssl req -x509 -new -newkey rsa:2048 -nodes -keyout delivery-ca-key.pem -out delivery-ca.pem \
  -not_before 20190101000000Z -not_after 21190101000000Z -subj "/CN=smtp delivery test CA" \
  -config openssl.cnf -extensions ca_ext
leaf() {
  printf '[ext]\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = %s\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n' "$2" > leaf.cnf
  openssl req -new -newkey rsa:2048 -nodes -keyout "$1-key.pem" -out leaf.csr -subj "/CN=$1" -config openssl.cnf
  openssl x509 -req -in leaf.csr -CA delivery-ca.pem -CAkey delivery-ca-key.pem -CAcreateserial \
    -out "$1.pem" -not_before 20190101000000Z -not_after 21190101000000Z -extfile leaf.cnf -extensions ext
  cat "$1.pem" delivery-ca.pem > "$1-chain.pem"
}
leaf delivery-server "DNS:mx1.example.test,DNS:mx2.example.test,DNS:mta-sts.example.test,DNS:example.test"
leaf delivery-other "DNS:unrelated.test"
rm -f leaf.cnf leaf.csr delivery-ca.srl delivery-ca-key.pem
