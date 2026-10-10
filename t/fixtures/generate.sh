#!/bin/sh
# Regenerate the test certificates and DKIM keys. Test material only.
set -e
cd "$(dirname "$0")"
gen_ca() {
  openssl req -x509 -new -newkey rsa:2048 -nodes -keyout "$1-key.pem" -out "$1.pem" \
    -days 36500 -subj "/CN=$2" -config openssl.cnf -extensions ca_ext
}
gen_ca ca "smtp test CA"
gen_ca other-ca "untrusted test CA"
openssl req -new -newkey rsa:2048 -nodes -keyout server-key.pem -out server.csr \
  -subj "/CN=localhost" -config openssl.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out server.pem -days 36500 -extfile openssl.cnf -extensions server_ext
rm -f server.csr ca.srl ca-key.pem other-ca-key.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out dkim-rsa-pkcs8.pem
openssl rsa -in dkim-rsa-pkcs8.pem -traditional -out dkim-rsa-pkcs1.pem
openssl genpkey -algorithm ED25519 -out dkim-ed25519.pem
openssl pkey -in dkim-rsa-pkcs8.pem -pubout -out dkim-rsa-pub.pem
openssl pkey -in dkim-ed25519.pem -pubout -out dkim-ed25519-pub.pem
