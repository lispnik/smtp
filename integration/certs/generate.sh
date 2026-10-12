#!/bin/sh
# Regenerate the certificates for the integration servers: a CA of their own
# and one server certificate, shared by Mailpit and Postfix, for the names and
# addresses the tests connect with. Long-lived so they never need renewing.
set -e
cd "$(dirname "$0")"
cnf=../../t/fixtures/openssl.cnf
openssl req -x509 -new -newkey rsa:2048 -nodes -keyout ca-key.pem -out ca.pem \
  -not_before 20190101000000Z -not_after 21190101000000Z -subj "/CN=smtp integration test CA" \
  -config "$cnf" -extensions ca_ext
printf '[ext]\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = DNS:localhost,DNS:mailpit,DNS:postfix,IP:127.0.0.1,IP:::1\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n' > leaf.cnf
openssl req -new -newkey rsa:2048 -nodes -keyout server-key.pem -out leaf.csr -subj "/CN=localhost" -config "$cnf"
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out server.pem -not_before 20190101000000Z -not_after 21190101000000Z -extfile leaf.cnf -extensions ext
cat server.pem ca.pem > server-chain.pem
# The servers run as non-root users; the key is a throwaway test key.
chmod 644 server-key.pem
rm -f leaf.cnf leaf.csr ca.srl ca-key.pem
