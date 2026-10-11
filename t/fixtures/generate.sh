#!/bin/sh
# Regenerate the test certificates and DKIM keys. Test material only.
#
# The certificates are backdated to 2019: macOS (used by pure-tls for
# verification) rejects server certificates issued after mid-2019 that are
# valid for more than 825 days, and these must not expire.
set -e
cd "$(dirname "$0")"
gen_ca() {
  openssl req -x509 -new -newkey rsa:2048 -nodes -keyout "$1-key.pem" -out "$1.pem" \
    -not_before 20190101000000Z -not_after 21190101000000Z -subj "/CN=$2" -config openssl.cnf -extensions ca_ext
}
gen_ca ca "smtp test CA"
gen_ca other-ca "untrusted test CA"
openssl req -new -newkey rsa:2048 -nodes -keyout server-key.pem -out server.csr \
  -subj "/CN=localhost" -config openssl.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out server.pem -not_before 20190101000000Z -not_after 21190101000000Z -extfile openssl.cnf -extensions server_ext
rm -f server.csr ca.srl ca-key.pem other-ca-key.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out dkim-rsa-pkcs8.pem
openssl rsa -in dkim-rsa-pkcs8.pem -traditional -out dkim-rsa-pkcs1.pem
openssl genpkey -algorithm ED25519 -out dkim-ed25519.pem
openssl pkey -in dkim-rsa-pkcs8.pem -pubout -out dkim-rsa-pub.pem
openssl pkey -in dkim-ed25519.pem -pubout -out dkim-ed25519-pub.pem
# Encrypted copies of the DKIM keys, one per supported format. The password
# is "dkim-test" except for the AES-128 PKCS #8 key, whose is "pässwörd" (UTF-8).
P=pass:dkim-test
openssl pkcs8 -topk8 -in dkim-rsa-pkcs8.pem -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout $P -out dkim-rsa-pkcs8-aes256.pem
openssl pkcs8 -topk8 -in dkim-rsa-pkcs8.pem -v2 aes-128-cbc -v2prf hmacWithSHA1 -passout 'pass:pässwörd' -out dkim-rsa-pkcs8-aes128-sha1.pem
openssl pkcs8 -topk8 -in dkim-rsa-pkcs8.pem -v2 aes-192-cbc -v2prf hmacWithSHA512 -passout $P -out dkim-rsa-pkcs8-aes192-sha512.pem
openssl pkcs8 -topk8 -in dkim-rsa-pkcs8.pem -scrypt -passout $P -out dkim-rsa-pkcs8-scrypt.pem
openssl pkcs8 -topk8 -in dkim-ed25519.pem -v2 aes-256-cbc -passout $P -out dkim-ed25519-aes256.pem
openssl pkcs8 -topk8 -in dkim-rsa-pkcs8.pem -v2 des-ede3-cbc -passout $P -out dkim-rsa-pkcs8-des3.pem
openssl rsa -in dkim-rsa-pkcs1.pem -traditional -aes256 -passout $P -out dkim-rsa-legacy-aes256.pem
openssl rsa -in dkim-rsa-pkcs1.pem -traditional -aes128 -passout $P -out dkim-rsa-legacy-aes128.pem
openssl rsa -in dkim-rsa-pkcs1.pem -traditional -des3 -passout $P -out dkim-rsa-legacy-des3.pem
# An unsupported cipher, for the error message.
openssl pkcs8 -topk8 -in dkim-rsa-pkcs8.pem -v2 camellia-256-cbc -passout $P -out dkim-rsa-pkcs8-camellia.pem
