# smtp

A modern, secure SMTP client and MIME message builder for Common Lisp.

```lisp
(smtp:send-mail "smtp.example.com"
                (smtp:make-message :from "Alice <alice@example.com>"
                                   :to "bob@example.net"
                                   :subject "Hello"
                                   :text "Hi Bob!")
                :credentials '(:username "alice@example.com" :password "app-password"))
```

That connects to port 587, upgrades to TLS (verifying the certificate and
the host name), authenticates, sends and disconnects. Nothing is ever sent in
plaintext unless you ask for it.

## Features

**Security by default**

- TLS is required: STARTTLS on 587 (refusing servers that don't offer it) or
  implicit TLS on 465. TLS 1.2 minimum.
- Two TLS backends: OpenSSL (through cl+ssl) or
  [pure-tls](https://github.com/atgreen/pure-tls), a TLS 1.3 implementation
  in Common Lisp with no foreign libraries.
- Certificate chain *and* host name (or IP address) are verified during the
  handshake, against the system trust store or a CA file you give.
- Credentials are never sent over an unencrypted connection unless you pass
  `:allow-insecure-auth t`.
- STARTTLS response injection (CVE-2011-0411 style) is detected and refused.
- Header and command injection is impossible: every address, header name and
  value, filename, Content-ID and SMTP command is validated, and a CR or LF
  anywhere is an error rather than something to "clean up".
- Line endings are canonicalized to CRLF and every line starting with `.` is
  dot-stuffed, so no message content can end the DATA phase early (SMTP
  smuggling).
- Traces redact credentials and never include message content.
- Message-IDs, MIME boundaries and Content-IDs come from OpenSSL's CSPRNG.
- Bounded reads: overlong reply lines and replies from a hostile server are
  protocol errors, not memory exhaustion.

**Authentication**: SASL PLAIN, LOGIN, XOAUTH2 and OAUTHBEARER (RFC 7628), for
Gmail and Microsoft 365 OAuth 2.0 as well as passwords. The strongest
mechanism the server offers is chosen automatically. Secrets may be functions,
called only when needed.

**ESMTP**: PIPELINING, SIZE (checked before sending), 8BITMIME, SMTPUTF8,
ENHANCEDSTATUSCODES, DSN, CHUNKING/BDAT, with HELO fallback for ancient
servers. One connection can send many messages.

**Messages**

- Plain text, HTML, or both (`multipart/alternative`), attachments
  (`multipart/mixed`) and inline images referenced by `cid:`
  (`multipart/related`).
- Attachments from files or from octet vectors in memory.
- The transfer encoding is chosen per part (7bit, quoted-printable or base64)
  so every message is 7-bit clean and no line exceeds the limits; long HTML
  lines are fine.
- Non-ASCII subjects and display names become RFC 2047 encoded-words, never
  splitting a character; non-ASCII filenames use RFC 2231 in
  Content-Disposition and encoded-words in the Content-Type name (the form
  Thunderbird sends), each given once.
- Internationalized domain names are converted with UTS #46 and Punycode;
  addresses with non-ASCII local parts are sent with SMTPUTF8 and UTF-8
  headers (RFC 6532).
- Correct RFC 5322 dates, unique Message-IDs, Bcc kept out of the headers,
  threading headers (In-Reply-To, References) and one-click unsubscribe
  (RFC 8058).

**DKIM** (the optional `smtp/dkim` system): rsa-sha256 and ed25519-sha256
(RFC 8463) signing with relaxed or simple canonicalization, oversigning, PEM
keys (PKCS #1 and PKCS #8, plain or password-encrypted), and a helper that
prints the DNS record. Signatures
are verified in the tests with OpenSSL and have been checked with dkimpy.

**Errors you can act on**: 4xx replies signal `smtp-transient-error` (retry
later), 5xx replies `smtp-permanent-error`, each carrying the reply and its
enhanced status code; timeouts, TLS failures and dropped connections have
their own conditions. A failed transaction leaves the connection usable.

## Installation

Clone this repository where ASDF can find it and fetch the dependencies with
[ocicl](https://github.com/ocicl/ocicl):

```sh
git clone https://github.com/lispnik/smtp.git
cd smtp && ocicl install
```

```lisp
(asdf:load-system "smtp")            ; TLS through OpenSSL
(asdf:load-system "smtp/pure-tls")   ; or TLS in pure Lisp; either or both
(asdf:load-system "smtp/dkim")       ; optional
```

| System | What it adds | Dependencies |
|---|---|---|
| `smtp/core` | Everything except TLS (plaintext only) | alexandria, babel, usocket |
| `smtp` | The OpenSSL backend | cffi, cl+ssl; OpenSSL 1.1.1 or later (3.x and 4.x work) |
| `smtp/pure-tls` | The pure Lisp backend | pure-tls |
| `smtp/dkim` | DKIM signing | ironclad |
| `smtp/delivery` | Direct delivery: MX, DANE, MTA-STS, retry queue | ironclad, bordeaux-threads |

### TLS backends

With one backend loaded it is used automatically; with both, OpenSSL is the
default. Choose per connection with `:tls-backend`, or globally:

```lisp
(setf smtp:*tls-backend* :pure-tls)   ; or :openssl
```

Both verify the certificate chain and the server's name (or IP address,
against the certificate's IP entries) inside the handshake, and are run
through the same test suite, including against each other.

| | `:openssl` | `:pure-tls` |
|---|---|---|
| Protocol versions | TLS 1.2 and 1.3 | TLS 1.3 only |
| Foreign code | libssl, libcrypto | none |
| Trust store | OpenSSL's default paths | macOS Keychain, Windows store, or system bundle |
| Encrypted client keys | yes | no |

TLS 1.3 is offered by every major provider (Gmail, Microsoft 365, Yahoo,
iCloud, Fastmail), but an older private server may need the OpenSSL
backend. With pure-tls, session resumption is turned off: pure-tls caches
session tickets per host name for the whole process, and a resumed session
skips certificate verification, so a connection could otherwise inherit one
made with different trust settings.

## Usage

### Sending one message

```lisp
(smtp:send-mail "smtp.gmail.com" message
                :credentials (smtp:make-credentials :username "alice@gmail.com"
                                                    :oauth2-token #'fetch-access-token))
```

`send-mail` takes every option of `open-connection` and `send-message` and
returns a `delivery-result`.

### Reusing a connection

```lisp
(smtp:with-connection (c "smtp.example.com"
                         :credentials '(:username "alice" :password "secret"))
  (dolist (m messages)
    (smtp:send-message c m)))
```

### Connection pools

A pool shares a bounded number of connections to one server between any
number of threads. Connections are opened when needed and kept for reuse.

```lisp
(defvar *pool*
  (smtp:make-connection-pool "smtp.example.com"
                             :credentials '(:username "alice" :password "secret")
                             :max-connections 4))

(smtp:pool-send-message *pool* message)   ; from any thread

(smtp:with-pooled-connection (c *pool*)   ; several messages on one connection
  (dolist (m messages) (smtp:send-message c m)))

(smtp:close-connection-pool *pool*)
```

`make-connection-pool` takes every option of `open-connection`, plus:

| Option | Default | |
|---|---|---|
| `:max-connections` | 4 | Connections open at once |
| `:max-idle` | `:max-connections` | Unused connections kept open |
| `:idle-timeout` | 60 | Seconds an unused connection is kept |
| `:max-messages-per-connection` | 100 | Transactions before a connection is retired |
| `:max-connection-age` | 600 | Seconds before a connection is retired |
| `:check-after` | 10 | Idle seconds after which NOOP is sent before reuse |
| `:wait-timeout` | 30 | Seconds to wait for a free connection, then `smtp-pool-timeout` |

A connection the server has closed or announced it is closing (421) while
it sat idle is noticed and replaced before use. If a reused connection
fails before the server accepted `MAIL FROM`, `pool-send-message` sends
the message once more on a new connection; nothing has been delivered at
that point, so it cannot arrive twice. Failures after that are signalled as
usual. A connection left broken or mid-transaction is closed rather than
returned to the pool. `connection-pool-statistics` reports usage.

### Building messages

```lisp
(smtp:make-message
 :from (smtp:make-mailbox "alice@example.com" "Alice Liddell")
 :to '("bob@example.net" "Carol <carol@example.org>")
 :cc "dave@example.com, \"Doe, John\" <john@example.com>"
 :bcc "audit@example.com"
 :reply-to "support@example.com"
 :subject "Your invoice — März"
 :text "Your invoice is attached."
 :html "<p>Your invoice is attached.</p><img src=\"cid:logo@example.com\">"
 :attachments (list #p"invoice.pdf"
                    (smtp:make-attachment logo-octets :filename "logo.png"
                                                      :inline t :content-id "logo@example.com"))
 :headers '(("X-Campaign" . "spring"))
 :list-unsubscribe "https://example.com/unsubscribe?u=42"
 :list-unsubscribe-post t)
```

Addresses are mailboxes or strings; lists of recipients may be lists or
comma-separated strings. Everything is validated when the message is made,
signalling `mail-format-error` (`invalid-address`, `invalid-header`) so a bad
address surfaces before any connection is opened. `render-message` returns the
octets that would be sent.

### Connection options

| Option | Default | Meaning |
|---|---|---|
| `:tls` | `:starttls` | `:starttls` (required), `:implicit`, `:opportunistic` (STARTTLS if offered) or `:none` |
| `:port` | 587 / 465 / 25 | By TLS mode |
| `:credentials` | — | `make-credentials` result, or its arguments as a plist |
| `:auth-mechanism` | automatic | `:plain`, `:login`, `:xoauth2`, `:oauthbearer` |
| `:ca-file` | system store | PEM file of trusted CAs |
| `:tls-hostname` | the host | Name or IP address the certificate must match |
| `:tls-backend` | `*tls-backend*` | `:openssl` or `:pure-tls` |
| `:verify` | `t` | `nil` disables certificate checks — for testing only |
| `:client-certificate`, `:client-key` | — | PEM files for TLS client authentication |
| `:local-name` | this host's name | Name sent with EHLO |
| `:connect-timeout` | 30 | Seconds to connect |
| `:timeout` | 300 | Seconds for each other read or write |
| `:data-timeout` | 600 | Seconds to wait for the server to accept the message |
| `:allow-insecure-auth` | `nil` | Allow credentials without TLS |
| `:trace` | `*trace*` | `t`, a stream, or a function of direction and line |

### Send options

`send-message` and `send-mail` also take:

- `:envelope-from` — defaults to the Sender, else the From address; `""`
  sends a null reverse-path, for bounces.
- `:recipients` — defaults to To, Cc and Bcc.
- `:dkim` — a DKIM signer, or a list of them.
- `:on-rejected-recipient` — `:error` (the default) or `:skip`.
- `:dsn-notify`, `:dsn-return`, `:dsn-envelope-id` — delivery status
  notifications, when the server supports DSN.
- `:chunking` — use BDAT when the server offers it (default `t`).

### Handling failures

```lisp
(handler-case (smtp:send-mail host message :credentials creds)
  (smtp:smtp-transient-error (e)      ; 4xx: queue for retry
    (retry-later message (smtp:reply-enhanced-status (smtp:smtp-error-reply e))))
  (smtp:smtp-permanent-error (e)      ; 5xx: give up, tell someone
    (report-bounce message e))
  (smtp:smtp-connection-error (e)     ; DNS, refused, timeout, TLS failure
    (retry-later message e)))
```

When some recipients are refused, `smtp-recipients-rejected` lists the accepted
and rejected addresses; the `send-to-accepted` restart sends to the accepted
ones:

```lisp
(handler-bind ((smtp:smtp-recipients-rejected
                 (lambda (e)
                   (log-rejections (smtp:smtp-recipients-rejected-rejected e))
                   (invoke-restart 'smtp:send-to-accepted))))
  (smtp:send-message connection message))
```

### DKIM

```lisp
(asdf:load-system "smtp/dkim")

(defvar *signer*
  (smtp/dkim:make-dkim-signer :domain "example.com"
                              :selector "mail2026"
                              :private-key #p"/etc/dkim/mail2026.pem"))

(smtp/dkim:dkim-dns-record *signer*)
;; => "v=DKIM1; k=rsa; p=MIIBIjANBgkqh..."  publish at mail2026._domainkey.example.com

(smtp:send-message connection message :dkim *signer*)
```

Generate a key with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`
or `openssl genpkey -algorithm ED25519`. Ed25519 signatures are small but not
every verifier supports them yet, so sign with both: `:dkim (list ed rsa)`.

An encrypted key needs `:password`, a string or a function returning one
(called only when the key is read). PKCS #8 keys encrypted with PBKDF2 or
scrypt, as `openssl genpkey -aes256` and `openssl pkcs8 -topk8` write them,
and OpenSSL's traditional `DEK-Info` keys are read, with AES-128/192/256-CBC
or DES-EDE3-CBC. A missing or wrong password signals
`smtp/dkim:dkim-key-password-error`; other key problems
`smtp/dkim:dkim-key-error`.

### Tracing

```lisp
(let ((smtp:*trace* t))
  (smtp:send-mail ...))
```

```
S: 220 smtp.example.com ESMTP
C: EHLO client.example.com
...
C: AUTH PLAIN [credentials redacted]
S: 235 2.7.0 Authentication successful
C: MAIL FROM:<alice@example.com> SIZE=1234
...
C: [1,234 octets of message data]
```

### Delivering without a relay

The `smtp/delivery` system sends straight to each recipient domain's mail
servers, the way an MTA does, instead of through a submission server:

```lisp
(asdf:load-system "smtp/delivery")

(smtp/delivery:deliver-message message :local-name "mail.example.com")
;; => list of RECIPIENT-STATUS: :delivered, :deferred (retry later) or :failed
```

For each domain the MX hosts are tried in order of preference, with implicit
MX (the domain itself) and null MX (RFC 7505) handled. Each host gets the
strongest protection the domain asks for:

| | When | Effect |
|---|---|---|
| DANE (RFC 7672) | The MX, address and TLSA records are DNSSEC-validated | TLS required; the certificate must match a TLSA record (DANE-EE or DANE-TA) |
| MTA-STS (RFC 8461) | The domain publishes an `enforce` policy | Only the policy's MX hosts; TLS 1.2+ with a valid certificate for the MX name |
| Opportunistic TLS | Otherwise | STARTTLS when offered, without certificate checks (RFC 7435); else plaintext |

DANE is checked first and MTA-STS cannot override a DANE failure. A host
that fails its checks is skipped, never sent mail, and the recipient is
deferred if no other host works. `:require-tls t` insists on a verified
certificate everywhere; `:dane nil` and `:mta-sts nil` turn those off.
`recipient-status-security` says what each delivery got.

DANE depends on a DNSSEC-validating resolver you trust. DNS answers carry
the validation result in an unprotected bit, so by default it is believed
only from a resolver on this host (such as Unbound on 127.0.0.1); with any
other resolver DANE is not used. To choose:

```lisp
(setf smtp/delivery:*resolver*
      (smtp/delivery:make-resolver :nameservers '("127.0.0.1") :trust-ad t))
```

MTA-STS policies are cached for their `max_age` in `*mta-sts-cache*`;
specialize `mta-sts-cache-get` and `mta-sts-cache-put` to keep them across
restarts.

Deferred recipients can be retried with a queue. Run it periodically; it
retries on a schedule (30 minutes, then 1, 2, 4 and every 8 hours) and gives
up after five days:

```lisp
(defvar *queue*
  (smtp/delivery:make-delivery-queue
   :local-name "mail.example.com"
   :on-failed (lambda (item statuses) (send-bounce item statuses))))

(smtp/delivery:enqueue-message *queue* message :dkim signer)
(smtp/delivery:run-delivery-queue *queue*)   ; e.g. every minute
```

Sending mail directly needs what any MTA needs to be accepted: a public
address with outbound port 25 open (many ISPs and clouds block it), a
`:local-name` matching its reverse DNS, and SPF and DKIM for the sender's
domain.

## Scope and limitations

- The delivery queue is in memory: keep `delivery-queue-messages` somewhere
  durable if queued mail must survive a restart. Bounces (DSNs) for failed
  recipients are left to the `:on-failed` callback, and TLSRPT reports
  (RFC 8460) are not sent.
- Timeouts rely on SBCL's deadlines; the library is developed and tested on
  SBCL. On other implementations it works but I/O is not time-limited.
- The test certificates are backdated to 2019 with a hundred-year lifetime:
  macOS, which pure-tls uses for verification there, rejects newer
  certificates valid for more than 825 days.
- Domain names are converted by UTS #46 (nontransitional, with every check
  on), using Unicode 15.0 data to match SBCL's; it passes all 6,235 ToASCII
  cases of the Unicode conformance file. Regenerate src/idna-table.lisp
  with tools/gen-idna-table.py when SBCL moves to a newer Unicode version.
- A connection is not safe to share between threads; use one per thread, or
  a connection pool, which is.
- Not included: CRAM-MD5 and SCRAM (rarely offered for SMTP), S/MIME and
  OpenPGP.

## Standards

RFC 5321 (SMTP), 5322 (message format), 2045–2047 and 2231 (MIME), 3492 and
5890–5893 (IDN) with Unicode UTS #46, 3207 (STARTTLS), 8314 (implicit TLS), 4954 (AUTH), 4616 (PLAIN),
7628 (OAUTHBEARER), 1870 (SIZE), 2920 (PIPELINING), 6152 (8BITMIME), 6531 and
6532 (SMTPUTF8), 3461 (DSN), 3463 (enhanced status codes), 3030 (CHUNKING),
2392 (Content-ID), 8058 (one-click unsubscribe), 6376 and 8463 (DKIM),
1035 and 6840 (DNS), 7505 (null MX), 7672, 7671 and 6698 (DANE), 8461
(MTA-STS).

## Development

```sh
ocicl install
make test
```

The tests run an in-process mock SMTP server (plain, STARTTLS and implicit
TLS, with its own test CA in `t/fixtures`; every TLS test runs with both
backends) through normal and hostile
conversations: injection attempts, malformed and oversized replies, stalls,
dropped connections, rejected recipients, transient and permanent failures.
Property tests check encodings and rendering against random input. DKIM
signatures are verified with the `openssl` command line tool when it is
installed.

`make stress` runs load and fuzz tests that take several minutes:
- throughput over one connection and through a pool of 16 threads;
- thousands of connections, checked for leaked descriptors and memory;
- 50 MB messages;
- 1,500 sessions with a randomly misbehaving server, each of which must end
  in an `smtp-error` within its timeouts;
- 3,000 random messages, rendered and read back with Python's email package;
- 200,000 corrupted DNS responses;
- a delivery queue run from several threads at once.

Pick sections with `STRESS=pool,messages make stress`.

`make integration` tests against real servers running in Docker:
- [Mailpit](https://mailpit.axllent.org/), which keeps what it receives;
- Postfix, which relays everything it accepts to Mailpit;
- [Stalwart](https://stalw.art/), which delivers to local mailboxes and
  checks DKIM and DMARC against keys served by a small CoreDNS server.

Each message is sent, read back through Mailpit's API or Stalwart's JMAP,
and compared with what was sent. Mailpit (Go) and Stalwart (Rust) parse
messages with their own libraries, so each is an independent check. The
tests cover:
- every route to each server: plaintext, STARTTLS and implicit TLS, with
  both TLS backends, with and without authentication;
- Unicode headers, bodies and addresses (SMTPUTF8), attachments, HTML with
  inline images, dot-stuffing, long lines, Bcc and an 8 MB message;
- DKIM: RSA and Ed25519 signatures, every canonicalization, over DATA and
  BDAT, for an internationalized domain, and a wrong key that must fail;
- each server's rules: BDAT and DATA, rejected recipients, relaying, bad
  passwords, refusing to send credentials without TLS, sending only as
  your own address, the SIZE limit, delivery status notifications,
  certificate checks and a connection pool.

The first run builds the Postfix and Stalwart images; after that a run takes
under a minute. The servers keep running between runs; `make
integration-down` stops them, and Mailpit's web page at
<http://localhost:18025> shows what was sent to Mailpit and Postfix. Without
make, as on Windows:

```sh
docker compose -f integration/compose.yaml up -d --build --wait
sbcl --eval '(asdf:test-system :smtp/integration)' --quit
```

All ports are on localhost: 11025 and 18025 for Mailpit; 10025, 10587 and
10465 for Postfix; 12025, 12587, 12465 and 18080 (JMAP) for Stalwart. The
servers share the Docker subnet 172.29.53.0/24. `SMTP_IT_HOST` and the
other variables in `integration/package.lisp` point the tests elsewhere.

## License

MIT. See [LICENSE](LICENSE).
