# Postfix for the smtp integration tests. It accepts mail on 25 (plain or
# STARTTLS), 587 (STARTTLS, then AUTH) and 465 (implicit TLS, then AUTH),
# and relays everything to Mailpit, where the tests read it back.
FROM debian:13-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postfix libsasl2-modules sasl2-bin ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY main.cf /etc/postfix/main.cf
COPY master.cf /etc/postfix/master.cf
COPY smtpd.conf /etc/postfix/sasl/smtpd.conf
COPY relay_recipients /etc/postfix/relay_recipients
# The test account for AUTH: user@example.test / secret.
RUN echo secret | saslpasswd2 -p -c -u example.test user \
 && chown root:postfix /etc/sasldb2 && chmod 640 /etc/sasldb2 \
 && postmap /etc/postfix/relay_recipients \
 && newaliases
EXPOSE 25 587 465
HEALTHCHECK --interval=60s --start-period=60s --start-interval=1s --timeout=3s CMD postfix status
CMD ["postfix", "start-fg"]
