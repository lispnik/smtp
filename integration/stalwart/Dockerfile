# Stalwart for the smtp integration tests, configured on first start from
# plan.ndjson by setup.sh. It delivers mail for example.test and bücher.test
# to local mailboxes, which the tests read back over JMAP, and verifies DKIM
# signatures against the keys published by the dns service.
FROM stalwartlabs/cli:1.0.13 AS cli

FROM stalwartlabs/stalwart:v0.16.22
COPY --from=cli /usr/local/bin/stalwart-cli /usr/local/bin/stalwart-cli
COPY config.json /etc/stalwart/config.json
COPY plan.ndjson setup.sh /opt/smtp-integration/
ENV STALWART_RECOVERY_ADMIN=admin:smtp-integration-admin
ENTRYPOINT ["/opt/smtp-integration/setup.sh"]
CMD []
HEALTHCHECK --interval=60s --start-period=120s --start-interval=1s --timeout=3s CMD test -f /tmp/ready
