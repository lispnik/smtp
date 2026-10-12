#!/bin/sh
# Start Stalwart; on the container's first start, load plan.ndjson (domains,
# accounts, certificate, listeners, DNS) through the management API, then
# restart so the listeners and certificate take effect. The health check
# passes once /tmp/ready exists.
set -e
# stalwart-cli caches the schema under $HOME, which the stalwart user lacks.
export HOME=/tmp
start() {
  /usr/local/bin/stalwart --config /etc/stalwart/config.json &
  pid=$!
  until curl -fs -o /dev/null http://127.0.0.1:8080/healthz/live; do sleep 0.5; done
}
trap 'kill -TERM $pid; wait $pid; exit 0' TERM INT
start
if [ ! -f /var/lib/stalwart/.smtp-integration ]; then
  stalwart-cli --no-color --url http://127.0.0.1:8080 \
    --user "${STALWART_RECOVERY_ADMIN%%:*}" --password "${STALWART_RECOVERY_ADMIN#*:}" \
    apply --file /opt/smtp-integration/plan.ndjson
  touch /var/lib/stalwart/.smtp-integration
  kill -TERM $pid
  wait $pid || true
  start
fi
touch /tmp/ready
wait $pid
