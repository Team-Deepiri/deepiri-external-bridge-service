#!/usr/bin/env bash
set -euo pipefail

payload_file="${1:-scripts/fixtures/github-issue-opened.json}"
webhook_url="${BOARDMAN_WEBHOOK_URL:-http://localhost:5006/webhooks/github}"
delivery_id="${GITHUB_DELIVERY_ID:-boardman-smoke-$(date +%s)}"
event_type="${GITHUB_EVENT_TYPE:-issues}"

if [[ -z "${GITHUB_WEBHOOK_SECRET:-}" ]]; then
  echo "GITHUB_WEBHOOK_SECRET is required."
  exit 1
fi

if [[ ! -f "${payload_file}" ]]; then
  echo "Payload file not found: ${payload_file}"
  exit 1
fi

payload="$(cat "${payload_file}")"
signature_hex="$(
  printf '%s' "${payload}" \
    | openssl dgst -sha256 -hmac "${GITHUB_WEBHOOK_SECRET}" \
    | awk '{print $2}'
)"
signature="sha256=${signature_hex}"

echo "Sending GitHub webhook to ${webhook_url}"
echo "Delivery ID: ${delivery_id}"
echo "Event type: ${event_type}"

curl -fsS -X POST "${webhook_url}" \
  -H "Content-Type: application/json" \
  -H "x-github-delivery: ${delivery_id}" \
  -H "x-github-event: ${event_type}" \
  -H "x-hub-signature-256: ${signature}" \
  --data "${payload}"

echo
echo "Webhook sent."
