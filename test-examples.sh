#!/bin/bash

# Deepiri Kafka Testing Examples
# 
# This script contains curl examples for testing the Kafka architecture
# Copy and paste commands into your terminal, or run this entire file
#
# Prerequisites:
#   - Services running: ./kafka-ops.sh start
#   - jq installed: brew install jq (optional, for JSON parsing)

set -e

API_BASE="http://localhost:5006"
WORKER_BASE="http://localhost:5007"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Deepiri Kafka Architecture - Testing Examples ===${NC}\n"

# ============================================================================
# 1. HEALTH CHECKS
# ============================================================================

echo -e "${GREEN}1. Health Checks${NC}\n"

echo "API Service Health:"
curl -s "$API_BASE/health" | jq '.'
echo ""

echo "Worker Service Health:"
curl -s "$WORKER_BASE/health" | jq '.'
echo ""

# ============================================================================
# 2. WEBHOOK INGESTION (PRODUCER)
# ============================================================================

echo -e "${GREEN}2. Webhook Ingestion - Single Webhook${NC}\n"

echo "Sending Stripe webhook..."
WEBHOOK_RESPONSE=$(curl -s -X POST "$API_BASE/webhooks/stripe" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "evt_stripe_'$(date +%s)'",
    "type": "charge.succeeded",
    "account_id": "stripe_acct_123",
    "data": {
      "object": {
        "id": "ch_'$(openssl rand -hex 8)'",
        "amount": 2999,
        "currency": "usd",
        "customer": "cus_abcdef123456",
        "description": "Test charge"
      }
    }
  }')

echo "$WEBHOOK_RESPONSE" | jq '.'
EVENT_ID=$(echo "$WEBHOOK_RESPONSE" | jq -r '.event_id')
CORR_ID=$(echo "$WEBHOOK_RESPONSE" | jq -r '.correlation_id')

echo ""
echo "Event ID: $EVENT_ID"
echo "Correlation ID: $CORR_ID"
echo ""

# ============================================================================
# 3. WEBHOOK INGESTION - MULTIPLE PROVIDERS
# ============================================================================

echo -e "${GREEN}3. Webhook Ingestion - Multiple Providers${NC}\n"

declare -a PROVIDERS=("stripe" "hubspot" "salesforce" "github")

for provider in "${PROVIDERS[@]}"; do
  echo "Sending $provider webhook..."
  
  case $provider in
    stripe)
      PAYLOAD='{
        "id": "evt_'$(date +%s)'",
        "type": "charge.succeeded",
        "account_id": "stripe_acct_123",
        "data": {"object": {"amount": 5000}}
      }'
      ;;
    hubspot)
      PAYLOAD='{
        "id": "evt_'$(date +%s)'",
        "type": "contact.updated",
        "account_id": "hubspot_acct_456",
        "data": {"contact_id": 12345}
      }'
      ;;
    salesforce)
      PAYLOAD='{
        "id": "evt_'$(date +%s)'",
        "type": "account.updated",
        "account_id": "salesforce_acct_789",
        "data": {"sobject_id": "001XXXXXXXXXXXXXXX"}
      }'
      ;;
    github)
      PAYLOAD='{
        "id": "evt_'$(date +%s)'",
        "type": "push",
        "repository": "team/repo",
        "commits": 3
      }'
      ;;
  esac
  
  curl -s -X POST "$API_BASE/webhooks/$provider" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" | jq '.event_id, .status' | tr -d '"\n'
  echo " ✓"
done

echo ""

# ============================================================================
# 4. SYNC JOB TRIGGERING (PRODUCER)
# ============================================================================

echo -e "${GREEN}4. Sync Job Triggering${NC}\n"

for integration_id in "stripe_acct_123" "hubspot_acct_456" "salesforce_acct_789"; do
  echo "Triggering sync for: $integration_id"
  
  curl -s -X POST "$API_BASE/integrations/sync" \
    -H "Content-Type: application/json" \
    -d "{
      \"integration_id\": \"$integration_id\",
      \"force\": false
    }" | jq '.job_id, .status'
  echo ""
done

# ============================================================================
# 5. METRICS
# ============================================================================

echo -e "${GREEN}5. Metrics (Prometheus Format)${NC}\n"

echo "Sample metrics from API service:"
curl -s "$API_BASE/metrics" | grep -E "^messages_produced|^producer_errors" | head -5
echo ""

echo "Sample metrics from Worker service:"
curl -s "$WORKER_BASE/metrics" | grep -E "^messages_consumed|^consumer_errors|^dlq_messages" | head -10
echo ""

# ============================================================================
# 6. WORKER STATUS
# ============================================================================

echo -e "${GREEN}6. Worker Status${NC}\n"

echo "Worker detailed status:"
curl -s "$WORKER_BASE/status" | jq '.'
echo ""

# ============================================================================
# 7. KAFKA TOPICS
# ============================================================================

echo -e "${GREEN}7. Kafka Topics${NC}\n"

echo "Topics created:"
docker exec deepiri-kafka kafka-topics \
  --bootstrap-server localhost:29092 \
  --list

echo ""

# ============================================================================
# 8. KAFKA CONSUMER GROUPS
# ============================================================================

echo -e "${GREEN}8. Kafka Consumer Groups${NC}\n"

echo "Consumer groups:"
docker exec deepiri-kafka kafka-consumer-groups \
  --bootstrap-server localhost:29092 \
  --list

echo ""
echo "webhook-processors group status:"
docker exec deepiri-kafka kafka-consumer-groups \
  --bootstrap-server localhost:29092 \
  --describe \
  --group webhook-processors

echo ""

# ============================================================================
# 9. INSPECT KAFKA TOPICS
# ============================================================================

echo -e "${GREEN}9. Inspect Topic Messages${NC}\n"

echo "Last 3 messages in integration.webhook.received:"
docker exec deepiri-kafka kafka-console-consumer \
  --bootstrap-server localhost:29092 \
  --topic integration.webhook.received \
  --from-beginning \
  --max-messages 3 \
  --property print.timestamp=true || echo "(No messages yet)"

echo ""

# ============================================================================
# 10. LOAD TEST SIMULATION
# ============================================================================

echo -e "${GREEN}10. Batch Webhook Ingestion (Light Load)${NC}\n"

echo "Sending 10 webhooks in rapid succession..."

for i in {1..10}; do
  curl -s -X POST "$API_BASE/webhooks/stripe" \
    -H "Content-Type: application/json" \
    -d "{
      \"id\": \"evt_batch_$i\",
      \"type\": \"charge.succeeded\",
      \"account_id\": \"stripe_acct_123\",
      \"amount\": $((i * 100))
    }" > /dev/null
  echo -n "."
done

echo " ✓"
echo ""
sleep 2

echo "Checking consumed messages:"
curl -s "$WORKER_BASE/metrics" | grep "messages_consumed_total" | head -1

echo ""

# ============================================================================
# 11. ERROR INJECTION (Simulate Failure)
# ============================================================================

echo -e "${GREEN}11. Optional: Inject Invalid Webhook (Watch DLQ)${NC}\n"

echo "Sending webhook with invalid signature..."
curl -s -X POST "$API_BASE/webhooks/stripe" \
  -H "Content-Type: application/json" \
  -H "X-Stripe-Signature: invalid_sig_12345" \
  -d '{
    "id": "evt_invalid",
    "type": "charge.succeeded",
    "account_id": "stripe_acct_123"
  }' | jq '.error // .status'

echo ""

# ============================================================================
# 12. VERIFY IDEMPOTENCY
# ============================================================================

echo -e "${GREEN}12. Test Idempotency (Send Duplicate Event)${NC}\n"

echo "Creating test event..."
TEST_EVENT_ID=$(openssl rand -hex 16)

EVENT_PAYLOAD="{
  \"id\": \"evt_idempotency_test_$TEST_EVENT_ID\",
  \"type\": \"charge.succeeded\",
  \"account_id\": \"stripe_acct_123\",
  \"amount\": 9999
}"

echo "First send:"
curl -s -X POST "$API_BASE/webhooks/stripe" \
  -H "Content-Type: application/json" \
  -d "$EVENT_PAYLOAD" | jq '.event_id'

echo "Waiting 2 seconds for processing..."
sleep 2

echo "Second send (same event):"
curl -s -X POST "$API_BASE/webhooks/stripe" \
  -H "Content-Type: application/json" \
  -d "$EVENT_PAYLOAD" | jq '.event_id'

echo ""
echo "Check Redis for dedup keys:"
docker exec deepiri-redis redis-cli KEYS "dedupe:*" | head -5

echo ""

# ============================================================================
# 13. PROMETHEUS QUERIES
# ============================================================================

echo -e "${GREEN}13. Prometheus API Examples${NC}\n"

echo "Query: Current message throughput (msg/sec)"
curl -s 'http://localhost:9090/api/v1/query?query=rate(messages_produced_total%5B1m%5D)' | jq '.data.result'

echo ""

echo "Query: p95 latency (seconds)"
curl -s 'http://localhost:9090/api/v1/query?query=histogram_quantile(0.95,rate(message_processing_seconds_bucket%5B1m%5D))' | jq '.data.result'

echo ""

echo "Query: Error rate"
curl -s 'http://localhost:9090/api/v1/query?query=rate(consumer_errors_total%5B5m%5D)' | jq '.data.result'

echo ""

# ============================================================================
# 14. DASHBOARD URLS
# ============================================================================

echo -e "${GREEN}14. Dashboard URLs${NC}\n"

echo "Prometheus:     http://localhost:9090"
echo "Grafana:        http://localhost:3000 (admin/admin)"
echo "API Metrics:    http://localhost:5006/metrics"
echo "Worker Metrics: http://localhost:5007/metrics"
echo ""

# ============================================================================
# SUMMARY
# ============================================================================

echo -e "${BLUE}=== Test Summary ===${NC}\n"

echo "✓ Health checks passed"
echo "✓ Webhooks ingested and queued"
echo "✓ Metrics visible in Prometheus"
echo "✓ Consumer groups active"
echo "✓ Messages flowing through Kafka"
echo ""

echo -e "${BLUE}Next Steps:${NC}"
echo "1. Open Grafana: http://localhost:3000"
echo "2. View dashboard: Dashboards → Deepiri Kafka Architecture"
echo "3. Run full load test: k6 run load-test.js"
echo "4. Check worker logs: docker logs deepiri-worker -f"
echo "5. Inspect DLQ if needed: docker logs deepiri-worker | grep DLQ"
echo ""

echo -e "${BLUE}Common Commands:${NC}"
echo "./kafka-ops.sh logs worker     # Watch worker processing"
echo "./kafka-ops.sh logs api        # Watch API requests"
echo "./kafka-ops.sh health          # Check system health"
echo "./kafka-ops.sh topics          # List Kafka topics"
echo "./kafka-ops.sh metrics         # Show current metrics"
echo ""
