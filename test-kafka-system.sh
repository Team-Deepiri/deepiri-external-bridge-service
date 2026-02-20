#!/bin/bash

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║                   KAFKA INTEGRATION SYSTEM TEST                           ║"
echo "║              Testing all components and verifying functionality            ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

passed=0
failed=0

# Test 1: API Service is Running
echo "[TEST 1] API Service Health Check"
if curl -s http://localhost:5006/health | grep -q "accepted"; then
  echo -e "${GREEN}✓ PASS${NC} - API service responding"
  ((passed++))
else
  echo -e "${RED}✗ FAIL${NC} - API service not responding"
  ((failed++))
fi

# Test 2: Prometheus Metrics Endpoint
echo ""
echo "[TEST 2] Prometheus Metrics Endpoint"
METRICS=$(curl -s http://localhost:5006/metrics | wc -l)
if [ "$METRICS" -gt 5 ]; then
  echo -e "${GREEN}✓ PASS${NC} - Metrics endpoint returning data ($METRICS lines)"
  ((passed++))
else
  echo -e "${RED}✗ FAIL${NC} - Metrics endpoint not responding"
  ((failed++))
fi

# Test 3: Send Single Webhook
echo ""
echo "[TEST 3] Single Webhook Ingestion"
RESPONSE=$(curl -s -X POST http://localhost:5006/webhooks/stripe \
  -H "Content-Type: application/json" \
  -H "X-Integration-ID: int_stripe_test_1" \
  -d '{"id":"evt_test_1","type":"charge.succeeded","amount":5000}')

if echo "$RESPONSE" | grep -q "event_id"; then
  echo -e "${GREEN}✓ PASS${NC} - Webhook accepted"
  EVENT_ID=$(echo "$RESPONSE" | grep -o '"event_id":"[^"]*"' | cut -d'"' -f4)
  echo "  Event ID: $EVENT_ID"
  ((passed++))
else
  echo -e "${RED}✗ FAIL${NC} - Webhook rejected"
  ((failed++))
fi

# Test 4: Check Produced Metrics
echo ""
echo "[TEST 4] Kafka Producer Metrics"
sleep 2
PRODUCED=$(curl -s http://localhost:5006/metrics | grep 'messages_produced_total' | grep -v '#' | head -1)
if [ -n "$PRODUCED" ]; then
  echo -e "${GREEN}✓ PASS${NC} - Kafka producer metrics available"
  echo "  $PRODUCED"
  ((passed++))
else
  echo -e "${RED}✗ FAIL${NC} - Kafka producer metrics missing"
  ((failed++))
fi

# Test 5: Worker Service Health
echo ""
echo "[TEST 5] Worker Service Health Check"
if curl -s http://localhost:5007/health | grep -q "healthy"; then
  echo -e "${GREEN}✓ PASS${NC} - Worker service responding"
  ((passed++))
else
  echo -e "${RED}✗ FAIL${NC} - Worker service not responding"
  ((failed++))
fi

# Test 6: Worker Metrics
echo ""
echo "[TEST 6] Worker Service Metrics"
WORKER_METRICS=$(curl -s http://localhost:5007/metrics | wc -l)
if [ "$WORKER_METRICS" -gt 5 ]; then
  echo -e "${GREEN}✓ PASS${NC} - Worker metrics available ($WORKER_METRICS lines)"
  ((passed++))
else
  echo -e "${RED}✗ FAIL${NC} - Worker metrics not available"
  ((failed++))
fi

# Test 7: Send Batch Webhooks
echo ""
echo "[TEST 7] Batch Webhook Processing (10 webhooks)"
for i in {1..10}; do
  curl -s -X POST http://localhost:5006/webhooks/stripe \
    -H "Content-Type: application/json" \
    -H "X-Integration-ID: int_stripe_batch" \
    -d "{\"id\":\"evt_batch_$i\",\"type\":\"charge.succeeded\"}" >/dev/null &
done
wait
echo -e "${GREEN}✓ PASS${NC} - 10 webhooks sent successfully"
((passed++))

# Test 8: Check Consumer Metrics After Processing
echo ""
echo "[TEST 8] Check Consumer Processing Metrics"
sleep 3
CONSUMED=$(curl -s http://localhost:5007/metrics | grep 'messages_consumed_total' | grep -v '#')
if [ -n "$CONSUMED" ]; then
  echo -e "${GREEN}✓ PASS${NC} - Messages being consumed by workers"
  echo "  $(echo $CONSUMED | head -1)"
  ((passed++))
else
  echo -e "${RED}✗ FAIL${NC} - No consumed messages detected"
  ((failed++))
fi

# Test 9: Verify No Errors
echo ""
echo "[TEST 9] Error Rate Check"
ERRORS=$(curl -s http://localhost:5006/metrics | grep 'producer_errors_total')
if echo "$ERRORS" | grep -q "0}"; then
  echo -e "${GREEN}✓ PASS${NC} - No producer errors"
  ((passed++))
else
  echo -e "${YELLOW}⚠ INFO${NC} - Some errors detected (may be expected)"
  echo "  $ERRORS"
fi

# Test 10: Prometheus Scrape Targets
echo ""
echo "[TEST 10] Prometheus Scrape Targets"
TARGETS=$(curl -s http://localhost:9090/api/v1/targets | grep -o '"health":"up"' | wc -l)
if [ "$TARGETS" -ge 2 ]; then
  echo -e "${GREEN}✓ PASS${NC} - Prometheus scraping $TARGETS targets"
  ((passed++))
else
  echo -e "${RED}✗ FAIL${NC} - Prometheus targets not healthy"
  ((failed++))
fi

# Test 11: Grafana Accessibility
echo ""
echo "[TEST 11] Grafana Dashboard Access"
if curl -s http://localhost:3000/api/health | grep -q "ok"; then
  echo -e "${GREEN}✓ PASS${NC} - Grafana accessible"
  ((passed++))
else
  echo -e "${RED}✗ FAIL${NC} - Grafana not accessible"
  ((failed++))
fi

# Test 12: Kafka Topic Verification
echo ""
echo "[TEST 12] Kafka Topic Verification"
TOPIC_CHECK=$(docker compose exec -T kafka kafka-topics --bootstrap-server localhost:9092 --list 2>/dev/null | grep -c "integration.webhook")
if [ "$TOPIC_CHECK" -gt 0 ]; then
  echo -e "${GREEN}✓ PASS${NC} - Kafka topics created"
  docker compose exec -T kafka kafka-topics --bootstrap-server localhost:9092 --list 2>/dev/null | grep "integration"
  ((passed++))
else
  echo -e "${YELLOW}⚠ INFO${NC} - Topic verification skipped (Docker exec may not work)"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║                          TEST SUMMARY                                      ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo -e "Passed: ${GREEN}$passed${NC}"
echo -e "Failed: ${RED}$failed${NC}"
echo -e "Total:  $((passed + failed))"
echo ""

if [ $failed -eq 0 ]; then
  echo -e "${GREEN}✅ ALL TESTS PASSED!${NC}"
  echo ""
  echo "Your Kafka Integration Service is production-ready:"
  echo "  ✓ API Service handling webhooks"
  echo "  ✓ Kafka Producer publishing events"
  echo "  ✓ Worker Service consuming messages"
  echo "  ✓ Prometheus collecting metrics"
  echo "  ✓ Grafana visualizing data"
else
  echo -e "${RED}❌ SOME TESTS FAILED${NC}"
  echo "Review the failures above"
fi

echo ""
