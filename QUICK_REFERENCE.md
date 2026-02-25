#!/bin/bash
# Quick Reference Card - Print this out!
# Performance Testing Command Reference

cat << 'EOF'

╔═══════════════════════════════════════════════════════════════════════════╗
║                     PERFORMANCE TESTING QUICK REFERENCE                  ║
║                     Keep this handy while testing!                       ║
╚═══════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════════
1️⃣  PRE-TEST CHECKS
═══════════════════════════════════════════════════════════════════════════════

Verify Docker is running:
  $ docker --version

Start all services:
  $ docker-compose up -d

Check service health:
  $ docker-compose ps

Verify Prometheus is accessible:
  $ curl http://localhost:9090/-/healthy

Verify Grafana is accessible:
  $ curl http://localhost:3000/api/health

═══════════════════════════════════════════════════════════════════════════════
2️⃣  RUN TESTS
═══════════════════════════════════════════════════════════════════════════════

OPTION A: Interactive Menu (Recommended)
  $ bash run-performance-tests.sh

OPTION B: Progressive Load Test (5→25→50→100→200 RPS)
  $ node scripts/progressive-load-test.js

OPTION C: Sustained Load Test (customize RPS & duration)
  $ node scripts/sustained-load-test.js              # 50 RPS, 5 min
  $ node scripts/sustained-load-test.js 100 300     # 100 RPS, 5 min
  $ node scripts/sustained-load-test.js 200 600     # 200 RPS, 10 min

OPTION D: Latency Breakdown (100 samples)
  $ node scripts/latency-breakdown-test.js          # 100 samples
  $ node scripts/latency-breakdown-test.js 500      # 500 samples

═══════════════════════════════════════════════════════════════════════════════
3️⃣  MONITORING DURING TESTS
═══════════════════════════════════════════════════════════════════════════════

TERMINAL 1: Watch Docker Stats
  $ docker stats
  
  Look for:
    ✓ api:    CPU < 25%, Memory < 100MB
    ✓ worker: CPU < 30%, Memory < 150MB

TERMINAL 2: Watch Service Logs
  $ docker-compose logs -f api worker
  
  Look for:
    ✓ No ERROR messages
    ✓ Message publishing/consuming logs
    ✓ Kafka connection logs

BROWSER 1: Prometheus Metrics
  http://localhost:9090
  
  Copy-paste these queries:
    
    # Throughput (RPS)
    rate(messages_produced_total[1m])
    
    # Average latency (ms)
    (rate(message_processing_seconds_sum[1m]) / rate(message_processing_seconds_count[1m])) * 1000
    
    # P95 latency (ms)
    histogram_quantile(0.95, rate(message_processing_seconds_bucket[1m])) * 1000
    
    # Consumer lag
    consumer_lag_current
    
    # Error rate (%)
    (rate(consumer_errors_total[1m]) / rate(messages_consumed_total[1m])) * 100

BROWSER 2: Grafana Dashboard
  http://localhost:3000
  Login: admin / admin
  
  Pre-built dashboard shows:
    ✓ Throughput trend (green line)
    ✓ Latency percentiles (multiple lines)
    ✓ Consumer lag (orange line)
    ✓ Error rate (red line)

═══════════════════════════════════════════════════════════════════════════════
4️⃣  METRIC INTERPRETATION GUIDE
═══════════════════════════════════════════════════════════════════════════════

THROUGHPUT (RPS)
  ✅ Healthy:   100+ RPS
  ⚠️  Warning:  50-100 RPS
  ❌ Critical:  < 50 RPS

LATENCY - AVERAGE (ms)
  ✅ Healthy:   < 50ms
  ⚠️  Warning:  50-100ms
  ❌ Critical:  > 100ms

LATENCY - P95 (ms)
  ✅ Healthy:   < 100ms
  ⚠️  Warning:  100-200ms
  ❌ Critical:  > 200ms

LATENCY - P99 (ms)
  ✅ Healthy:   < 200ms
  ⚠️  Warning:  200-400ms
  ❌ Critical:  > 400ms

ERROR RATE (%)
  ✅ Healthy:   < 0.5%
  ⚠️  Warning:  0.5-2%
  ❌ Critical:  > 2%

CONSUMER LAG (messages)
  ✅ Healthy:   < 50
  ⚠️  Warning:  50-500 (if growing)
  ❌ Critical:  > 1000 or increasing

CPU USAGE (per service)
  ✅ Healthy:   < 40%
  ⚠️  Warning:  40-70%
  ❌ Critical:  > 80%

MEMORY USAGE (per service)
  ✅ Healthy:   < 200MB
  ⚠️  Warning:  200-400MB
  ❌ Critical:  > 400MB

═══════════════════════════════════════════════════════════════════════════════
5️⃣  RECORDING YOUR RESULTS
═══════════════════════════════════════════════════════════════════════════════

From Progressive Load Test Output:

Stage at Max Sustainable RPS (100):
  ✓ Record: RPS = 100
  ✓ Record: Avg latency = __ ms
  ✓ Record: P95 latency = __ ms
  ✓ Record: P99 latency = __ ms
  ✓ Record: Error rate = __ %
  ✓ Calculate: Success rate = 100 - error%

From Grafana Dashboard at Peak Load:
  ✓ Screenshot the dashboard
  ✓ Record: CPU usage for api service = __ %
  ✓ Record: CPU usage for worker service = __ %
  ✓ Record: Memory for api service = __ MB
  ✓ Record: Memory for worker service = __ MB
  ✓ Record: Max consumer lag = __ messages

From Sustained Load Test Output:
  ✓ Record: Final consumer lag = __ messages
  ✓ Record: Average latency over 5 min = __ ms
  ✓ Record: Stability (latency deviation) = __ %

From Latency Breakdown Test Output:
  ✓ Record: P95 API latency = __ ms
  ✓ Record: P99 API latency = __ ms
  ✓ Record: % of requests < 10ms = __ %
  ✓ Record: % of requests < 50ms = __ %

═══════════════════════════════════════════════════════════════════════════════
6️⃣  CREATING RESUME BULLETS
═══════════════════════════════════════════════════════════════════════════════

TEMPLATE 1: Throughput & Latency
  • Engineered Kafka event streaming handling [100] RPS 
    with [95.6]ms P95 latency using producer/consumer pattern

TEMPLATE 2: Reliability
  • Achieved [99.88]% end-to-end delivery rate under peak load 
    with exponential backoff retry logic

TEMPLATE 3: Observability
  • Built comprehensive monitoring stack with Prometheus & Grafana 
    capturing 11 key metrics (throughput, latency percentiles, lag)

TEMPLATE 4: Architecture
  • Designed consumer groups with automatic rebalancing 
    processing [100] RPS with minimal consumer lag

TEMPLATE 5: Performance
  • Sustained [100] RPS throughput for 5+ minutes with stable 
    latency and zero data loss under peak load

TEMPLATE 6: Scalability
  • Implemented distributed event processing across consumer groups 
    with horizontal scaling capability up to [200] RPS

═══════════════════════════════════════════════════════════════════════════════
7️⃣  TROUBLESHOOTING
═══════════════════════════════════════════════════════════════════════════════

Issue: "Connection refused" when running tests
  Solution:
    1. Check Docker: docker-compose ps
    2. Services should show "Up"
    3. If not: docker-compose restart api
    4. Wait 5 seconds
    5. Retry test

Issue: High error rates during test
  Solution:
    1. Check logs: docker-compose logs api worker
    2. Look for ERROR messages
    3. Check Kafka: docker-compose logs kafka
    4. Restart: docker-compose restart
    5. Wait 10 seconds
    6. Retry test

Issue: Consumer lag growing and not recovering
  Solution:
    1. Worker might be overloaded
    2. Restart: docker-compose restart worker
    3. Reduce load: node scripts/sustained-load-test.js 25 300
    4. Monitor: docker stats | grep worker

Issue: Prometheus shows no data
  Solution:
    1. Check targets: http://localhost:9090/targets
    2. Both api and worker should show "UP" (green)
    3. Check metrics: curl http://localhost:5006/metrics
    4. If empty: docker-compose restart api
    5. Wait 10 seconds for metrics to appear

Issue: Grafana dashboard is blank
  Solution:
    1. Check Prometheus data source
    2. Go to: http://localhost:3000
    3. Settings → Data Sources → Prometheus
    4. Click "Save & Test"
    5. Should show "Data source is working"
    6. Go back to dashboard and refresh

═══════════════════════════════════════════════════════════════════════════════
8️⃣  USEFUL COMMANDS
═══════════════════════════════════════════════════════════════════════════════

Start all services:
  $ docker-compose up -d

Stop all services:
  $ docker-compose down

View service status:
  $ docker-compose ps

View all service logs:
  $ docker-compose logs

Follow specific service logs:
  $ docker-compose logs -f api
  $ docker-compose logs -f worker

Restart a service:
  $ docker-compose restart api
  $ docker-compose restart worker

View Prometheus targets:
  http://localhost:9090/targets

Clear all data and restart:
  $ docker-compose down -v
  $ docker-compose up -d

Check API health:
  $ curl http://localhost:5006/health

Check Worker health:
  $ curl http://localhost:5007/health

Get current metrics:
  $ curl http://localhost:5006/metrics | head -50

═══════════════════════════════════════════════════════════════════════════════
9️⃣  KEY METRIC QUERIES
═══════════════════════════════════════════════════════════════════════════════

THROUGHPUT (messages/sec)
  rate(messages_produced_total[1m])

AVERAGE LATENCY (milliseconds)
  (rate(message_processing_seconds_sum[1m]) / 
   rate(message_processing_seconds_count[1m])) * 1000

P50 LATENCY (milliseconds)
  histogram_quantile(0.50, rate(message_processing_seconds_bucket[1m])) * 1000

P95 LATENCY (milliseconds)
  histogram_quantile(0.95, rate(message_processing_seconds_bucket[1m])) * 1000

P99 LATENCY (milliseconds)
  histogram_quantile(0.99, rate(message_processing_seconds_bucket[1m])) * 1000

CONSUMER LAG (messages)
  consumer_lag_current

ERROR RATE (percentage)
  (rate(consumer_errors_total[1m]) / rate(messages_consumed_total[1m])) * 100

SUCCESS RATE (percentage)
  (rate(messages_consumed_total[1m]) / rate(messages_produced_total[1m])) * 100

═══════════════════════════════════════════════════════════════════════════════
🔟 TIMELINE FOR COMPLETE TEST SUITE
═══════════════════════════════════════════════════════════════════════════════

0:00 - Start services
  Command: docker-compose up -d
  Duration: ~30 seconds

0:30 - Wait for health
  Duration: ~30 seconds (services need to be ready)

1:00 - Run Progressive Load Test
  Command: node scripts/progressive-load-test.js
  Duration: ~5 minutes
  Output: Summary table with 5 load stages

6:00 - Cool down
  Duration: ~5 seconds

6:05 - Run Sustained Load Test
  Command: node scripts/sustained-load-test.js 50 300
  Duration: ~5 minutes
  Output: Stability metrics and lag trend

11:05 - Cool down
  Duration: ~5 seconds

11:10 - Run Latency Breakdown Test
  Command: node scripts/latency-breakdown-test.js 100
  Duration: ~2 minutes
  Output: Percentile distribution and histogram

13:10 - Complete!

TOTAL TIME: ~13 minutes for full assessment

═══════════════════════════════════════════════════════════════════════════════

Print this card and keep it by your desk while testing!
Update the bracketed [values] with your actual results.

EOF
