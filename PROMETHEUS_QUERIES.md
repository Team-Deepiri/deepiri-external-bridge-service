# Performance Testing Guide - Prometheus Queries & Execution

## Quick Start

### 1. Ensure Services Are Running
```bash
# From project root
docker-compose up -d

# Verify all services are ready (wait ~10 seconds)
docker-compose ps

# Expected output: All services should show "Up"
```

### 2. Run Your First Load Test
```bash
# Progressive load test (stages 5→25→50→100→200 RPS)
node scripts/progressive-load-test.js

# Expected duration: ~5 minutes
# Shows: throughput, latency (avg/P95/P99), error rates at each stage
```

### 3. Monitor During Test
Open these in separate tabs:

```bash
# Terminal 1: Watch Docker resource usage
docker stats

# Terminal 2: Monitor logs
docker-compose logs -f api worker

# Browser: Prometheus queries
open http://localhost:9090

# Browser: Grafana dashboard
open http://localhost:3000
```

---

## Prometheus Query Reference

All queries below work in Prometheus at `http://localhost:9090`

### Core Metrics Queries

#### 1. **Throughput (RPS)**
```promql
# Messages produced per second (current rate)
rate(messages_produced_total[1m])

# Label with topic
rate(messages_produced_total{topic="webhooks"}[1m])
```

**What it measures**: How many messages/sec your producer is sending
**Expected range**: 5-200 RPS during load tests
**Resume metric**: "handled 100 RPS throughput"

---

#### 2. **Average Latency (ms)**
```promql
# Average message processing latency
(rate(message_processing_seconds_sum[1m]) / rate(message_processing_seconds_count[1m])) * 1000

# With percentile label (if available)
(rate(message_processing_seconds_sum{le="10"}[1m]) / rate(message_processing_seconds_count[1m])) * 1000
```

**What it measures**: Mean time from producer send to consumer receive
**Expected range**: 8ms at baseline, 40ms+ at peak load
**Resume metric**: "achieved 18ms average latency"

---

#### 3. **P95 Latency (95th percentile)**
```promql
# 95th percentile latency (converts seconds to ms)
histogram_quantile(0.95, rate(message_processing_seconds_bucket[1m])) * 1000
```

**What it measures**: 95% of messages complete within this time
**Expected range**: 20-60ms at baseline, 100-200ms at peak
**Resume metric**: "P95 latency of 95.6ms"
**Why it matters**: SLA guarantees, customer expectations

---

#### 4. **P99 Latency (99th percentile)**
```promql
# 99th percentile latency
histogram_quantile(0.99, rate(message_processing_seconds_bucket[1m])) * 1000
```

**What it measures**: 99% of messages complete within this time
**Expected range**: 30-100ms at baseline, 200-400ms at peak
**Resume metric**: "P99 latency of 156.8ms"
**Why it matters**: Catches outlier slowdowns

---

#### 5. **Consumer Lag (messages)**
```promql
# Current consumer lag (how many messages behind)
consumer_lag_current

# With consumer group
consumer_lag_current{group="webhook-consumer"}
```

**What it measures**: How many messages waiting in queue to be consumed
**Expected range**: 0-10 at baseline, 50-500 at peak (should recover)
**Resume metric**: "maintained <10 message consumer lag"
**Healthy trend**: Spikes during load, drops back to 0 when load ends

---

#### 6. **Error Rate (%)**
```promql
# Errors per second
rate(consumer_errors_total[1m])

# Error percentage
(rate(consumer_errors_total[1m]) / rate(messages_consumed_total[1m])) * 100
```

**What it measures**: Percentage of messages that failed to process
**Expected range**: 0-0.1% at baseline, <1% at peak
**Resume metric**: "maintained <0.5% error rate under 100 RPS"

---

#### 7. **Success Rate (%)**
```promql
# Success percentage (opposite of error rate)
(rate(messages_consumed_total[1m]) / rate(messages_produced_total[1m])) * 100

# As a ratio
messages_consumed_total / messages_produced_total
```

**What it measures**: Percentage of messages successfully processed
**Expected range**: >99.5% for production systems
**Resume metric**: "99.88% end-to-end delivery rate"

---

## Advanced Monitoring

### CPU & Memory Usage During Tests

```bash
# Terminal 1: Watch real-time Docker stats
docker stats

# Expected during 100 RPS:
# api:    ~15-25% CPU,  ~80MB memory
# worker: ~20-30% CPU,  ~120MB memory
```

### Kafka Broker Metrics

```promql
# Messages in topic
kafka_topic_partitions{topic="webhooks"}

# Consumer group offset
kafka_consumergroup_lag{consumergroup="webhook-consumer"}
```

### API Response Times (from API metrics)

```promql
# HTTP request duration
rate(http_request_duration_seconds_sum[1m]) / rate(http_request_duration_seconds_count[1m])

# P95 HTTP latency
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[1m]))
```

---

## Execution Plan: Step-by-Step

### Phase 1: Baseline Test (5 minutes)

```bash
# Start services
docker-compose up -d

# Wait for all services to be healthy
sleep 10

# Run baseline (5 RPS, 30 seconds)
node scripts/progressive-load-test.js

# While running, in another terminal:
# Open Prometheus and run queries
```

**What to record**:
- [ ] Baseline latency (should be ~8-10ms avg, <20ms P95)
- [ ] Error rate (should be 0%)
- [ ] Consumer lag (should be 0)
- [ ] CPU usage (should be <10%)

---

### Phase 2: Progressive Load Test (15 minutes)

```bash
# Clear any backlog
docker-compose restart worker

# Run full progressive test (5→25→50→100→200 RPS)
node scripts/progressive-load-test.js

# This will automatically output summary table
```

**What to record**:
- [ ] Max sustainable RPS (P95 < 100ms)
- [ ] Breaking point (where errors spike)
- [ ] Latency degradation curve
- [ ] Consumer lag at each stage

---

### Phase 3: Sustained Load Test (7 minutes)

```bash
# Run at your max sustainable RPS (e.g., 50 RPS for 5 minutes)
node scripts/sustained-load-test.js 50 300

# Monitor metrics and consumer lag
```

**What to record**:
- [ ] Sustained throughput (should match target)
- [ ] Stability (latency shouldn't degrade over time)
- [ ] Consumer lag trend (should stay stable or trend down)
- [ ] Memory/CPU (should remain stable, no leaks)

---

### Phase 4: Latency Breakdown (2 minutes)

```bash
# Detailed latency analysis on 100 samples
node scripts/latency-breakdown-test.js 100

# For more samples:
node scripts/latency-breakdown-test.js 500
```

**What to record**:
- [ ] API response time distribution
- [ ] P95 and P99 latencies
- [ ] Percentage of requests < 10ms, < 50ms, < 100ms

---

## Prometheus Dashboard Queries

Add these to Grafana for visualization:

### Panel 1: Throughput (RPS)
```promql
rate(messages_produced_total[1m])
```
**Graph type**: Time series
**Y-axis label**: RPS
**Color**: Green

---

### Panel 2: Latency Percentiles
```promql
# Query A
histogram_quantile(0.50, rate(message_processing_seconds_bucket[1m])) * 1000
# Label: P50

# Query B
histogram_quantile(0.95, rate(message_processing_seconds_bucket[1m])) * 1000
# Label: P95

# Query C
histogram_quantile(0.99, rate(message_processing_seconds_bucket[1m])) * 1000
# Label: P99
```
**Graph type**: Time series
**Y-axis label**: Latency (ms)
**Colors**: Blue, Orange, Red

---

### Panel 3: Consumer Lag
```promql
consumer_lag_current
```
**Graph type**: Time series
**Y-axis label**: Messages
**Color**: Orange
**Alert threshold**: >100 messages

---

### Panel 4: Error Rate
```promql
(rate(consumer_errors_total[1m]) / rate(messages_consumed_total[1m])) * 100
```
**Graph type**: Time series
**Y-axis label**: Error %
**Color**: Red
**Alert threshold**: >1%

---

## Interpreting Results

### Healthy Metrics (Production-Ready)
```
✅ Throughput:      100+ RPS
✅ Avg Latency:     < 50ms
✅ P95 Latency:     < 100ms
✅ P99 Latency:     < 200ms
✅ Error Rate:      < 0.5%
✅ Success Rate:    > 99.5%
✅ Consumer Lag:    < 50 messages
✅ CPU Usage:       < 40% per service
✅ Memory Usage:    < 200MB per service
```

### Warning Metrics (Needs Optimization)
```
⚠️  Throughput:      50-100 RPS
⚠️  Avg Latency:     50-100ms
⚠️  P95 Latency:     100-200ms
⚠️  Error Rate:      0.5-2%
⚠️  Consumer Lag:    50-500 messages (growing)
⚠️  CPU Usage:       40-70% per service
⚠️  Memory Usage:    200-400MB per service
```

### Critical Metrics (Requires Fixing)
```
❌ Throughput:      < 50 RPS
❌ Avg Latency:     > 100ms
❌ P95 Latency:     > 200ms
❌ Error Rate:      > 2%
❌ Success Rate:    < 99%
❌ Consumer Lag:    > 1000 messages (and growing)
❌ CPU Usage:       > 80% per service
❌ Memory Usage:    > 400MB per service
```

---

## Sample Results Template

Copy this into a file called `PERFORMANCE_RESULTS.md`:

```markdown
# Performance Test Results - [Date]

## Test Environment
- **Date**: [YYYY-MM-DD]
- **Duration**: [Minutes]
- **Docker Compose**: 7 services (Kafka, Redis, API, Worker, Prometheus, Grafana, Zookeeper)
- **Load Test Script**: progressive-load-test.js

## Progressive Load Test Results

| Stage    | RPS | Avg (ms) | P95 (ms) | P99 (ms) | Error % | Notes |
|----------|-----|----------|----------|----------|---------|-------|
| Baseline |   5 |     8.42 |    15.34 |    22.10 |    0.00 | Baseline performance |
| Light    |  25 |    12.30 |    28.50 |    45.20 |    0.02 | Stable operation |
| Moderate |  50 |    18.60 |    52.30 |    87.40 |    0.05 | Approaching limit |
| Heavy    | 100 |    42.20 |    95.60 |   156.80 |    0.12 | Sustainable max |
| Peak     | 200 |    87.50 |   210.30 |   342.10 |    1.25 | Breaking point |

## Key Findings
1. **Max Sustainable Throughput**: 100 RPS (P95: 95.6ms, Error: 0.12%)
2. **Latency Degradation**: ~1ms increase per 25 RPS
3. **Error Rate**: Starts increasing above 100 RPS
4. **Consumer Lag**: Recovers to <10 messages after each stage

## Resume Bullets Generated
- "Engineered Kafka producer/consumer handling 100 RPS with 95.6ms P95 latency"
- "Maintained 99.88% end-to-end message delivery rate under peak load"
- "Implemented consumer group auto-rebalancing with exponential backoff retry logic"
```

---

## Troubleshooting

### Issue: "Connection refused" errors
```bash
# Services not running
docker-compose ps

# Restart if needed
docker-compose restart api worker

# Wait 5 seconds before retrying test
sleep 5
```

### Issue: High memory usage
```bash
# Check Docker logs for leaks
docker-compose logs worker | grep -i "memory\|error"

# Restart worker
docker-compose restart worker

# Monitor memory during next test
docker stats | grep worker
```

### Issue: Decreasing throughput over time
```bash
# Indicates backpressure/consumer lag
# Check consumer lag
curl http://localhost:5007/metrics | grep consumer_lag

# Increase worker replicas (if using Kubernetes)
# Or restart worker
docker-compose restart worker
```

### Issue: Prometheus queries returning no data
```bash
# Verify metrics are being exported
curl http://localhost:5006/metrics | head -20
curl http://localhost:5007/metrics | head -20

# Check Prometheus targets
open http://localhost:9090/targets

# Both should show "UP"
```

---

## Commands Reference

```bash
# Start infrastructure
docker-compose up -d

# View logs
docker-compose logs -f api
docker-compose logs -f worker

# Monitor resources
docker stats

# Run load tests
node scripts/progressive-load-test.js
node scripts/sustained-load-test.js 50 300
node scripts/latency-breakdown-test.js 100

# Check metrics
curl http://localhost:5006/metrics
curl http://localhost:5007/metrics

# Stop services
docker-compose down

# Clean up (reset lag, errors)
docker-compose down -v
docker-compose up -d
```

---

## Next Steps

1. **Run all three tests** and record results
2. **Screenshot Grafana** during peak load
3. **Compile results** into `PERFORMANCE_RESULTS.md`
4. **Generate resume bullets** using templates + actual numbers
5. **Share with team** or add to portfolio
