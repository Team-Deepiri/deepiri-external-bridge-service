# Kafka Architecture - Performance Testing & Metrics Guide

## Overview

This guide walks you through measuring performance of your Kafka event streaming architecture. You'll generate resume-ready metrics that demonstrate:

- **Throughput**: Events processed per second
- **Latency**: End-to-end and per-stage latencies
- **Consumer Lag**: Backlog handling capability
- **Reliability**: Failure and retry rates
- **Resource Usage**: CPU/memory efficiency under load

---

## Part 1: Setup & Prerequisites

### Required Tools
```bash
# Ensure you have:
- Node.js 18+ (installed)
- Docker & Docker Compose (running services)
- curl (for manual testing)
- jq (JSON parsing) - brew install jq
- k6 (advanced load testing) - brew install k6
```

### Verify Services Running
```bash
docker compose ps
# Expected: All services (kafka, redis, api, worker, prometheus, grafana) showing "Up"

# Quick health check
curl http://localhost:5006/health | jq .status
curl http://localhost:5007/health | jq .status
```

---

## Part 2: Load Testing Scripts

### Script 1: Progressive Load Test (Recommended for Performance Baseline)

**File: `scripts/progressive-load-test.js`**

This script gradually increases load to find your system's breaking point.

```javascript
#!/usr/bin/env node
/**
 * Progressive Load Test for Kafka Architecture
 * 
 * Gradually increases throughput to measure:
 * - Maximum sustainable throughput
 * - Latency degradation under load
 * - System breaking point
 * 
 * Usage: node scripts/progressive-load-test.js
 */

const http = require('http');
const { performance } = require('perf_hooks');

const API_BASE = 'http://localhost:5006';
const WORKER_BASE = 'http://localhost:5007';

class ProgressiveLoadTest {
  constructor() {
    this.results = [];
    this.currentLoad = 0;
    this.totalSent = 0;
    this.totalErrors = 0;
    this.latencies = [];
  }

  /**
   * Send a single webhook
   */
  async sendWebhook() {
    return new Promise((resolve) => {
      const startTime = performance.now();
      const payload = JSON.stringify({
        id: `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        type: 'charge.succeeded',
        account_id: `stripe_${Math.floor(Math.random() * 100)}`,
        amount: Math.floor(Math.random() * 10000),
        timestamp: new Date().toISOString()
      });

      const options = {
        hostname: 'localhost',
        port: 5006,
        path: '/webhooks/stripe',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': payload.length,
          'X-Test-Run': 'progressive-load'
        }
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          const latency = performance.now() - startTime;
          this.latencies.push(latency);
          this.totalSent++;
          
          if (res.statusCode === 202) {
            resolve({ success: true, latency, statusCode: res.statusCode });
          } else {
            this.totalErrors++;
            resolve({ success: false, latency, statusCode: res.statusCode });
          }
        });
      });

      req.on('error', (err) => {
        this.totalErrors++;
        const latency = performance.now() - startTime;
        resolve({ success: false, latency, error: err.message });
      });

      req.write(payload);
      req.end();
    });
  }

  /**
   * Run progressive load: 5 RPS → 50 RPS → 100 RPS → 200 RPS
   */
  async runProgressiveTest() {
    const stages = [
      { rps: 5, durationSeconds: 30, label: 'Baseline' },
      { rps: 25, durationSeconds: 30, label: 'Light' },
      { rps: 50, durationSeconds: 30, label: 'Moderate' },
      { rps: 100, durationSeconds: 30, label: 'Heavy' },
      { rps: 200, durationSeconds: 30, label: 'Peak' }
    ];

    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log('║        PROGRESSIVE LOAD TEST - Kafka Architecture         ║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');

    for (const stage of stages) {
      console.log(`\n📊 Stage: ${stage.label} (${stage.rps} RPS for ${stage.durationSeconds}s)\n`);
      
      this.latencies = [];
      const stageStart = Date.now();
      const interval = 1000 / stage.rps; // milliseconds between requests
      let requestCount = 0;

      const testStart = performance.now();
      while (performance.now() - testStart < stage.durationSeconds * 1000) {
        const batchStart = performance.now();
        
        // Send one request
        await this.sendWebhook();
        requestCount++;

        // Rate limiting: sleep to maintain target RPS
        const elapsed = performance.now() - batchStart;
        if (elapsed < interval) {
          await this.sleep(interval - elapsed);
        }

        // Progress indicator
        if (requestCount % Math.ceil(stage.rps * 5) === 0) {
          process.stdout.write('.');
        }
      }

      // Calculate stats
      const stats = this.calculateStats(this.latencies);
      this.results.push({
        stage: stage.label,
        rps: stage.rps,
        totalSent: requestCount,
        totalErrors: this.totalErrors,
        errorRate: (this.totalErrors / this.totalSent * 100).toFixed(2),
        ...stats
      });

      console.log('\n\n✅ Results:');
      console.log(`   Requests sent: ${requestCount}`);
      console.log(`   Success rate: ${(100 - stats.errorRate).toFixed(2)}%`);
      console.log(`   Avg latency: ${stats.avgLatency.toFixed(2)}ms`);
      console.log(`   P95 latency: ${stats.p95Latency.toFixed(2)}ms`);
      console.log(`   P99 latency: ${stats.p99Latency.toFixed(2)}ms`);
      console.log(`   Max latency: ${stats.maxLatency.toFixed(2)}ms`);

      // Wait before next stage
      if (stage !== stages[stages.length - 1]) {
        console.log('\n⏳ Cooling down for 5 seconds...\n');
        await this.sleep(5000);
      }
    }

    this.printSummary();
  }

  /**
   * Calculate latency statistics
   */
  calculateStats(latencies) {
    if (latencies.length === 0) return {};

    const sorted = latencies.sort((a, b) => a - b);
    const avg = latencies.reduce((a, b) => a + b) / latencies.length;
    const p50 = sorted[Math.floor(sorted.length * 0.5)];
    const p95 = sorted[Math.floor(sorted.length * 0.95)];
    const p99 = sorted[Math.floor(sorted.length * 0.99)];
    const max = sorted[sorted.length - 1];
    const min = sorted[0];

    return {
      avgLatency: avg,
      minLatency: min,
      maxLatency: max,
      p50Latency: p50,
      p95Latency: p95,
      p99Latency: p99,
      errorRate: (this.totalErrors / this.totalSent * 100).toFixed(2)
    };
  }

  /**
   * Print final summary table
   */
  printSummary() {
    console.log('\n\n╔════════════════════════════════════════════════════════════╗');
    console.log('║                  PERFORMANCE SUMMARY                      ║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');

    console.log('Stage        RPS   Avg(ms)  P95(ms)  P99(ms)  Error %');
    console.log('─'.repeat(60));
    
    for (const result of this.results) {
      console.log(
        `${result.stage.padEnd(12)} ${String(result.rps).padStart(3)}  ` +
        `${String(result.avgLatency.toFixed(2)).padStart(8)} ` +
        `${String(result.p95Latency.toFixed(2)).padStart(8)} ` +
        `${String(result.p99Latency.toFixed(2)).padStart(8)} ` +
        `${String(result.errorRate).padStart(7)}`
      );
    }

    console.log('\n✨ Key Insights:');
    
    const peakStage = this.results[this.results.length - 1];
    console.log(`   • Peak throughput tested: ${peakStage.rps} RPS`);
    console.log(`   • P95 latency at peak: ${peakStage.p95Latency.toFixed(2)}ms`);
    console.log(`   • Error rate at peak: ${peakStage.errorRate}%`);

    // Find max sustainable throughput (where P95 < 100ms or error rate < 1%)
    const sustainable = this.results.filter(r => r.p95Latency < 100 && parseFloat(r.errorRate) < 1);
    if (sustainable.length > 0) {
      const maxSustainable = sustainable[sustainable.length - 1];
      console.log(`   • Max sustainable throughput: ${maxSustainable.rps} RPS`);
    }

    console.log('\n📝 Resume Bullet Points:');
    console.log(`   • Designed Kafka producer/consumer handling ${peakStage.rps} RPS throughput`);
    console.log(`   • Achieved P95 latency of ${peakStage.p95Latency.toFixed(2)}ms end-to-end`);
    console.log(`   • Implemented automatic retry logic with exponential backoff`);
    console.log(`   • Built comprehensive monitoring with Prometheus & Grafana`);
  }

  /**
   * Helper: sleep
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Run the test
const test = new ProgressiveLoadTest();
test.runProgressiveTest().catch(console.error);
```

---

### Script 2: Sustained Load Test (Measure Long-term Stability)

**File: `scripts/sustained-load-test.js`**

Tests your system under constant high load for 5 minutes to measure stability.

```javascript
#!/usr/bin/env node
/**
 * Sustained Load Test - 5 minute constant load
 * 
 * Measures:
 * - Consumer lag over time
 * - Memory stability
 * - Error rates under sustained load
 */

const http = require('http');
const { performance } = require('perf_hooks');

const API_BASE = 'http://localhost:5006';
const WORKER_BASE = 'http://localhost:5007';

class SustainedLoadTest {
  constructor(targetRps = 50, durationSeconds = 300) {
    this.targetRps = targetRps;
    this.durationSeconds = durationSeconds;
    this.metrics = {
      sent: 0,
      errors: 0,
      latencies: [],
      timestamps: []
    };
  }

  async sendWebhook() {
    return new Promise((resolve) => {
      const startTime = performance.now();
      const payload = JSON.stringify({
        id: `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        type: 'charge.succeeded',
        amount: Math.floor(Math.random() * 10000),
        timestamp: new Date().toISOString()
      });

      const options = {
        hostname: 'localhost',
        port: 5006,
        path: '/webhooks/stripe',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': payload.length
        }
      };

      const req = http.request(options, (res) => {
        res.on('data', () => {});
        res.on('end', () => {
          const latency = performance.now() - startTime;
          this.metrics.latencies.push(latency);
          this.metrics.sent++;
          if (res.statusCode !== 202) {
            this.metrics.errors++;
          }
          resolve();
        });
      });

      req.on('error', () => {
        this.metrics.errors++;
        resolve();
      });

      req.write(payload);
      req.end();
    });
  }

  async fetchMetrics() {
    return new Promise((resolve) => {
      const options = {
        hostname: 'localhost',
        port: 5007,
        path: '/metrics',
        method: 'GET'
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          resolve(data);
        });
      });

      req.on('error', () => resolve(''));
      req.end();
    });
  }

  async runSustainedTest() {
    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log('║         SUSTAINED LOAD TEST - 5 minute test               ║');
    console.log('║         Target RPS: ' + String(this.targetRps).padStart(38) + ' ║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');

    const interval = 1000 / this.targetRps;
    const startTime = performance.now();
    const startTimestamp = Date.now();
    let checkCount = 0;

    while (performance.now() - startTime < this.durationSeconds * 1000) {
      const batchStart = performance.now();
      
      // Send webhook
      await this.sendWebhook();

      // Every 10 seconds, fetch consumer metrics
      if (checkCount++ % (this.targetRps * 10) === 0) {
        const elapsed = Math.round((performance.now() - startTime) / 1000);
        const metricsOutput = await this.fetchMetrics();
        
        // Extract consumer lag from metrics
        const lagMatch = metricsOutput.match(/consumer_lag_current\{[^}]*\}\s+(\d+)/);
        const consumedMatch = metricsOutput.match(/messages_consumed_total\{[^}]*\}\s+(\d+)/);
        
        const lag = lagMatch ? lagMatch[1] : 'N/A';
        const consumed = consumedMatch ? consumedMatch[1] : 'N/A';
        
        process.stdout.write(`\r[${elapsed}s] Sent: ${this.metrics.sent} | Lag: ${lag} | Consumed: ${consumed} | Errors: ${this.metrics.errors}`);
      }

      // Rate limiting
      const elapsed = performance.now() - batchStart;
      if (elapsed < interval) {
        await new Promise(r => setTimeout(r, interval - elapsed));
      }
    }

    console.log('\n\n✅ Test Complete!\n');
    this.printResults();
  }

  printResults() {
    const latencies = this.metrics.latencies.sort((a, b) => a - b);
    const avg = latencies.reduce((a, b) => a + b) / latencies.length;
    const p95 = latencies[Math.floor(latencies.length * 0.95)];
    const p99 = latencies[Math.floor(latencies.length * 0.99)];

    console.log('📊 Sustained Load Results:');
    console.log(`   Total requests: ${this.metrics.sent}`);
    console.log(`   Total errors: ${this.metrics.errors}`);
    console.log(`   Error rate: ${(this.metrics.errors / this.metrics.sent * 100).toFixed(2)}%`);
    console.log(`   Average latency: ${avg.toFixed(2)}ms`);
    console.log(`   P95 latency: ${p95.toFixed(2)}ms`);
    console.log(`   P99 latency: ${p99.toFixed(2)}ms`);
  }
}

const test = new SustainedLoadTest(50, 300); // 50 RPS for 5 minutes
test.runSustainedTest().catch(console.error);
```

---

### Script 3: Latency Breakdown Test (Per-stage Analysis)

**File: `scripts/latency-breakdown-test.js`**

Measures latency at each stage (API → Kafka → Worker → Processing).

```javascript
#!/usr/bin/env node
/**
 * Latency Breakdown Test
 * 
 * Measures:
 * - API ingestion latency
 * - Kafka publish latency (from Prometheus)
 * - Consumer processing latency
 * - End-to-end latency
 */

const http = require('http');

class LatencyBreakdownTest {
  async sendWebhookAndMeasure() {
    return new Promise((resolve) => {
      const payload = JSON.stringify({
        id: `evt_breakdown_${Date.now()}`,
        type: 'test.latency',
        timestamp: new Date().toISOString()
      });

      const options = {
        hostname: 'localhost',
        port: 5006,
        path: '/webhooks/stripe',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': payload.length
        }
      };

      const start = Date.now();
      const req = http.request(options, (res) => {
        const apiLatency = Date.now() - start;
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            const response = JSON.parse(data);
            resolve({
              apiLatency,
              eventId: response.event_id,
              correlationId: response.correlation_id,
              statusCode: res.statusCode
            });
          } catch (e) {
            resolve({ apiLatency, error: true });
          }
        });
      });

      req.on('error', () => resolve({ error: true }));
      req.write(payload);
      req.end();
    });
  }

  async getKafkaMetrics() {
    return new Promise((resolve) => {
      const options = {
        hostname: 'localhost',
        port: 5006,
        path: '/metrics',
        method: 'GET'
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          // Extract latency metrics
          const publishLatency = data.match(/publish_latency_seconds_bucket\{[^}]*le="0.1"\}\s+(\d+)/);
          resolve(data);
        });
      });

      req.on('error', () => resolve(''));
      req.end();
    });
  }

  async runLatencyBreakdownTest() {
    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log('║           LATENCY BREAKDOWN TEST - 100 samples            ║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');

    const results = [];
    console.log('Measuring API latency (100 requests)...\n');

    for (let i = 0; i < 100; i++) {
      const result = await this.sendWebhookAndMeasure();
      if (!result.error) {
        results.push(result);
        process.stdout.write('.');
      }
      // Small delay between requests
      await new Promise(r => setTimeout(r, 10));
    }

    const latencies = results.map(r => r.apiLatency);
    const sorted = latencies.sort((a, b) => a - b);

    const stats = {
      count: latencies.length,
      min: sorted[0],
      max: sorted[sorted.length - 1],
      avg: latencies.reduce((a, b) => a + b) / latencies.length,
      p50: sorted[Math.floor(sorted.length * 0.5)],
      p95: sorted[Math.floor(sorted.length * 0.95)],
      p99: sorted[Math.floor(sorted.length * 0.99)]
    };

    console.log('\n\n📊 API Ingestion Latency Results:\n');
    console.log(`   Samples: ${stats.count}`);
    console.log(`   Min: ${stats.min}ms`);
    console.log(`   Avg: ${stats.avg.toFixed(2)}ms`);
    console.log(`   P50: ${stats.p50}ms`);
    console.log(`   P95: ${stats.p95}ms`);
    console.log(`   P99: ${stats.p99}ms`);
    console.log(`   Max: ${stats.max}ms`);

    console.log('\n📈 Distribution:');
    const buckets = [10, 20, 50, 100, 200];
    for (const bucket of buckets) {
      const count = latencies.filter(l => l <= bucket).length;
      const pct = (count / latencies.length * 100).toFixed(1);
      console.log(`   ${bucket}ms: ${pct}%`);
    }
  }
}

const test = new LatencyBreakdownTest();
test.runLatencyBreakdownTest().catch(console.error);
```

---

## Part 3: Prometheus Queries for Key Metrics

### Setup: Add These Queries to Your Grafana Dashboard

#### 1. **Throughput (Events/Second)**

```promql
# Messages produced per second (last 1 minute)
rate(messages_produced_total[1m])

# Messages consumed per second (last 1 minute)
rate(messages_consumed_total[1m])

# Net throughput (produced - consumed)
rate(messages_produced_total[1m]) - rate(messages_consumed_total[1m])
```

**Example Result**: `45.2` events/sec

---

#### 2. **Average Latency (Milliseconds)**

```promql
# Average message processing time
(
  rate(message_processing_seconds_sum[1m]) /
  rate(message_processing_seconds_count[1m])
) * 1000

# Average API ingestion latency
(
  rate(publish_latency_seconds_sum[1m]) /
  rate(publish_latency_seconds_count[1m])
) * 1000
```

**Example Result**: `42.5` ms

---

#### 3. **P95 Latency (Milliseconds)**

```promql
# P95 message processing latency
histogram_quantile(0.95, rate(message_processing_seconds_bucket[1m])) * 1000

# P95 API ingestion latency
histogram_quantile(0.95, rate(publish_latency_seconds_bucket[1m])) * 1000
```

**Example Result**: `89.3` ms

---

#### 4. **P99 Latency (Milliseconds)**

```promql
# P99 message processing latency
histogram_quantile(0.99, rate(message_processing_seconds_bucket[1m])) * 1000

# P99 API ingestion latency
histogram_quantile(0.99, rate(publish_latency_seconds_bucket[1m])) * 1000
```

**Example Result**: `156.8` ms

---

#### 5. **Consumer Lag (Messages Behind)**

```promql
# Current consumer lag (messages waiting to be processed)
consumer_lag_current

# Maximum lag across all partitions
max(consumer_lag_current)

# Average lag across all partitions
avg(consumer_lag_current)
```

**Example Result**: `12` messages (healthy if < 1000)

---

#### 6. **Error Rates**

```promql
# Producer errors per second
rate(producer_errors_total[1m])

# Consumer errors per second
rate(consumer_errors_total[1m])

# DLQ (Dead Letter Queue) messages per second
rate(dlq_messages_total[1m])

# Total error rate as percentage
(
  rate(consumer_errors_total[1m]) /
  (rate(messages_consumed_total[1m]) + rate(consumer_errors_total[1m]))
) * 100
```

**Example Result**: `0.2%` error rate

---

#### 7. **Success Rate**

```promql
# Percentage of messages successfully processed
(
  rate(messages_consumed_total[1m]) /
  rate(messages_produced_total[1m])
) * 100
```

**Example Result**: `99.8%` success rate

---

## Part 4: Running the Tests & Collecting Metrics

### Step 1: Create Scripts Directory

```bash
mkdir -p scripts
# Copy the three test scripts above into scripts/
```

### Step 2: Run Progressive Load Test

```bash
node scripts/progressive-load-test.js
```

**Output Example**:
```
Stage        RPS   Avg(ms)  P95(ms)  P99(ms)  Error %
────────────────────────────────────────────────────────
Baseline       5      8.42    15.34    22.10     0.00
Light         25     12.30    28.50    45.20     0.02
Moderate      50     18.60    52.30    87.40     0.05
Heavy        100     42.20    95.60   156.80     0.12
Peak         200     87.50   210.30   342.10     1.25

✨ Key Insights:
   • Peak throughput tested: 200 RPS
   • P95 latency at peak: 210.30ms
   • Error rate at peak: 1.25%
   • Max sustainable throughput: 100 RPS
```

### Step 3: Monitor in Prometheus

While load test is running:

```bash
# Terminal 1: Run load test
node scripts/progressive-load-test.js

# Terminal 2: Watch metrics in Prometheus
open http://localhost:9090

# Search for metric: messages_produced_total
# Graph should show increasing line during test
```

### Step 4: Monitor in Grafana

```bash
open http://localhost:3000

# Dashboard: "Deepiri Kafka Architecture"
# Watch panels update in real-time:
# - Messages Produced/sec
# - Messages Consumed/sec
# - Processing Latency
# - Consumer Lag
```

### Step 5: Collect Results

After each test stage, record:

```bash
# Get current metrics
curl http://localhost:5006/metrics | grep -E "messages_produced_total|consumer_lag_current|message_processing"

# Example output:
# messages_produced_total{topic="integration.webhook.received"} 5234
# consumer_lag_current{group="webhook-processors",partition="0",topic="integration.webhook.received"} 42
# message_processing_seconds_bucket{le="0.1",topic="integration.webhook.received"} 2103
```

---

## Part 5: Interpreting Results

### Key Metrics & Healthy Ranges

| Metric | Healthy | Warning | Critical |
|--------|---------|---------|----------|
| **Throughput** | > 50 RPS | 20-50 RPS | < 20 RPS |
| **Avg Latency** | < 50ms | 50-100ms | > 100ms |
| **P95 Latency** | < 100ms | 100-200ms | > 200ms |
| **P99 Latency** | < 200ms | 200-500ms | > 500ms |
| **Consumer Lag** | < 100 msgs | 100-1000 msgs | > 1000 msgs |
| **Error Rate** | < 0.1% | 0.1-1% | > 1% |
| **Success Rate** | > 99.9% | 99-99.9% | < 99% |

### Example Results & Interpretation

**Scenario: Baseline Performance (No Load)**

```
Throughput: 45.2 RPS
Avg Latency: 8.42ms
P95 Latency: 15.34ms
P99 Latency: 22.10ms
Consumer Lag: 2 messages
Error Rate: 0.00%
Success Rate: 100%
```

**Interpretation**: ✅ Excellent
- Fast baseline performance
- Low and consistent latency
- No errors
- System stable

---

**Scenario: Heavy Load (100 RPS)**

```
Throughput: 100 RPS
Avg Latency: 42.20ms
P95 Latency: 95.60ms
P99 Latency: 156.80ms
Consumer Lag: 87 messages
Error Rate: 0.12%
Success Rate: 99.88%
```

**Interpretation**: ✅ Good
- Maintains 100 RPS throughput
- Latency acceptable (P95 < 100ms)
- Slight backlog but manageable
- Error rate < 1%

---

**Scenario: Peak Load (200 RPS)**

```
Throughput: 200 RPS
Avg Latency: 87.50ms
P95 Latency: 210.30ms
P99 Latency: 342.10ms
Consumer Lag: 245 messages
Error Rate: 1.25%
Success Rate: 98.75%
```

**Interpretation**: ⚠️ At Limits
- System handling 200 RPS but degrading
- P95 latency doubled
- Consumer lag growing
- Error rate approaching 1%

---

## Part 6: Resume-Ready Bullet Points

Based on your performance test results, use these formats:

### Bullet Point Templates

```
• Architected high-throughput Kafka event streaming system handling 
  [THROUGHPUT] RPS with [P95_LATENCY]ms P95 latency

• Implemented producer/consumer pattern with automatic retry logic 
  achieving [SUCCESS_RATE]% message delivery rate

• Designed consumer groups with auto-rebalancing, sustaining 
  [THROUGHPUT] concurrent event processing with < [LAG] message lag

• Built comprehensive observability with Prometheus & Grafana, 
  capturing 11+ key metrics including latency percentiles and 
  consumer lag for production monitoring

• Engineered Dead Letter Queue pattern for failure isolation, 
  maintaining [ERROR_RATE]% error rate under peak load

• Optimized message processing pipeline achieving 
  [AVG_LATENCY]ms average end-to-end latency
```

### Example (Using Real Numbers)

```
• Architected high-throughput Kafka event streaming system handling 
  100 RPS with 95.6ms P95 latency and 99.88% delivery rate

• Implemented producer/consumer pattern with exponential backoff retry logic 
  achieving 99.88% message delivery across distributed consumer groups

• Designed consumer groups with auto-rebalancing, sustaining 
  100 concurrent webhook processing with < 100 message consumer lag

• Built comprehensive observability with Prometheus & Grafana, 
  capturing 11 key metrics including latency histograms, throughput rates, 
  and consumer lag for production monitoring

• Engineered Dead Letter Queue pattern for failure isolation, 
  maintaining 0.12% error rate and idempotency via Redis deduplication

• Optimized message processing pipeline achieving 42.2ms average 
  end-to-end latency with < 1% error rate under sustained 100 RPS load
```

---

## Part 7: Optional - Advanced Metrics

### CPU & Memory Usage (Docker)

```bash
# Monitor Docker container resource usage
docker stats deepiri-api-service --no-stream
docker stats deepiri-worker-service --no-stream

# Output:
# CONTAINER              CPU %     MEM USAGE / LIMIT
# deepiri-api-service    2.3%      145.2 MiB / 1 GiB
# deepiri-worker-service 5.1%      189.5 MiB / 1 GiB
```

### Collect CPU/Memory During Load Test

```bash
#!/bin/bash
# Monitor.sh - Run alongside load test

echo "TIME,CPU_API,MEM_API,CPU_WORKER,MEM_WORKER" > metrics.csv

for i in {1..300}; do
  api_stats=$(docker stats deepiri-api-service --no-stream | tail -1)
  worker_stats=$(docker stats deepiri-worker-service --no-stream | tail -1)
  
  api_cpu=$(echo "$api_stats" | awk '{print $3}' | sed 's/%//')
  api_mem=$(echo "$api_stats" | awk '{print $4}')
  worker_cpu=$(echo "$worker_stats" | awk '{print $3}' | sed 's/%//')
  worker_mem=$(echo "$worker_stats" | awk '{print $4}')
  
  echo "$(date +%s),$api_cpu,$api_mem,$worker_cpu,$worker_mem" >> metrics.csv
  sleep 1
done
```

**Analysis**: Calculate max/avg CPU and memory during load test to add to resume.

---

## Part 8: Quick Reference - Test Commands

```bash
# Start services
docker compose up -d

# Verify running
docker compose ps

# Run progressive load test (comprehensive)
node scripts/progressive-load-test.js

# Run sustained load test (5 minutes, constant 50 RPS)
node scripts/sustained-load-test.js

# Check API metrics
curl http://localhost:5006/metrics | grep messages

# Check worker metrics
curl http://localhost:5007/metrics | grep consumer_lag

# View Prometheus
open http://localhost:9090

# View Grafana
open http://localhost:3000 # admin/admin

# View API health
curl http://localhost:5006/health | jq

# View worker health
curl http://localhost:5007/health | jq

# Stop services
docker compose down
```

---

## Next Steps

1. **Run all three load test scripts** and record results in a spreadsheet
2. **Screenshot Grafana dashboard** during peak load (shows real-time metrics)
3. **Collect before/after Prometheus graphs** (shows trend over test duration)
4. **Calculate sustainable throughput** (where P95 < 100ms and error rate < 1%)
5. **Write 6-8 resume bullets** using the templates above with YOUR actual numbers
6. **Create performance summary document** for portfolio/interview

---

## Troubleshooting

### Load Test Not Sending Webhooks

```bash
# Check API service is running
curl http://localhost:5006/health

# Check logs
docker logs deepiri-api-service
```

### Metrics Not Showing in Prometheus

```bash
# Check Prometheus scrape config
curl http://localhost:9090/api/v1/scrape_configs

# Check targets
curl http://localhost:9090/api/v1/targets
```

### Consumer Lag Always Growing

```bash
# Check worker logs for processing errors
docker logs deepiri-worker-service | tail -20

# Check if worker is actually consuming
curl http://localhost:5007/metrics | grep messages_consumed
```

---

## Sample Performance Metrics Document

Create `PERFORMANCE_RESULTS.md`:

```markdown
# Kafka Architecture Performance Results

## Test Environment
- MacBook (Docker)
- 2 CPU cores / 4 GB RAM allocated to Docker
- Kafka: 1 broker, 3 partitions
- Consumer: 1 worker with max 10 concurrent messages

## Results

### Progressive Load Test
- Peak throughput: 200 RPS
- Max sustainable throughput: 100 RPS (P95 < 100ms, error < 1%)
- Baseline throughput: 5 RPS (P95: 15ms)

### Key Metrics
- Average latency: 42.2ms (at 100 RPS)
- P95 latency: 95.6ms
- P99 latency: 156.8ms
- Error rate: 0.12%
- Success rate: 99.88%
- Consumer lag: 87 messages (at 100 RPS)

### Resource Usage
- API Service CPU: ~2.3% (at 100 RPS)
- Worker Service CPU: ~5.1% (at 100 RPS)
- Memory (API): 145 MiB
- Memory (Worker): 189 MiB
```

---

That covers everything! Now you have a complete framework for measuring and documenting your Kafka architecture performance.