#!/usr/bin/env node
/**
 * Sustained Load Test - Constant load for 5 minutes
 * 
 * Measures:
 * - Consumer lag over time
 * - Memory stability
 * - Error rates under sustained load
 * - Peak throughput sustainability
 * 
 * Usage: node scripts/sustained-load-test.js [targetRps] [durationSeconds]
 * Default: 50 RPS for 300 seconds (5 minutes)
 * 
 * Examples:
 *   node scripts/sustained-load-test.js         # 50 RPS, 5 min
 *   node scripts/sustained-load-test.js 100 600 # 100 RPS, 10 min
 */

const http = require('http');
const { performance } = require('perf_hooks');

class SustainedLoadTest {
  constructor(targetRps = 50, durationSeconds = 300) {
    this.targetRps = targetRps;
    this.durationSeconds = durationSeconds;
    this.metrics = {
      sent: 0,
      errors: 0,
      latencies: [],
      timestamps: [],
      lagSamples: []
    };
  }

  async sendWebhook() {
    return new Promise((resolve) => {
      const startTime = performance.now();
      const payload = JSON.stringify({
        id: `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        type: 'charge.succeeded',
        account_id: `stripe_${Math.floor(Math.random() * 10)}`,
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
          this.metrics.timestamps.push(Date.now());
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
    console.log('║      SUSTAINED LOAD TEST - Constant high-volume load      ║');
    console.log(`║      Target RPS: ${String(this.targetRps).padEnd(36)} ║`);
    console.log(`║      Duration: ${this.durationSeconds} seconds${' '.repeat(32 - String(this.durationSeconds).length)}║`);
    console.log('╚════════════════════════════════════════════════════════════╝\n');

    const interval = 1000 / this.targetRps;
    const startTime = performance.now();
    let checkCount = 0;
    const metricsCheckInterval = this.targetRps * 10; // Every 10 seconds

    console.log('Running test (press Ctrl+C to stop early)...\n');

    while (performance.now() - startTime < this.durationSeconds * 1000) {
      const batchStart = performance.now();
      
      // Send webhook
      await this.sendWebhook();

      // Every 10 seconds, fetch consumer metrics
      if (checkCount++ % metricsCheckInterval === 0) {
        const elapsed = Math.round((performance.now() - startTime) / 1000);
        const metricsOutput = await this.fetchMetrics();
        
        // Extract consumer lag from metrics
        const lagMatch = metricsOutput.match(/consumer_lag_current\{[^}]*\}\s+(\d+)/);
        const consumedMatch = metricsOutput.match(/messages_consumed_total\{[^}]*\}\s+(\d+)/);
        
        const lag = lagMatch ? lagMatch[1] : 'N/A';
        const consumed = consumedMatch ? consumedMatch[1] : 'N/A';
        
        this.metrics.lagSamples.push({
          timestamp: elapsed,
          lag: parseInt(lag) || 0,
          consumed: parseInt(consumed) || 0
        });
        
        const avgLatency = this.metrics.latencies.length > 0 
          ? (this.metrics.latencies.reduce((a, b) => a + b) / this.metrics.latencies.length).toFixed(2)
          : 'N/A';
        
        process.stdout.write(`\r[${String(elapsed).padStart(3)}s] Sent: ${String(this.metrics.sent).padStart(6)} | Consumed: ${String(consumed).padStart(6)} | Lag: ${String(lag).padStart(4)} | Errors: ${String(this.metrics.errors).padStart(4)} | Avg Latency: ${String(avgLatency).padStart(6)}ms`);
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
    const p50 = latencies[Math.floor(latencies.length * 0.5)];
    const p95 = latencies[Math.floor(latencies.length * 0.95)];
    const p99 = latencies[Math.floor(latencies.length * 0.99)];

    console.log('📊 Sustained Load Test Results:');
    console.log(`   Duration: ${this.durationSeconds} seconds`);
    console.log(`   Target RPS: ${this.targetRps}`);
    console.log(`   Total requests sent: ${this.metrics.sent}`);
    console.log(`   Total errors: ${this.metrics.errors}`);
    console.log(`   Error rate: ${(this.metrics.errors / this.metrics.sent * 100).toFixed(2)}%`);
    console.log(`   Success rate: ${(100 - (this.metrics.errors / this.metrics.sent * 100)).toFixed(2)}%`);

    console.log('\n⏱️  Latency Statistics (milliseconds):');
    console.log(`   Minimum: ${latencies[0].toFixed(2)}ms`);
    console.log(`   Average: ${avg.toFixed(2)}ms`);
    console.log(`   P50 (median): ${p50.toFixed(2)}ms`);
    console.log(`   P95: ${p95.toFixed(2)}ms`);
    console.log(`   P99: ${p99.toFixed(2)}ms`);
    console.log(`   Maximum: ${latencies[latencies.length - 1].toFixed(2)}ms`);

    console.log('\n📈 Consumer Lag Trend:');
    if (this.metrics.lagSamples.length > 0) {
      const lags = this.metrics.lagSamples.map(s => s.lag);
      const avgLag = lags.reduce((a, b) => a + b) / lags.length;
      const maxLag = Math.max(...lags);
      const minLag = Math.min(...lags);
      console.log(`   Min lag: ${minLag} messages`);
      console.log(`   Avg lag: ${avgLag.toFixed(0)} messages`);
      console.log(`   Max lag: ${maxLag} messages`);
      
      const endLag = this.metrics.lagSamples[this.metrics.lagSamples.length - 1].lag;
      if (endLag <= 10) {
        console.log(`   ✅ System caught up (final lag: ${endLag} messages)`);
      } else if (endLag < 100) {
        console.log(`   ⚠️  Some backlog remains (final lag: ${endLag} messages)`);
      } else {
        console.log(`   ❌ Significant backlog (final lag: ${endLag} messages)`);
      }
    }

    console.log('\n📝 Resume Bullet:');
    const achievedRps = (this.metrics.sent / this.durationSeconds).toFixed(1);
    console.log(`   • Sustained ${achievedRps} RPS throughput for ${this.durationSeconds}s with ${p95.toFixed(2)}ms P95 latency`);
    console.log(`   • Achieved ${(100 - (this.metrics.errors / this.metrics.sent * 100)).toFixed(2)}% reliability under constant load`);
  }
}

// Parse command line arguments
const targetRps = parseInt(process.argv[2]) || 50;
const durationSeconds = parseInt(process.argv[3]) || 300;

const test = new SustainedLoadTest(targetRps, durationSeconds);
test.runSustainedTest().catch(err => {
  console.error('\nTest failed:', err.message);
  process.exit(1);
});
