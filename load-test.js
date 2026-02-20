/**
 * Load test for Deepiri Kafka architecture
 * 
 * Tests webhook ingestion at scale
 * 
 * Installation:
 *   brew install k6   # macOS
 *   or https://k6.io/docs/getting-started/installation/
 * 
 * Run:
 *   k6 run load-test.js
 * 
 * View results in Grafana:
 *   http://localhost:3000 (admin:admin)
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Histogram } from 'k6/metrics';

// Custom metrics
const webhooksReceived = new Counter('webhooks_received');
const apiLatency = new Histogram('api_latency');
const syncJobsTriggered = new Counter('sync_jobs_triggered');

export const options = {
  // Stages: ramp up -> sustain -> ramp down
  stages: [
    { duration: '10s', target: 10 },   // Ramp up to 10 VUs over 10 seconds
    { duration: '30s', target: 50 },   // Ramp up to 50 VUs over 30 seconds
    { duration: '1m', target: 50 },    // Stay at 50 VUs for 1 minute (sustain)
    { duration: '30s', target: 0 },    // Ramp down to 0 VUs over 30 seconds
  ],
  thresholds: {
    'http_req_duration': ['p(95)<500', 'p(99)<1000'], // 95% of requests < 500ms, 99% < 1s
    'http_req_failed': ['rate<0.1'], // error rate < 10%
  },
};

const API_BASE = 'http://localhost:5006';

const providers = ['stripe', 'hubspot', 'salesforce', 'github', 'slack'];
const integrationIds = ['stripe_123', 'hubspot_456', 'salesforce_789', 'github_abc', 'slack_def'];

/**
 * Simulate webhook payload from various providers
 */
function generateWebhookPayload(provider) {
  const now = Date.now();
  
  const payloads = {
    stripe: {
      id: `evt_${now}`,
      type: 'charge.succeeded',
      account_id: 'stripe_123',
      data: {
        object: {
          id: `ch_${Math.random().toString(36).substr(2, 9)}`,
          amount: Math.floor(Math.random() * 10000),
          currency: 'usd',
          customer: `cus_${Math.random().toString(36).substr(2, 9)}`,
        }
      }
    },
    hubspot: {
      id: `evt_${now}`,
      type: 'contact.updated',
      account_id: 'hubspot_456',
      data: {
        contact_id: Math.floor(Math.random() * 100000),
        email: `user_${now}@example.com`,
        properties: {
          firstname: 'Test',
          lastname: 'User'
        }
      }
    },
    salesforce: {
      id: `evt_${now}`,
      type: 'account.updated',
      account_id: 'salesforce_789',
      data: {
        sobject_id: `001${Math.random().toString(36).substr(2, 15)}`,
        fields: ['Name', 'Industry']
      }
    },
    github: {
      id: `evt_${now}`,
      type: 'push',
      account_id: 'github_abc',
      repository: 'deepiri/external-bridge',
      commits: Math.floor(Math.random() * 5) + 1
    },
    slack: {
      id: `evt_${now}`,
      type: 'event_callback',
      account_id: 'slack_def',
      event: {
        type: 'message',
        user: `U${Math.random().toString(36).substr(2, 8)}`,
        text: `Test message ${now}`
      }
    }
  };

  return payloads[provider] || payloads.stripe;
}

/**
 * Test webhook ingestion
 */
export function webhookIngestion() {
  const provider = providers[Math.floor(Math.random() * providers.length)];
  const payload = generateWebhookPayload(provider);

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'k6-load-test',
    },
  };

  const startTime = new Date();
  const response = http.post(`${API_BASE}/webhooks/${provider}`, JSON.stringify(payload), params);
  const latency = new Date() - startTime;

  apiLatency.add(latency);
  webhooksReceived.add(1);

  check(response, {
    'webhook accepted (202)': (r) => r.status === 202,
    'response has event_id': (r) => r.json('event_id') !== null,
    'response has correlation_id': (r) => r.json('correlation_id') !== null,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });

  sleep(0.1); // Small delay between requests
}

/**
 * Test sync job triggering
 */
export function syncJobTriggering() {
  const integrationId = integrationIds[Math.floor(Math.random() * integrationIds.length)];
  const payload = {
    integration_id: integrationId,
    force: Math.random() > 0.7, // 30% of syncs are forced
  };

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'k6-load-test',
    },
  };

  const response = http.post(`${API_BASE}/integrations/sync`, JSON.stringify(payload), params);
  syncJobsTriggered.add(1);

  check(response, {
    'sync job accepted (202)': (r) => r.status === 202,
    'response has job_id': (r) => r.json('job_id') !== null,
  });

  sleep(0.2);
}

/**
 * Test health endpoint
 */
export function healthCheck() {
  const response = http.get(`${API_BASE}/health`);

  check(response, {
    'health is healthy': (r) => r.json('status') === 'healthy' || r.json('status') === 'degraded',
    'kafka producer connected': (r) => r.json('components.kafka_producer.connected') === true,
    'redis connected': (r) => r.json('components.redis.connected') === true,
  });

  sleep(1);
}

/**
 * Test metrics endpoint
 */
export function metricsCheck() {
  const response = http.get(`${API_BASE}/metrics`);

  check(response, {
    'metrics endpoint returns 200': (r) => r.status === 200,
    'metrics contains produced count': (r) => r.body.includes('messages_produced_total'),
    'metrics contains processed count': (r) => r.body.includes('messages_consumed_total'),
  });

  sleep(2);
}

/**
 * Main test function
 * Distribute load across different scenarios
 */
export default function () {
  const scenario = Math.random();

  if (scenario < 0.7) {
    // 70% webhook requests
    webhookIngestion();
  } else if (scenario < 0.9) {
    // 20% sync requests
    syncJobTriggering();
  } else if (scenario < 0.95) {
    // 5% health checks
    healthCheck();
  } else {
    // 5% metrics checks
    metricsCheck();
  }
}

/**
 * Setup: Run before test
 */
export function setup() {
  console.log('Starting load test...');
  console.log(`Target: ${API_BASE}`);
  console.log('Stages: Ramp up (40s) -> Sustain (60s) -> Ramp down (30s)');
}

/**
 * Teardown: Run after test
 */
export function teardown(data) {
  const summaryEndpoint = `${API_BASE}/metrics`;
  const response = http.get(summaryEndpoint);
  
  console.log('\n=== Load Test Results ===');
  console.log(`Test completed. Check Grafana at http://localhost:3000`);
  console.log(`Prometheus at http://localhost:9090`);
}
