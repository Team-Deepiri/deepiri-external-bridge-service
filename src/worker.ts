/**
 * Worker Service - Kafka Consumer
 * 
 * This is a separate Node.js process that:
 * 1. Connects to Kafka
 * 2. Consumes messages from topics (webhooks, sync jobs)
 * 3. Processes them with retry/DLQ logic
 * 4. Exposes /health and /metrics endpoints
 * 
 * Run separately from the API service:
 *   npm run build
 *   node dist/worker.js
 */

import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import winston from 'winston';
import { KafkaConsumerService } from './kafka/consumer';
import { HealthCheckService, MetricsService } from './kafka/health';
import kafkaProducerService from './kafka/producer';
import { syncGithubWebhookToPlaky } from './boardman/githubWebhookSync';

dotenv.config();

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console({ format: winston.format.simple() })]
});

// Boardman worker contract: fail fast when required integration env vars
// are missing so we never start in a partially configured state.
const REQUIRED_BOARDMAN_ENV_VARS = [
  'GITHUB_APP_ID',
  'GITHUB_APP_PRIVATE_KEY',
  'GITHUB_WEBHOOK_SECRET',
  'GITHUB_INSTALLATION_ID',
  'GITHUB_ORG',
  'PLAKY_API_KEY',
  'PLAKY_BASE_URL',
  'PLAKY_WORKSPACE_ID',
  'PLAKY_BOARD_ID',
  'PLAKY_ITEM_GROUP_ID',
  'PLAKY_FIELD_EXTERNAL_KEY_ID',
  'PLAKY_FIELD_GITHUB_URL_ID',
  'PLAKY_FIELD_REPO_ID',
  'PLAKY_FIELD_STATUS_ID',
  'PLAKY_FIELD_PR_URL_ID',
  'PLAKY_FIELD_MERGE_STATE_ID',
  'PLAKY_STATUS_OPEN_VALUE',
  'PLAKY_STATUS_CLOSED_VALUE',
  'PLAKY_MERGE_STATE_OPEN_VALUE',
  'PLAKY_MERGE_STATE_MERGED_VALUE',
  'PLAKY_MERGE_STATE_CLOSED_VALUE',
  'PLAKY_MERGE_STATE_DRAFT_VALUE',
  'ROUTE_SECRET'
] as const;

function isPlaceholderValue(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    normalized.startsWith('your-') ||
    normalized === 'change-me' ||
    normalized === 'replace-me'
  );
}

function validateBoardmanEnvOrExit(): void {
  const missing = REQUIRED_BOARDMAN_ENV_VARS.filter((envVar) => {
    const value = process.env[envVar];
    if (!value || value.trim() === '') return true;
    return isPlaceholderValue(value);
  });

  if (missing.length === 0) return;

  logger.error('Missing required Boardman worker environment variables', {
    missing,
    hint: 'Populate .env/.env-k8s and mounted secrets before starting worker.'
  });
  process.exit(1);
}

/**
 * Example event handlers
 * These are what actually process the webhook/sync events
 */

/**
 * Handle webhook processing
 * This is where you'd call your business logic:
 * - Validate data against your DB
 * - Trigger API calls to external services
 * - Update your database
 * - Send notifications
 */
async function handleWebhookEvent(event: Record<string, any>, headers: Record<string, string>): Promise<void> {
  const eventId = event.event_id;
  const correlationId = event.correlation_id;
  const provider = String(event.provider || '').toLowerCase();

  logger.info('Processing webhook event', {
    event_id: eventId,
    correlation_id: correlationId,
    provider: provider,
    event_type: event.provider_event_type
  });

  // Route on provider and execute the appropriate business logic.
  // Each branch should throw on transient failures so the consumer's
  // retry loop (with exponential back-off) is exercised before the
  // message is sent to the DLQ.
  switch (provider) {
    case 'github':
      {
        const syncResult = await syncGithubWebhookToPlaky(event);
        if (syncResult.skipped) {
          logger.info('Skipped GitHub webhook event', {
            event_id: eventId,
            correlation_id: correlationId,
            reason: syncResult.reason,
            action: syncResult.action,
            linked_issue_keys: syncResult.linkedIssueKeys
          });
          break;
        }

        logger.info('GitHub Boardman sync completed', {
          event_id: eventId,
          correlation_id: correlationId,
          plaky_item_id: syncResult.plakyItemId,
          created: syncResult.created,
          external_key: syncResult.externalKey,
          action: syncResult.action,
          linked_issue_keys: syncResult.linkedIssueKeys
        });
      }
      break;
    case 'notion':
      logger.info('Notion webhook handler not implemented yet; event acknowledged for future support', {
        event_id: eventId,
        correlation_id: correlationId
      });
      break;
    case 'trello':
      logger.info('Trello webhook handler not implemented yet; event acknowledged for future support', {
        event_id: eventId,
        correlation_id: correlationId
      });
      break;
    default:
      logger.warn('No handler registered for provider', { provider, event_id: eventId });
  }

  logger.info('Webhook event processed successfully', {
    event_id: eventId,
    correlation_id: correlationId
  });
}

/**
 * Handle sync job processing
 */
async function handleSyncEvent(event: Record<string, any>, headers: Record<string, string>): Promise<void> {
  const jobId = event.job_id;
  const correlationId = event.correlation_id;
  const integrationId = event.integration_id;

  logger.info('Processing sync job', {
    job_id: jobId,
    correlation_id: correlationId,
    integration_id: integrationId
  });

  // TODO: implement sync business logic per integration type.
  // Throw on transient failures so the consumer retry loop is exercised.
  // Examples:
  // - Fetch data from external system (Salesforce, HubSpot)
  // - Merge with internal state
  // - Write results to database
  // - Trigger webhooks to notify clients

  logger.info('Sync job processed successfully', {
    job_id: jobId,
    correlation_id: correlationId
  });
}

/**
 * Main worker process
 */
async function main() {
  validateBoardmanEnvOrExit();

  const workerPort = parseInt(process.env.WORKER_PORT || '5007', 10);
  const app = express();
  app.use(express.json());

  // Create consumer instances for different topics
  // Using consumer groups ensures load balancing across multiple worker instances
  const webhookConsumer = new KafkaConsumerService(
    'webhook-processors',
    10 // max 10 concurrent webhook processes
  );
  const syncConsumer = new KafkaConsumerService(
    'sync-processors',
    5 // max 5 concurrent sync processes
  );

  // Register handlers
  webhookConsumer.register('integration.webhook.received', handleWebhookEvent);
  syncConsumer.register('integration.sync.requested', handleSyncEvent);

  // Initialize health checker
  const healthCheckService = new HealthCheckService(kafkaProducerService);
  healthCheckService.registerConsumer('webhook-processors', webhookConsumer);
  healthCheckService.registerConsumer('sync-processors', syncConsumer);

  try {
    logger.info('Initializing worker...');

    // Initialize consumers
    await webhookConsumer.init(['integration.webhook.received']);
    await syncConsumer.init(['integration.sync.requested']);

    logger.info('Consumers initialized, starting to process messages...');

    // Wire the DLQ producer so failed messages are published rather than dropped.
    webhookConsumer.setDLQProducer(kafkaProducerService);
    syncConsumer.setDLQProducer(kafkaProducerService);

    // Fire-and-detach: consumer.start() runs an infinite KafkaJS polling loop
    // and never resolves, so we must NOT await it here.  Errors are fatal —
    // crash the process so the container orchestrator can restart it.
    void webhookConsumer.start().catch((err: unknown) => {
      logger.error('webhookConsumer crashed', { error: err instanceof Error ? err.message : err });
      process.exit(1);
    });
    void syncConsumer.start().catch((err: unknown) => {
      logger.error('syncConsumer crashed', { error: err instanceof Error ? err.message : err });
      process.exit(1);
    });

    // Setup Express endpoints for monitoring
    app.get('/health', async (req: Request, res: Response) => {
      try {
        const health = await healthCheckService.check();
        const statusCode = health.status === 'healthy' ? 200 : 503;
        res.status(statusCode).json(health);
      } catch (error) {
        logger.error('Health check failed:', error);
        res.status(503).json({
          status: 'unhealthy',
          timestamp: new Date().toISOString(),
          service: 'worker-service',
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    });

    app.get('/metrics', async (req: Request, res: Response) => {
      try {
        const metrics = await MetricsService.getMetrics();
        res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
        res.send(metrics);
      } catch (error) {
        logger.error('Failed to serve metrics:', error);
        res.status(500).json({ error: 'Failed to generate metrics' });
      }
    });

    app.get('/status', (req: Request, res: Response) => {
      res.json({
        status: 'running',
        timestamp: new Date().toISOString(),
        consumers: {
          webhooks: webhookConsumer.getStatus(),
          sync: syncConsumer.getStatus()
        }
      });
    });

    const server = app.listen(workerPort, () => {
      logger.info(`Worker service listening on port ${workerPort}`);
      logger.info(`Metrics available at http://localhost:${workerPort}/metrics`);
      logger.info(`Health check at http://localhost:${workerPort}/health`);
    });

    // Graceful shutdown: stop consumers first so no new messages are
    // accepted, then drain the HTTP server, then exit.
    const shutdown = async () => {
      logger.info('Shutting down worker service...');

      // 1. Stop Kafka consumers before closing the HTTP server so that
      //    in-flight messages finish processing and are not re-queued.
      await webhookConsumer.stop();
      await syncConsumer.stop();

      // 2. Stop accepting new HTTP requests.
      await new Promise<void>(resolve => server.close(() => resolve()));

      // 3. Clean exit.
      process.exit(0);
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  } catch (error) {
    logger.error('Failed to start worker:', error);
    process.exit(1);
  }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error: Error) => {
  logger.error('Uncaught exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason: any) => {
  logger.error('Unhandled rejection:', reason);
  process.exit(1);
});

main();
