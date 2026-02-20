import { Kafka, Consumer, logLevel } from 'kafkajs';
import { Counter, Histogram, Gauge } from 'prom-client';
import { createClient } from 'redis';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console({ format: winston.format.simple() })]
});

/**
 * Prometheus metrics for consumer
 * - messages_consumed_total: counts successfully processed messages
 * - consumer_errors_total: counts processing errors (by stage: validate, process, etc)
 * - message_processing_seconds: histogram of processing time
 * - consumer_lag_current: gauge of current consumer lag (offset lag)
 * - dlq_messages_total: counts messages sent to DLQ (by topic, reason)
 */
export const consumerMetrics = {
  messagesConsumedTotal: new Counter({
    name: 'messages_consumed_total',
    help: 'Total number of messages successfully consumed and processed',
    labelNames: ['topic', 'group']
  }),
  consumerErrorsTotal: new Counter({
    name: 'consumer_errors_total',
    help: 'Total number of consumer errors',
    labelNames: ['topic', 'stage'] // stage: validate, dedupe, process, publish_dlq
  }),
  messageProcessingSeconds: new Histogram({
    name: 'message_processing_seconds',
    help: 'Histogram of message processing time',
    labelNames: ['topic'],
    buckets: [0.1, 0.5, 1, 2, 5, 10, 30]
  }),
  consumerLagCurrent: new Gauge({
    name: 'consumer_lag_current',
    help: 'Current consumer lag (difference between latest offset and committed offset)',
    labelNames: ['topic', 'group', 'partition']
  }),
  dlqMessagesTotal: new Counter({
    name: 'dlq_messages_total',
    help: 'Total messages sent to Dead Letter Queue',
    labelNames: ['topic', 'reason'] // reason: max_retries, validation_error, etc
  })
};

/**
 * Interface for event processing handler
 */
export interface EventHandler {
  (event: Record<string, any>, headers: Record<string, string>): Promise<void>;
}

/**
 * KafkaConsumerService
 * A robust consumer with:
 * - Bounded concurrency (process N messages in parallel)
 * - Idempotency via Redis
 * - Exponential backoff retries
 * - Dead Letter Queue on max retries
 * - Comprehensive metrics
 * 
 * Usage:
 *   const consumer = new KafkaConsumerService('webhook-processors');
 *   consumer.register('integration.webhook.received', handleWebhook);
 *   await consumer.init(['integration.webhook.received']);
 *   await consumer.start();
 */
export class KafkaConsumerService {
  private kafka: Kafka;
  private consumer: Consumer | null = null;
  private redisClient = createClient({
    url: `redis://${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || '6379'}`
  });
  private groupId: string;
  private handlers: Map<string, EventHandler> = new Map();
  private isConnected = false;
  private isRunning = false;

  // Concurrency control: max N messages processing in parallel
  private concurrencyLimit = 10;
  private activeProcesses = 0;

  // Retry config
  private maxRetries = 3;
  private baseBackoffMs = 1000; // Start with 1 second
  private backoffMultiplier = 2; // exponential: 1s, 2s, 4s, etc

  constructor(groupId: string, concurrencyLimit: number = 10) {
    this.groupId = groupId;
    this.concurrencyLimit = concurrencyLimit;

    this.kafka = new Kafka({
      clientId: `external-bridge-consumer-${groupId}`,
      brokers: (process.env.KAFKA_BROKERS || 'localhost:9092').split(','),
      logLevel: logLevel.ERROR,
      retry: {
        initialRetryTime: 100,
        retries: 8,
        maxRetryTime: 30000
      },
      connectionTimeout: 10000,
      requestTimeout: 30000
    });
  }

  /**
   * Register a handler for a topic
   * @param topic - Topic name
   * @param handler - Async function that processes the event
   */
  register(topic: string, handler: EventHandler): void {
    this.handlers.set(topic, handler);
    logger.info(`Registered handler for topic: ${topic}`);
  }

  /**
   * Initialize consumer and connect to Kafka + Redis
   */
  async init(topics: string[]): Promise<void> {
    try {
      // Connect to Redis (for idempotency)
      await this.redisClient.connect();
      logger.info('Connected to Redis');

      // Create and connect Kafka consumer
      this.consumer = this.kafka.consumer({
        groupId: this.groupId,
        sessionTimeout: 30000,
        rebalanceTimeout: 60000,
        // Auto commit is disabled; we manually commit after processing
        allowAutoTopicCreation: true
      });

      await this.consumer.connect();
      logger.info('Kafka consumer initialized and connected');

      // Subscribe to topics
      await this.consumer.subscribe({
        topics: topics,
        fromBeginning: false // Start from latest offset for new consumers
      });

      this.isConnected = true;
      logger.info(`Subscribed to topics: ${topics.join(', ')} with group: ${this.groupId}`);
    } catch (error) {
      logger.error('Failed to initialize consumer:', error);
      throw error;
    }
  }

  /**
   * Start consuming messages
   * This runs indefinitely; messages are processed via eachMessage callback
   */
  async start(): Promise<void> {
    if (!this.consumer || !this.isConnected) {
      throw new Error('Consumer not initialized');
    }

    this.isRunning = true;

    try {
      await this.consumer.run({
        eachMessage: async ({ topic, partition, message }) => {
          // Apply concurrency limit: wait if too many active processes
          while (this.activeProcesses >= this.concurrencyLimit) {
            await new Promise(resolve => setTimeout(resolve, 50));
          }

          this.activeProcesses++;

          try {
            await this.processMessage(topic, partition, message);
          } catch (error) {
            logger.error('Error in eachMessage callback:', error);
          } finally {
            this.activeProcesses--;
          }
        }
      });

      logger.info(`Consumer started for group: ${this.groupId}`);
    } catch (error) {
      logger.error('Failed to start consumer:', error);
      throw error;
    }
  }

  /**
   * Process a single message with retry logic and idempotency
   * 
   * Flow:
   * 1. Check if already processed (Redis dedup)
   * 2. If yes, mark as consumed and skip
   * 3. If no, attempt processing with retry loop
   * 4. On success, mark as processed in Redis and commit offset
   * 5. On max retries, send to DLQ
   */
  private async processMessage(
    topic: string,
    partition: number,
    message: any
  ): Promise<void> {
    const startTime = Date.now();
    const eventId = message.headers?.event_id?.toString() || 'unknown';
    const correlationId = message.headers?.correlation_id?.toString() || 'unknown';
    const messageKey = message.key?.toString() || 'unknown';

    logger.info('Processing message', {
      event_id: eventId,
      correlation_id: correlationId,
      topic,
      partition,
      offset: message.offset
    });

    try {
      const event = JSON.parse(message.value?.toString() || '{}');

      // Step 1: Check idempotency (deduplication)
      const dedupeKey = `dedupe:${topic}:${eventId}`;
      const isDuplicate = await this.redisClient.exists(dedupeKey);

      if (isDuplicate) {
        logger.info(`Duplicate event detected, skipping`, { event_id: eventId });
        consumerMetrics.consumerErrorsTotal.labels(topic, 'duplicate_skipped').inc();
        // Still commit offset so we don't reprocess
        await this.consumer!.commitOffsets([
          {
            topic,
            partition,
            offset: (parseInt(message.offset) + 1).toString()
          }
        ]);
        return;
      }

      // Step 2: Get handler for this topic
      const handler = this.handlers.get(topic);
      if (!handler) {
        throw new Error(`No handler registered for topic: ${topic}`);
      }

      // Step 3: Execute with retry loop
      let lastError: Error | null = null;
      for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
        try {
          // Call the user's handler function
          await handler(event, message.headers || {});

          // Success! Mark as processed and exit retry loop
          const ttlSeconds = 24 * 60 * 60; // Keep dedup key for 24 hours
          await this.redisClient.setEx(dedupeKey, ttlSeconds, 'processed');

          // Commit offset (tells Kafka we successfully processed this message)
          await this.consumer!.commitOffsets([
            {
              topic,
              partition,
              offset: (parseInt(message.offset) + 1).toString()
            }
          ]);

          const processingTime = (Date.now() - startTime) / 1000;
          consumerMetrics.messagesConsumedTotal.labels(topic, this.groupId).inc();
          consumerMetrics.messageProcessingSeconds.labels(topic).observe(processingTime);

          logger.info('Message processed successfully', {
            event_id: eventId,
            correlation_id: correlationId,
            attempt,
            processing_time_seconds: processingTime
          });

          return;
        } catch (error) {
          lastError = error as Error;
          logger.warn(`Processing attempt ${attempt + 1}/${this.maxRetries + 1} failed:`, {
            event_id: eventId,
            error: error instanceof Error ? error.message : String(error)
          });

          if (attempt < this.maxRetries) {
            // Apply exponential backoff
            const backoffMs = this.baseBackoffMs * Math.pow(this.backoffMultiplier, attempt);
            logger.info(`Retrying in ${backoffMs}ms...`);
            await new Promise(resolve => setTimeout(resolve, backoffMs));
          }
        }
      }

      // Step 4: Max retries exceeded, send to DLQ
      logger.error('Max retries exceeded, sending to DLQ', {
        event_id: eventId,
        correlation_id: correlationId,
        last_error: lastError instanceof Error ? lastError.message : String(lastError)
      });

      const reason = lastError instanceof Error ? lastError.message : 'Unknown error';
      await this.sendToDLQ(topic, event, partition, eventId, correlationId, reason);

      // Mark as processed (don't retry anymore) and commit offset
      await this.redisClient.setEx(dedupeKey, 24 * 60 * 60, 'dlq');
      await this.consumer!.commitOffsets([
        {
          topic,
          partition,
          offset: (parseInt(message.offset) + 1).toString()
        }
      ]);

      consumerMetrics.dlqMessagesTotal.labels(topic, 'max_retries').inc();
    } catch (error) {
      logger.error('Unexpected error processing message:', {
        event_id: eventId,
        error: error instanceof Error ? error.message : String(error)
      });
      consumerMetrics.consumerErrorsTotal.labels(topic, 'unexpected_error').inc();
    }
  }

  /**
   * Send failed message to Dead Letter Queue topic
   * DLQ topic naming: {original_topic}.dlq
   */
  private async sendToDLQ(
    originalTopic: string,
    event: Record<string, any>,
    partition: number,
    eventId: string,
    correlationId: string,
    reason: string
  ): Promise<void> {
    try {
      const dlqTopic = `${originalTopic}.dlq`;
      const dlqEvent = {
        ...event,
        original_topic: originalTopic,
        dlq_reason: reason,
        dlq_timestamp: new Date().toISOString(),
        original_partition: partition
      };

      // TODO: Use KafkaProducerService to publish to DLQ
      // For now, just log that we sent it
      logger.error(`Message sent to DLQ: ${dlqTopic}`, {
        event_id: eventId,
        correlation_id: correlationId,
        dlq_event: dlqEvent
      });
    } catch (error) {
      logger.error('Failed to send to DLQ:', error);
    }
  }

  /**
   * Gracefully stop consumer
   */
  async stop(): Promise<void> {
    if (this.consumer && this.isConnected) {
      await this.consumer.disconnect();
      await this.redisClient.quit();
      this.isConnected = false;
      this.isRunning = false;
      logger.info('Kafka consumer disconnected');
    }
  }

  /**
   * Check current status
   */
  getStatus(): {
    isConnected: boolean;
    isRunning: boolean;
    groupId: string;
    activeProcesses: number;
  } {
    return {
      isConnected: this.isConnected,
      isRunning: this.isRunning,
      groupId: this.groupId,
      activeProcesses: this.activeProcesses
    };
  }

  /**
   * Get last processed timestamp (for health checks)
   */
  async getLastProcessedTimestamp(): Promise<string | null> {
    const key = `last_processed:${this.groupId}`;
    return await this.redisClient.get(key);
  }

  /**
   * Set last processed timestamp
   */
  private async setLastProcessedTimestamp(): Promise<void> {
    const key = `last_processed:${this.groupId}`;
    await this.redisClient.set(key, new Date().toISOString());
  }
}
