import { Kafka, Producer, ProducerRecord, logLevel } from 'kafkajs';
import { Counter, Histogram } from 'prom-client';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console({ format: winston.format.simple() })]
});

/**
 * Prometheus metrics for producer
 * - messages_produced_total: counts successful publishes (by topic)
 * - producer_errors_total: counts publish failures (by topic, error_type)
 * - publish_latency_seconds: histogram of publish latency (p50, p95, p99)
 */
export const producerMetrics = {
  messagesProducedTotal: new Counter({
    name: 'messages_produced_total',
    help: 'Total number of messages published to Kafka',
    labelNames: ['topic']
  }),
  producerErrorsTotal: new Counter({
    name: 'producer_errors_total',
    help: 'Total number of producer errors',
    labelNames: ['topic', 'error_type']
  }),
  publishLatencySeconds: new Histogram({
    name: 'publish_latency_seconds',
    help: 'Latency of publishing a message to Kafka',
    labelNames: ['topic'],
    buckets: [0.001, 0.01, 0.05, 0.1, 0.5, 1, 5]
  })
};

/**
 * KafkaProducerService
 * Wraps KafkaJS producer with metrics, error handling, and retry logic.
 * 
 * Usage:
 *   const service = new KafkaProducerService();
 *   await service.init();
 *   await service.publishEvent('integration.webhook.received', {
 *     integration_id: 'stripe_123',
 *     event_id: 'evt_456',
 *     payload: {...}
 *   });
 */
export class KafkaProducerService {
  private kafka: Kafka;
  private producer: Producer | null = null;
  private isConnected = false;

  constructor() {
    this.kafka = new Kafka({
      clientId: 'external-bridge-producer',
      brokers: (process.env.KAFKA_BROKERS || 'localhost:9092').split(','),
      logLevel: logLevel.ERROR,
      retry: {
        initialRetryTime: 100,
        retries: 8,
        maxRetryTime: 30000
      },
      // Connection timeout for broker discovery
      connectionTimeout: 10000,
      requestTimeout: 30000
    });
  }

  /**
   * Initialize producer and connect to Kafka broker
   */
  async init(): Promise<void> {
    try {
      this.producer = this.kafka.producer({
        allowAutoTopicCreation: true,
        maxInFlightRequests: 5
      });

      await this.producer.connect();
      this.isConnected = true;
      logger.info('Kafka producer initialized and connected');
    } catch (error) {
      logger.error('Failed to initialize Kafka producer:', error);
      throw error;
    }
  }

  /**
   * Publish an event to a Kafka topic
   * 
   * @param topic - Kafka topic name
   * @param event - Event payload (must have integration_id for partitioning)
   * @param integrationId - Integration ID for partitioning key (ensures events for same integration go to same partition)
   * 
   * Explanation:
   * - We use integration_id as the partition key to guarantee ordering per integration
   * - Kafka will hash the key and always send it to the same partition
   * - The producer sends in the background; we track metrics but don't block the API
   */
  async publishEvent(
    topic: string,
    event: Record<string, any>,
    integrationId: string
  ): Promise<void> {
    if (!this.producer || !this.isConnected) {
      throw new Error('Producer not initialized');
    }

    const startTime = Date.now();
    const record: ProducerRecord = {
      topic,
      messages: [
        {
          key: integrationId, // Partition key: ensures all events for same integration go to same partition
          value: JSON.stringify(event),
          headers: {
            'event_id': event.event_id || 'unknown',
            'correlation_id': event.correlation_id || 'unknown',
            'timestamp': new Date().toISOString()
          }
        }
      ]
    };

    try {
      await this.producer.send(record);
      const latency = (Date.now() - startTime) / 1000;
      
      // Record success metrics
      producerMetrics.messagesProducedTotal.labels(topic).inc();
      producerMetrics.publishLatencySeconds.labels(topic).observe(latency);

      logger.info(`Event published to ${topic}`, {
        event_id: event.event_id,
        correlation_id: event.correlation_id,
        integration_id: integrationId,
        latency_seconds: latency
      });
    } catch (error) {
      const errorType = error instanceof Error ? error.constructor.name : 'UnknownError';
      producerMetrics.producerErrorsTotal.labels(topic, errorType).inc();
      
      logger.error(`Failed to publish event to ${topic}:`, {
        event_id: event.event_id,
        correlation_id: event.correlation_id,
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Gracefully disconnect producer
   */
  async disconnect(): Promise<void> {
    if (this.producer && this.isConnected) {
      await this.producer.disconnect();
      this.isConnected = false;
      logger.info('Kafka producer disconnected');
    }
  }

  /**
   * Check if producer is connected
   */
  isProducerConnected(): boolean {
    return this.isConnected;
  }
}

export default new KafkaProducerService();
