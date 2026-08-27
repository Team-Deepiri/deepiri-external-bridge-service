import { register } from 'prom-client';
import { KafkaProducerService } from './producer';
import { KafkaConsumerService } from './consumer';
import { createClient, RedisClientType } from 'redis';
import { createLogger } from '@team-deepiri/shared-utils';

const logger = createLogger('external-bridge-service');

/**
 * HealthCheckService
 * Provides detailed health status including Kafka and Redis connectivity
 * 
 * This is critical for:
 * 1. Kubernetes liveness/readiness probes
 * 2. Load balancer health checks
 * 3. Alerting on dependency failures
 */
export class HealthCheckService {
  private producerService: KafkaProducerService;
  private consumerServices: Map<string, KafkaConsumerService> = new Map();
  private redisClient: RedisClientType;
  private lastHealthCheck: { timestamp: string; status: string } | null = null;

  constructor(producerService: KafkaProducerService) {
    this.producerService = producerService;
    this.redisClient = createClient({
      url: `redis://:${process.env.REDIS_PASSWORD || ''}@${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || '6379'}`
    });
  }

  /**
   * Register a consumer service for health checks
   */
  registerConsumer(groupId: string, service: KafkaConsumerService): void {
    this.consumerServices.set(groupId, service);
  }

  /**
   * Perform health check
   * Returns overall status + detailed component status
   */
  async check(): Promise<HealthCheckResponse> {
    const timestamp = new Date().toISOString();
    const kafkaEnabled = process.env.KAFKA_ENABLED !== 'false';

    try {
      // Check producer with a live connectivity probe (not just a boolean flag).
      // When Kafka is intentionally disabled (cloud profile — no broker exists
      // at all), treat it as not-applicable rather than unhealthy, so the
      // service doesn't report permanently degraded for a dependency it was
      // never meant to have.
      const producerHealthy = kafkaEnabled ? await this.producerService.isProducerConnected() : true;

      // Check Redis
      let redisHealthy = false;
      try {
        if (!this.redisClient.isOpen) {
          await this.redisClient.connect();
        }
        await this.redisClient.ping();
        redisHealthy = true;
      } catch (error) {
        logger.warn('Redis health check failed:', error);
      }

      const consumerHealthStatus: Record<string, any> = {};
      let allConsumersHealthy = true;

      for (const [groupId, consumer] of this.consumerServices) {
        const status = consumer.getStatus();
        const lastProcessed = await consumer.getLastProcessedTimestamp();
        const consumerOk = status.isConnected && status.isRunning;

        if (!consumerOk) allConsumersHealthy = false;

        consumerHealthStatus[groupId] = {
          connected: status.isConnected,
          running: status.isRunning,
          active_processes: status.activeProcesses,
          last_processed_timestamp: lastProcessed || 'never'
        };
      }

      const overallHealthy = producerHealthy && redisHealthy && allConsumersHealthy;

      const response: HealthCheckResponse = {
        status: overallHealthy ? 'healthy' : 'degraded',
        timestamp,
        service: 'external-bridge-service',
        components: {
          kafka_producer: {
            status: producerHealthy ? 'healthy' : 'unhealthy',
            connected: producerHealthy
          },
          redis: {
            status: redisHealthy ? 'healthy' : 'unhealthy',
            connected: redisHealthy
          },
          kafka_consumers: consumerHealthStatus
        }
      };

      this.lastHealthCheck = {
        timestamp,
        status: response.status
      };

      return response;
    } catch (error) {
      logger.error('Health check failed:', error);
      throw error;
    }
  }

  /**
   * Get last health check result (faster than running full check)
   */
  getLastHealthStatus(): { timestamp: string; status: string } | null {
    return this.lastHealthCheck;
  }
}

/**
 * Response type for health check endpoint
 */
export interface HealthCheckResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  service: string;
  components: {
    kafka_producer: {
      status: string;
      connected: boolean;
    };
    redis: {
      status: string;
      connected: boolean;
    };
    kafka_consumers: Record<string, any>;
  };
}

/**
 * MetricsService
 * Exposes Prometheus metrics in text format
 */
export class MetricsService {
  /**
   * Get metrics in Prometheus text format
   * This is called by the GET /metrics endpoint
   */
  static async getMetrics(): Promise<string> {
    try {
      const metrics = await register.metrics();
      return metrics;
    } catch (error) {
      logger.error('Failed to gather metrics:', error);
      throw error;
    }
  }

  /**
   * Get metrics in JSON format (optional, for dashboards)
   */
  static async getMetricsJSON(): Promise<any[]> {
    try {
      const metrics = await register.getMetricsAsJSON();
      return metrics;
    } catch (error) {
      logger.error('Failed to gather metrics as JSON:', error);
      throw error;
    }
  }
}

export default { HealthCheckService, MetricsService };
