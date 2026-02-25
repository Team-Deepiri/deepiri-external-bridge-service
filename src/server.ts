import express, { Express, Request, Response, ErrorRequestHandler } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import winston from 'winston';
import cookieParser from 'cookie-parser';
import routes from './index';
import kafkaProducerService from './kafka/producer';
import { HealthCheckService, MetricsService } from './kafka/health';
import { validateBodyIfPresent } from './middleware/inputValidation';

dotenv.config();

const app: Express = express();
const PORT: number = parseInt(process.env.PORT || '5006', 10);

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console({ format: winston.format.simple() })]
});

/**
 * Initialize Kafka and Health Services
 * These are called during server startup
 */
let healthCheckService: HealthCheckService;

const initializeServices = async () => {
  try {
    // Initialize Kafka producer (non-blocking publish for webhooks)
    await kafkaProducerService.init();
    logger.info('Kafka producer initialized');

    // Initialize health checker
    healthCheckService = new HealthCheckService(kafkaProducerService);
    logger.info('Health check service initialized');

    return true;
  } catch (error) {
    logger.error('Failed to initialize services:', error);
    // Don't exit; allow graceful degradation
    return false;
  }
};

app.use(helmet());
app.use(cors());
app.use(cookieParser());
app.use(express.json({ limit: '100kb' }));
app.use(validateBodyIfPresent());

/**
 * GET /metrics
 * Prometheus metrics endpoint
 * curl http://localhost:5006/metrics
 */
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

/**
 * GET /health
 * Health check endpoint with Kafka and Redis status
 * Kubernetes liveness/readiness probes can hit this
 * curl http://localhost:5006/health
 */
app.get('/health', async (req: Request, res: Response) => {
  try {
    if (!healthCheckService) {
      return res.status(503).json({ error: 'Health check service not initialized' });
    }

    const health = await healthCheckService.check();
    const statusCode = health.status === 'healthy' ? 200 : 503;
    res.status(statusCode).json(health);
  } catch (error) {
    logger.error('Health check failed:', error);
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      service: 'external-bridge-service',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// PostgreSQL connection via Prisma (if needed for webhook/integration storage)
// For now, external bridge primarily handles webhooks and API integrations

app.use('/', routes);

const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  logger.error('External Bridge Service error:', err);
  res.status(500).json({ error: 'Internal server error' });
};
app.use(errorHandler);

/**
 * Start server with async initialization
 */
const startServer = async () => {
  try {
    // Initialize Kafka and other services; hard-fail if they are unavailable
    const servicesReady = await initializeServices();
    if (!servicesReady) {
      logger.error('Critical services failed to initialize. Refusing to start server.');
      process.exit(1);
    }

    const server = app.listen(PORT, () => {
      logger.info(`External Bridge Service running on port ${PORT}`);
      logger.info(`Metrics available at http://localhost:${PORT}/metrics`);
      logger.info(`Health check at http://localhost:${PORT}/health`);
    });

    // Graceful shutdown
    process.on('SIGTERM', async () => {
      logger.info('SIGTERM signal received: closing HTTP server');
      server.close(async () => {
        logger.info('HTTP server closed');
        await kafkaProducerService.disconnect();
        process.exit(0);
      });
    });

    process.on('SIGINT', async () => {
      logger.info('SIGINT signal received: closing HTTP server');
      server.close(async () => {
        logger.info('HTTP server closed');
        await kafkaProducerService.disconnect();
        process.exit(0);
      });
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
startServer();

export default app;

