import express, { Express, Request, Response, ErrorRequestHandler } from 'express';
// MongoDB removed - using PostgreSQL via Prisma if needed
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { logger, secureLog } from '@deepiri/shared-utils';
import cookieParser from 'cookie-parser';
import { randomUUID } from 'crypto';
import routes from './index';
import kafkaProducerService from './kafka/producer';
import { HealthCheckService, MetricsService } from './kafka/health';
import { validateBodyIfPresent } from './middleware/inputValidation';
import { bodyParserConfig, requestSizeLimiter } from './middleware/requestLimits';

dotenv.config();

const app: Express = express();
const PORT: number = parseInt(process.env.PORT || '5006', 10);

app.use(helmet());
app.use(cors());
app.use(cookieParser());

// Request size limits (Issue 8)
app.use(requestSizeLimiter);
app.use(express.json(bodyParserConfig.json));
app.use(express.urlencoded(bodyParserConfig.urlencoded));
app.use(validateBodyIfPresent());

app.use((req: Request, res: Response, next) => {
  const requestId = req.headers['x-request-id'] as string || randomUUID();
  (req as any).requestId = requestId;
  res.setHeader('x-request-id', requestId);
  next();
});

app.use((req: Request, res: Response, next) => {
  const startTime = Date.now();

  res.on('finish', () => {
    const durationMs = Date.now() - startTime;
    logger.info('HTTP request completed', {
      requestId: (req as any).requestId || 'unknown',
      method: req.method,
      path: req.originalUrl,
      statusCode: res.statusCode,
      durationMs,
      userAgent: req.get('user-agent') || 'unknown',
      ip: req.ip,
    });
  });

  next();
});

// PostgreSQL connection via Prisma (if needed for webhook/integration storage)
// For now, external bridge primarily handles webhooks and API integrations

app.get('/health', async (req: Request, res: Response) => {
  // If Kafka health checker is available, use it; otherwise just respond healthy.
  try {
    const healthCheck = new HealthCheckService(kafkaProducerService);
    const health = await healthCheck.check();
    const statusCode = health.status === 'healthy' ? 200 : 503;
    return void res.status(statusCode).json(health);
  } catch {
    return void res.json({
      status: 'healthy',
      service: 'external-bridge-service',
      timestamp: new Date().toISOString()
    });
  }
});

// Optional: expose Prometheus metrics (if your MetricsService is wired)
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

app.use('/', routes);

const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  secureLog('error', 'External Bridge Service error:', err);
  logger.error('External Bridge Service error', {
    requestId: (req as any).requestId || 'unknown',
    method: req.method,
    path: req.originalUrl,
    errorMessage: err instanceof Error ? err.message : 'Unknown error',
    stack: err instanceof Error ? err.stack : undefined,
  });
  res.status(500).json({ error: 'Internal server error' });
};
app.use(errorHandler);

/**
 * Initialize external services needed for API process.
 * Worker consumers run in a separate process (worker.ts).
 */
const initializeServices = async (): Promise<boolean> => {
  try {
    await kafkaProducerService.init();
    return true;
  } catch (err) {
    logger.error('Kafka producer failed to initialize', {
      error: err instanceof Error ? err.message : String(err)
    });
    return false;
  }
};

/**
 * Start server with async initialization
 */
const startServer = async () => {
  try {
    const servicesReady = await initializeServices();
    if (!servicesReady) {
      logger.error('Critical services failed to initialize. Refusing to start server.');
      process.exit(1);
    }

    const server = app.listen(PORT, () => {
      logger.info(`External Bridge Service running on port ${PORT}`);
      logger.info(`Health check at http://localhost:${PORT}/health`);
      logger.info(`Metrics available at http://localhost:${PORT}/metrics`);
    });

    const shutdown = async (signal: string) => {
      logger.info(`${signal} signal received: closing HTTP server`);
      server.close(async () => {
        logger.info('HTTP server closed');
        try {
          await kafkaProducerService.disconnect();
        } catch (e) {
          logger.warn('Kafka producer disconnect failed', {
            error: e instanceof Error ? e.message : String(e)
          });
        }
        process.exit(0);
      });
    };

    process.on('SIGTERM', () => void shutdown('SIGTERM'));
    process.on('SIGINT', () => void shutdown('SIGINT'));
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

export default app;