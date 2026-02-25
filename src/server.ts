import express, { Express, Request, Response, ErrorRequestHandler } from 'express';
// MongoDB removed - using PostgreSQL via Prisma if needed
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { logger, secureLog } from '@deepiri/shared-utils';
import cookieParser from 'cookie-parser';
import routes from './index';
import { validateBodyIfPresent } from './middleware/inputValidation';
import kafkaProducerService from './kafka/producer';

dotenv.config();

const app: Express = express();
const PORT: number = parseInt(process.env.PORT || '5006', 10);

app.use(helmet());
app.use(cors());
app.use(cookieParser());
app.use(express.json({ limit: '100kb' }));
app.use(validateBodyIfPresent());

// PostgreSQL connection via Prisma (if needed for webhook/integration storage)
// For now, external bridge primarily handles webhooks and API integrations

app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'healthy', service: 'external-bridge-service', timestamp: new Date().toISOString() });
});

app.use('/', routes);

const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  secureLog('error', 'External Bridge Service error:', err);
  res.status(500).json({ error: 'Internal server error' });
};
app.use(errorHandler);

const initializeServices = async (): Promise<boolean> => {
  try {
    // If your producer has connect/init method, call it.
    // If not, skip this and rely on lazy connect in publishEvent.
    if (typeof (kafkaProducerService as any).connect === 'function') {
      await (kafkaProducerService as any).connect();
    }
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
      logger.info(`Metrics available at http://localhost:${PORT}/metrics`);
      logger.info(`Health check at http://localhost:${PORT}/health`);
    });

    const shutdown = async (signal: string) => {
      logger.info(`${signal} signal received: closing HTTP server`);
      server.close(async () => {
        logger.info('HTTP server closed');
        await kafkaProducerService.disconnect();
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

