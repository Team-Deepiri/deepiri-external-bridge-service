import express, { Express, Request, Response, ErrorRequestHandler } from 'express';
// MongoDB removed - using PostgreSQL via Prisma if needed
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import winston from 'winston';
import cookieParser from 'cookie-parser';
import { randomUUID } from 'crypto';
import routes from './index';

dotenv.config();

const app: Express = express();
const PORT: number = parseInt(process.env.PORT || '5006', 10);

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console({ format: winston.format.simple() })]
});

app.use(helmet());
app.use(cors());
app.use(cookieParser());
app.use(express.json());

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

app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'healthy', service: 'external-bridge-service', timestamp: new Date().toISOString() });
});

app.use('/', routes);

const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  logger.error('External Bridge Service error', {
    requestId: (req as any).requestId || 'unknown',
    method: req.method,
    path: req.originalUrl,
    errorMessage: err instanceof Error ? err.message : 'Unknown error',
    stack: err instanceof Error ? err.stack : undefined,
  });

  res.status(500).json({
    success: false,
    error: 'Internal server error',
    requestId: (req as any).requestId || 'unknown',
    timestamp: new Date().toISOString(),
  });
};
app.use(errorHandler);

app.listen(PORT, () => {
  logger.info(`External Bridge Service running on port ${PORT}`);
});

export default app;

