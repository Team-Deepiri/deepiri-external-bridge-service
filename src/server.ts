import express, { Express, Request, Response, ErrorRequestHandler } from 'express';
// MongoDB removed - using PostgreSQL via Prisma if needed
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import winston from 'winston';
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
app.use(express.json());

// PostgreSQL connection via Prisma (if needed for webhook/integration storage)
// For now, external bridge primarily handles webhooks and API integrations

app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'healthy', service: 'external-bridge-service', timestamp: new Date().toISOString() });
});

app.use('/', routes);

const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  logger.error('External Bridge Service error:', err);
  res.status(500).json({ error: 'Internal server error' });
};
app.use(errorHandler);

app.listen(PORT, () => {
  logger.info(`External Bridge Service running on port ${PORT}`);
});

export default app;

