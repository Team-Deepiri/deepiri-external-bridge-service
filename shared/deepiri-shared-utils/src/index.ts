import winston from 'winston';

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console({ format: winston.format.simple() })]
});

export const createLogger = (name: string) => logger;

export const secureLog = (level: 'info' | 'warn' | 'error', message: string, meta?: any) => {
  (logger as any)[level]?.(message, meta);
};
