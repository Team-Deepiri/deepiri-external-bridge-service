import winston from 'winston';

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console({ format: winston.format.simple() })]
});

// Keep compatibility with code expecting createLogger(name)
export const createLogger = (name: string) => logger;

// Minimal secureLog helper used by services
export const secureLog = (level: 'info' | 'warn' | 'error', message: string, meta?: any) => {
  (logger as any)[level]?.(message, meta);
};
