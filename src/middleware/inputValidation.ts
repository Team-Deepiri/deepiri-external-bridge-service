/* Input validation middleware - length limits and consistent validation patterns */

import { Request, Response, NextFunction } from 'express';
import { body, validationResult, ValidationChain } from 'express-validator';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console({ format: winston.format.simple() })],
});

const MAX_BODY_KEYS = 50;
const MAX_STRING_VALUE_LENGTH = 10000;

export const validate = (validations: ValidationChain[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    await Promise.all(validations.map((v) => v.run(req)));
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const requestId = (req as any).requestId || 'unknown';
      logger.warn('Validation failed', {
        requestId,
        path: req.path,
        method: req.method,
        errors: errors.array(),
      });
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        requestId,
        timestamp: new Date().toISOString(),
        errors: errors.array().map((err: any) => ({
          field: err.path || err.param || err.type || 'unknown',
          message: err.msg,
          value: err.value,
        })),
      });
    }
    next();
  };
};

export const generateBodyValidations = () => [
  body()
    .isObject()
    .withMessage('Body must be a JSON object')
    .custom((val: Record<string, unknown>) => {
      const keys = Object.keys(val || {});
      if (keys.length > MAX_BODY_KEYS) {
        throw new Error(`Body must have at most ${MAX_BODY_KEYS} keys`);
      }
      for (const k of keys) {
        if (k.length > 500) throw new Error('Body key names must be at most 500 characters');
        const v = (val as Record<string, unknown>)[k];
        if (typeof v === 'string' && v.length > MAX_STRING_VALUE_LENGTH) {
          throw new Error(`Body string values must be at most ${MAX_STRING_VALUE_LENGTH} characters`);
        }
      }
      return true;
    }),
];

/** Run body validation only when request has a JSON body. */
export const validateBodyIfPresent = () => {
  const validations = generateBodyValidations();
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
      return validate(validations)(req, res, next);
    }
    next();
  };
};

const isApplicationHeader = (headerName: string): boolean => {
    const normalizedHeaderName = headerName.toLowerCase();
    return normalizedHeaderName === 'authorization' || normalizedHeaderName.startsWith('x-');
};

const sanitizeValue = (value: unknown): unknown => {
    if (typeof value === 'string') {
        return value.trim();
    }

    if (Array.isArray(value)) {
        return value.map((item) => sanitizeValue(item));
    }

    if (value && typeof value === 'object') {
        const sanitizedRecord: Record<string, unknown> = {};
        for (const [key, nestedValue] of Object.entries(value as Record<string, unknown>)) {
            sanitizedRecord[key] = sanitizeValue(nestedValue);
        }
        return sanitizedRecord;
    }

    return value;
};

type RequestValidator = (req: Request) => string | null;

interface RequestValidationOptions {
    allowedBodyFields?: string[];
    allowedQueryFields?: string[];
    allowedHeaderFields?: string[];
    sanitizeBody?: boolean;
    validators?: RequestValidator[];
}

interface ValidationErrorItem {
    field: string;
    message: string;
    value?: unknown;
}

export const validateRequest = (options: RequestValidationOptions = {}) => {
    return (req: Request, res: Response, next: NextFunction): void => {
        const requestId = (req as any).requestId || 'unknown';
        const errors: ValidationErrorItem[] = [];

        if (options.allowedBodyFields && req.body && typeof req.body === 'object' && !Array.isArray(req.body)) {
            const unknownBodyFields = Object.keys(req.body).filter(
                (field) => !options.allowedBodyFields?.includes(field)
            );

            if (unknownBodyFields.length > 0) {
                errors.push({
                    field: 'body',
                    message: `Unknown body fields provided: ${unknownBodyFields.join(', ')}`,
                    value: unknownBodyFields,
                });
            }
        }

        if (options.allowedQueryFields && req.query && typeof req.query === 'object') {
            const unknownQueryFields = Object.keys(req.query).filter(
                (field) => !options.allowedQueryFields?.includes(field)
            );

            if (unknownQueryFields.length > 0) {
                errors.push({
                    field: 'query',
                    message: `Unknown query fields provided: ${unknownQueryFields.join(', ')}`,
                    value: unknownQueryFields,
                });
            }
        }

        if (options.allowedHeaderFields && req.headers && typeof req.headers === 'object') {
            const normalizedAllowedHeaderFields = options.allowedHeaderFields.map((field) => field.toLowerCase());
            const unknownHeaderFields = Object.keys(req.headers).filter(
                (field) => isApplicationHeader(field) && !normalizedAllowedHeaderFields.includes(field.toLowerCase())
            );

            if (unknownHeaderFields.length > 0) {
                errors.push({
                    field: 'headers',
                    message: `Unknown headers provided: ${unknownHeaderFields.join(', ')}`,
                    value: unknownHeaderFields,
                });
            }
        }

        if (options.validators) {
            for (const validator of options.validators) {
                const validationMessage = validator(req);
                if (validationMessage) {
                    errors.push({
                        field: 'request',
                        message: validationMessage,
                    });
                }
            }
        }

        if (errors.length > 0) {
            logger.warn('Validation failed', {
                requestId,
                path: req.path,
                method: req.method,
                errors,
            });

            res.status(400).json({
                success: false,
                message: 'Validation failed',
                requestId,
                timestamp: new Date().toISOString(),
                errors,
            });
            return;
        }

        if (req.query && typeof req.query === 'object') {
            req.query = sanitizeValue(req.query) as Request['query'];
        }

        if (req.params && typeof req.params === 'object') {
            req.params = sanitizeValue(req.params) as Request['params'];
        }

        if (options.sanitizeBody !== false && req.body && typeof req.body === 'object') {
            req.body = sanitizeValue(req.body) as Request['body'];
        }

        next();
    };
};

const ALLOWED_PROVIDERS = new Set(['github', 'notion', 'trello', 'google']);

export const providerValidator: RequestValidator = (req: Request): string | null => {
    const provider = req.params.provider;
    if (!provider || typeof provider !== 'string') {
        return 'provider route parameter is required';
    }

    const normalizedProvider = provider.trim().toLowerCase();
    if (!ALLOWED_PROVIDERS.has(normalizedProvider)) {
        return `Unsupported provider: ${provider}`;
    }

    req.params.provider = normalizedProvider;
    return null;
};

export const oauthCallbackQueryValidator: RequestValidator = (req: Request): string | null => {
    const code = req.query.code;
    const state = req.query.state;
    const oauthError = req.query.error;

    if (oauthError !== undefined && typeof oauthError !== 'string') {
        return 'OAuth error must be a string when provided';
    }

    if (code !== undefined && typeof code !== 'string') {
        return 'Authorization code must be a string when provided';
    }

    if (state !== undefined && typeof state !== 'string') {
        return 'OAuth state must be a string when provided';
    }

    if (!oauthError && !code) {
        return 'Either query.error or query.code is required';
    }

    return null;
};

export const webhookPayloadValidator: RequestValidator = (req: Request): string | null => {
    if (req.body === undefined || req.body === null) {
        return 'Webhook payload is required';
    }

    if (typeof req.body !== 'object' || Array.isArray(req.body)) {
        return 'Webhook payload must be a JSON object';
    }

    return null;
};
