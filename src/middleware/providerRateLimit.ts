import { Request, Response, NextFunction } from 'express';
import { createRedisClient, logger } from '@team-deepiri/shared-utils';

const redis = createRedisClient();

const RATE_LIMIT = {
    windowMs: parseInt(process.env.PROVIDER_RATE_LIMIT_WINDOW_MS || '60000', 10),
    maxRequests: parseInt(process.env.PROVIDER_RATE_LIMIT_MAX_REQUESTS || '100', 10),
};

interface RateLimitResult {
    allowed: boolean;
    count: number;
    remaining: number;
}

const getClientIdentifier = (req: Request): string => {
    const forwardedFor = req.headers['x-forwarded-for'];
    if (typeof forwardedFor === 'string' && forwardedFor.trim().length > 0) {
        return forwardedFor.split(',')[0].trim();
    }

    const realIp = req.headers['x-real-ip'];
    if (typeof realIp === 'string' && realIp.trim().length > 0) {
        return realIp.trim();
    }

    return req.ip || req.socket.remoteAddress || 'unknown';
};

const getProviderIdentifier = (req: Request): string => {
    const provider = req.params.provider;
    if (typeof provider !== 'string' || provider.trim().length === 0) {
        return 'unknown';
    }

    return provider.trim().toLowerCase();
};

async function checkRateLimit(req: Request): Promise<RateLimitResult> {
    const provider = getProviderIdentifier(req);
    const clientId = getClientIdentifier(req);
    const key = `ratelimit:provider:${provider}:${clientId}`;
    const now = Date.now();
    const windowStart = now - RATE_LIMIT.windowMs;

    const pipeline = redis.pipeline();
    pipeline.zremrangebyscore(key, '-inf', windowStart);
    pipeline.zadd(key, now, `${now}:${Math.random()}`);
    pipeline.zcard(key);
    pipeline.pexpire(key, RATE_LIMIT.windowMs);

    const results = await pipeline.exec();

    if (!results || results.some(([err]) => err !== null)) {
        throw new Error('Redis rate limit pipeline failed');
    }

    const count = results[2][1] as number;

    return {
        allowed: count <= RATE_LIMIT.maxRequests,
        count,
        remaining: Math.max(0, RATE_LIMIT.maxRequests - count),
    };
}

export async function providerRateLimitMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    let rateLimit: RateLimitResult;

    try {
        rateLimit = await checkRateLimit(req);
    } catch (error) {
        logger.warn('Provider rate limit check failed; allowing request', {
            requestId: (req as any).requestId || 'unknown',
            path: req.originalUrl,
            method: req.method,
            errorMessage: error instanceof Error ? error.message : 'Unknown error',
        });
        rateLimit = { allowed: true, count: 0, remaining: RATE_LIMIT.maxRequests };
    }

    res.setHeader('X-RateLimit-Limit', RATE_LIMIT.maxRequests);
    res.setHeader('X-RateLimit-Remaining', rateLimit.remaining);

    if (!rateLimit.allowed) {
        res.setHeader('Retry-After', Math.ceil(RATE_LIMIT.windowMs / 1000));
        res.status(429).json({ error: 'Too Many Requests: Provider rate limit exceeded.' });
        return;
    }

    next();
}
