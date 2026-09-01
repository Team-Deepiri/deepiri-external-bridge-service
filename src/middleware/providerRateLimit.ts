import { Request } from 'express';
import rateLimit from 'express-rate-limit';

const WINDOW_MS = 60_000;
const MAX_REQUESTS = 100;

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

export const providerRateLimitMiddleware = rateLimit({
    windowMs: WINDOW_MS,
    limit: MAX_REQUESTS,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => `${getProviderIdentifier(req)}:${getClientIdentifier(req)}`,
    message: {
        error: 'Too Many Requests: Provider rate limit exceeded.',
    },
    skip: (req) => req.method === 'OPTIONS',
    handler: (req, res, _next, options) => {
        res.status(options.statusCode).json(options.message);
    },
});

// Per-client limiter for the GitHub team-activity read API. `/github/overview`
// can fan out to hundreds of GitHub calls on a cache miss, so cap request
// volume even though the gateway also rate-limits /api/integrations.
export const githubApiRateLimitMiddleware = rateLimit({
    windowMs: WINDOW_MS,
    limit: MAX_REQUESTS,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: getClientIdentifier,
    message: {
        error: 'Too Many Requests: GitHub activity API rate limit exceeded.',
    },
    skip: (req) => req.method === 'OPTIONS',
    handler: (req, res, _next, options) => {
        res.status(options.statusCode).json(options.message);
    },
});
