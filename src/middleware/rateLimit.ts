import rateLimit from 'express-rate-limit';

export const webhookRateLimiter = rateLimit({
  windowMs: 60_000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many webhook requests, please retry shortly' }
});

export const boardmanApiRateLimiter = rateLimit({
  windowMs: 60_000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many Boardman requests, please retry shortly' }
});

export const oauthRateLimiter = rateLimit({
  windowMs: 60_000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many OAuth requests, please retry shortly' }
});
