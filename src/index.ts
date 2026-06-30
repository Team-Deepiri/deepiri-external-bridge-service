import express, { Router, Request, Response } from 'express';
import webhookService from './webhookService';
import {
    oauthCallbackQueryValidator,
    providerValidator,
    validateRequest,
    webhookPayloadValidator,
} from './middleware/inputValidation';
import { providerRateLimitMiddleware } from './middleware/providerRateLimit';

const router: Router = express.Router();

// Webhook routes
router.post(
    '/webhooks/:provider',
    providerRateLimitMiddleware,
    validateRequest({
        allowedHeaderFields: ['x-request-id', 'x-signature', 'x-github-event', 'x-api-key'],
        validators: [providerValidator, webhookPayloadValidator],
        sanitizeBody: false,
    }),
    (req: Request, res: Response) => webhookService.receiveWebhook(req, res)
);

router.get(
    '/webhooks/:provider/status',
    providerRateLimitMiddleware,
    validateRequest({
        allowedHeaderFields: ['x-request-id', 'x-api-key'],
        validators: [providerValidator],
    }),
    (req: Request, res: Response) => webhookService.getStatus(req, res)
);

// OAuth routes
router.get(
    '/oauth/:provider/authorize',
    providerRateLimitMiddleware,
    validateRequest({
        allowedHeaderFields: ['x-request-id', 'x-api-key'],
        validators: [providerValidator],
    }),
    (req: Request, res: Response) => webhookService.initiateOAuth(req, res)
);

router.get(
    '/oauth/:provider/callback',
    providerRateLimitMiddleware,
    validateRequest({
        allowedQueryFields: ['code', 'state', 'error'],
        allowedHeaderFields: ['x-request-id', 'x-api-key'],
        validators: [providerValidator, oauthCallbackQueryValidator],
    }),
    (req: Request, res: Response) => webhookService.handleOAuthCallback(req, res)
);

export default router;

