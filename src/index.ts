import express, { Router, Request, Response } from 'express';
import webhookService from './webhookService';
import {
    oauthCallbackQueryValidator,
    providerValidator,
    validateRequest,
    webhookPayloadValidator,
} from './middleware/inputValidation';
import { webhookRateLimitMiddleware } from './middleware/webhookRateLimit';

const router: Router = express.Router();

// Webhook routes
router.post(
    '/webhooks/:provider',
    webhookRateLimitMiddleware,
    validateRequest({
        allowedHeaderFields: ['x-request-id', 'x-signature', 'x-github-event', 'x-api-key'],
        validators: [providerValidator, webhookPayloadValidator],
        sanitizeBody: false,
    }),
    (req: Request, res: Response) => webhookService.receiveWebhook(req, res)
);

router.get(
    '/webhooks/:provider/status',
    webhookRateLimitMiddleware,
    validateRequest({
        allowedHeaderFields: ['x-request-id', 'x-api-key'],
        validators: [providerValidator],
    }),
    (req: Request, res: Response) => webhookService.getStatus(req, res)
);

// OAuth routes
router.get(
    '/oauth/:provider/authorize',
    validateRequest({
        allowedHeaderFields: ['x-request-id', 'x-api-key'],
        validators: [providerValidator],
    }),
    (req: Request, res: Response) => webhookService.initiateOAuth(req, res)
);

router.get(
    '/oauth/:provider/callback',
    validateRequest({
        allowedQueryFields: ['code', 'state', 'error'],
        allowedHeaderFields: ['x-request-id', 'x-api-key'],
        validators: [providerValidator, oauthCallbackQueryValidator],
    }),
    (req: Request, res: Response) => webhookService.handleOAuthCallback(req, res)
);

export default router;

