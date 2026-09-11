import express, { Router, Request, Response } from 'express';
import webhookService from './webhookService';
import githubRouter from './github/router';
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
        allowedHeaderFields: [
            'x-request-id', 'x-api-key', 'x-signature', 'x-github-event',
            // GitHub attaches these to every delivery; reject-on-unknown would
            // otherwise 400 real webhooks before signature verification runs.
            'x-hub-signature', 'x-hub-signature-256', 'x-github-delivery',
            'x-github-hook-id', 'x-github-hook-installation-target-id',
            'x-github-hook-installation-target-type',
        ],
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

// GitHub team-activity read API (open PRs, reviewers, per-member review load).
// Consumed by the portal People page via the gateway at /api/integrations/github/*.
router.use('/github', githubRouter);

export default router;

