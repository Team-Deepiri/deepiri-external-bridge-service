import express, { Router, Request, Response } from 'express';
import webhookService from './webhookService';
import boardmanAssistantRoutes from './boardman/boardmanAssistantRoutes';
import boardmanApiRoutes from './boardman/boardmanApiRoutes';
import { boardmanApiRateLimiter, oauthRateLimiter, webhookRateLimiter } from './middleware/rateLimit';

const router: Router = express.Router();

// Webhook routes
router.post('/webhooks/:provider', webhookRateLimiter, (req: Request, res: Response) => webhookService.receiveWebhook(req, res));
router.get('/webhooks/:provider/status', webhookRateLimiter, (req: Request, res: Response) => webhookService.getStatus(req, res));

// Boardman API (ROUTE_SECRET protected)
router.use('/api/v1/boardman', boardmanApiRateLimiter, boardmanApiRoutes);
router.use('/boardman/assistant', boardmanApiRateLimiter, boardmanAssistantRoutes);

// OAuth routes
router.get('/oauth/:provider/authorize', oauthRateLimiter, (req: Request, res: Response) => webhookService.initiateOAuth(req, res));
router.get('/oauth/:provider/callback', oauthRateLimiter, (req: Request, res: Response) => webhookService.handleOAuthCallback(req, res));

export default router;
