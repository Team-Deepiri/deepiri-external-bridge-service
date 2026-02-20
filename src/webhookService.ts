import crypto from 'crypto';
import { Request, Response } from 'express';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';
import kafkaProducerService from './kafka/producer';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console({ format: winston.format.simple() })]
});

interface WebhookHandler {
  (payload: any, headers: Record<string, string>): Promise<any>;
}

interface WebhookHistoryEntry {
  provider: string;
  payload: any;
  result: any;
  timestamp: Date;
}

class WebhookService {
  private webhookHandlers: Map<string, WebhookHandler>;
  private webhookHistory: WebhookHistoryEntry[];

  constructor() {
    this.webhookHandlers = new Map();
    this.webhookHistory = [];
  }

  registerHandler(provider: string, handler: WebhookHandler): void {
    this.webhookHandlers.set(provider, handler);
    logger.info('Webhook handler registered', { provider });
  }

  async receiveWebhook(req: Request, res: Response): Promise<void> {
    const correlationId = uuidv4();
    const eventId = uuidv4();
    const { provider } = req.params;
    const payload = req.body;
    const headers = req.headers as Record<string, string>;
    const startTime = Date.now();

    try {
      logger.info('Webhook received', {
        event_id: eventId,
        correlation_id: correlationId,
        provider
      });

      // Validate webhook signature
      if (headers['x-signature'] && !this._verifySignature(provider, payload, headers['x-signature'])) {
        return void res.status(401).json({
          event_id: eventId,
          correlation_id: correlationId,
          error: 'Invalid webhook signature'
        });
      }

      // Build event for Kafka
      const integrationId = `${provider}_${payload.account_id || payload.organization_id || 'default'}`;
      const kafkaEvent = {
        event_id: eventId,
        correlation_id: correlationId,
        provider: provider,
        provider_event_id: payload.id || `${provider}-${Date.now()}`,
        provider_event_type: payload.type || headers['x-github-event'] || headers['x-trello-webhook-trigger'] || 'unknown',
        integration_id: integrationId,
        received_at: new Date().toISOString(),
        payload: payload,
        source_ip: req.ip || 'unknown'
      };

      /**
       * KAFKA INTEGRATION PATTERN: Producer (non-blocking)
       * 
       * We don't await the Kafka publish. This is the "fire-and-forget" pattern:
       * 1. Return 202 Accepted immediately to the webhook sender
       * 2. Publish to Kafka in the background
       * 3. If publish fails, it's logged but doesn't affect the HTTP response
       * 
       * Why? The webhook sender expects a quick response (< 5s usually).
       * Our consumer workers will process the message from Kafka asynchronously.
       * This decouples the webhook ingestion from processing.
       */
      kafkaProducerService
        .publishEvent('integration.webhook.received', kafkaEvent, integrationId)
        .catch(error => {
          logger.error('Failed to publish webhook to Kafka', {
            event_id: eventId,
            correlation_id: correlationId,
            provider,
            error: error instanceof Error ? error.message : String(error)
          });
          // Note: Can't change HTTP response here; already sent 202
        });

      // Record in history for quick access
      this.webhookHistory.push({
        provider,
        payload,
        result: { event_id: eventId, correlation_id: correlationId, status: 'queued' },
        timestamp: new Date()
      });

      if (this.webhookHistory.length > 1000) {
        this.webhookHistory.shift();
      }

      const processingTime = Date.now() - startTime;

      // Return 202 Accepted
      res.status(202).json({
        event_id: eventId,
        correlation_id: correlationId,
        status: 'accepted',
        message: 'Webhook received and queued for processing',
        processing_time_ms: processingTime
      });

      logger.info('Webhook accepted and queued', {
        event_id: eventId,
        correlation_id: correlationId,
        provider,
        processing_time_ms: processingTime
      });
    } catch (error: any) {
      logger.error('Error receiving webhook:', error);
      const statusCode = error.message?.includes('not supported') ? 400 : 500;
      res.status(statusCode).json({
        event_id: uuidv4(),
        correlation_id: correlationId,
        error: error.message || 'Webhook processing failed'
      });
    }
  }

  async getStatus(req: Request, res: Response): Promise<void> {
    try {
      const { provider } = req.params;
      const history = this.getWebhookHistory(provider, 10);
      res.json({ provider, recentWebhooks: history });
    } catch (error: any) {
      logger.error('Error getting status:', error);
      res.status(500).json({ error: 'Failed to get status' });
    }
  }

  async initiateOAuth(req: Request, res: Response): Promise<void> {
    try {
      const { provider } = req.params;

      if (provider !== 'google') {
        res.status(400).json({ error: `OAuth provider '${provider}' not supported` });
        return;
      }

      const clientId = process.env.GOOGLE_CLIENT_ID;
      const baseUrl = process.env.EXTERNAL_BRIDGE_BASE_URL;

      if (!clientId) {
        logger.error('GOOGLE_CLIENT_ID not configured');
        res.status(500).json({ error: 'GOOGLE_CLIENT_ID environment variable is required' });
        return;
      }

      if (!baseUrl) {
        logger.error('EXTERNAL_BRIDGE_BASE_URL not configured');
        res.status(500).json({ error: 'EXTERNAL_BRIDGE_BASE_URL environment variable is required' });
        return;
      }

      // Build redirect URI from environment variable
      const redirectUri = `${baseUrl}/oauth/google/callback`;

      // Generate random state for CSRF protection
      const state = crypto.randomBytes(32).toString('hex');

      // Store state in httpOnly cookie
      const isProduction = process.env.NODE_ENV === 'production';
      res.cookie('oauth_state', state, {
        httpOnly: true,
        sameSite: 'lax',
        secure: isProduction,
        maxAge: 600000 // 10 minutes
      });

      // Google OAuth authorization URL
      const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      authUrl.searchParams.set('client_id', clientId);
      authUrl.searchParams.set('redirect_uri', redirectUri);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('scope', 'openid email profile');
      authUrl.searchParams.set('access_type', 'offline');
      authUrl.searchParams.set('prompt', 'consent');
      authUrl.searchParams.set('state', state);

      logger.info('Redirecting to Google OAuth', { redirectUri });
      res.redirect(authUrl.toString());
    } catch (error: any) {
      logger.error('Error initiating OAuth:', error);
      res.status(500).json({ error: 'OAuth initiation failed' });
    }
  }

  async handleOAuthCallback(req: Request, res: Response): Promise<void> {
    try {
      const { provider } = req.params;

      if (provider !== 'google') {
        res.status(400).json({ error: `OAuth provider '${provider}' not supported` });
        return;
      }

      const { code, state: queryState, error: oauthError } = req.query;

      if (oauthError) {
        logger.error('Google OAuth error', { error: oauthError });
        res.status(400).json({ error: `OAuth error: ${oauthError}` });
        return;
      }

      if (!code || typeof code !== 'string') {
        res.status(400).json({ error: 'Authorization code is required' });
        return;
      }

      // Verify CSRF state
      const cookieState = req.cookies?.oauth_state;
      if (!cookieState || !queryState || cookieState !== queryState) {
        logger.error('OAuth state mismatch - possible CSRF attack', {
          cookieState: !!cookieState,
          queryState: !!queryState
        });
        res.status(401).json({ error: 'Invalid OAuth state - security check failed' });
        return;
      }

      // Clear state cookie after verification
      res.clearCookie('oauth_state');

      const clientId = process.env.GOOGLE_CLIENT_ID;
      const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
      const baseUrl = process.env.EXTERNAL_BRIDGE_BASE_URL;
      
      // AUTH_SERVICE_URL: use env var or default to docker service hostname (not localhost)
      const authServiceUrl = process.env.AUTH_SERVICE_URL || 'http://auth-service:5001';

      if (!clientId || !clientSecret) {
        logger.error('Google OAuth credentials not configured');
        res.status(500).json({ error: 'GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables are required' });
        return;
      }

      if (!baseUrl) {
        logger.error('EXTERNAL_BRIDGE_BASE_URL not configured');
        res.status(500).json({ error: 'EXTERNAL_BRIDGE_BASE_URL environment variable is required' });
        return;
      }

      // Build redirect URI from environment variable (must match authorize)
      const redirectUri = `${baseUrl}/oauth/google/callback`;

      // Exchange authorization code for tokens
      logger.info('Exchanging authorization code for tokens');
      const tokenParams = new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
      });

      const tokenResponse = await axios.post(
        'https://oauth2.googleapis.com/token',
        tokenParams.toString(),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      const { id_token } = tokenResponse.data;

      if (!id_token) {
        logger.error('No id_token in token response');
        res.status(500).json({ error: 'Failed to obtain ID token from Google' });
        return;
      }

      // Forward id_token to auth-service
      logger.info('Forwarding ID token to auth-service', { authServiceUrl });
      const authResponse = await axios.post(`${authServiceUrl}/auth/google`, {
        idToken: id_token
      }, {
        headers: {
          'Content-Type': 'application/json'
        }
      });

      // Return auth-service response to frontend
      res.json(authResponse.data);
    } catch (error: any) {
      logger.error('Error handling OAuth callback:', error);

      // Clear state cookie on error
      res.clearCookie('oauth_state');

      if (error.response) {
        // Forward error from auth-service if available
        const status = error.response.status || 500;
        const message = error.response.data?.error || error.message || 'OAuth callback failed';
        res.status(status).json({ error: message });
      } else if (error.request) {
        // Network error (auth-service unreachable)
        res.status(503).json({ error: 'Auth service unavailable' });
      } else {
        // Other error
        res.status(500).json({ error: 'OAuth callback failed' });
      }
    }
  }

  private async processWebhook(provider: string, payload: any, headers: Record<string, string> = {}): Promise<any> {
    try {
      if (headers['x-signature'] && !this._verifySignature(provider, payload, headers['x-signature'])) {
        throw new Error('Invalid webhook signature');
      }

      const handler = this.webhookHandlers.get(provider);
      if (!handler) {
        throw new Error(`No handler registered for provider: ${provider}`);
      }

      const result = await handler(payload, headers);

      this.webhookHistory.push({
        provider,
        payload,
        result,
        timestamp: new Date()
      });

      if (this.webhookHistory.length > 1000) {
        this.webhookHistory.shift();
      }

      logger.info('Webhook processed', { provider, success: !!result });
      return result;
    } catch (error) {
      logger.error('Error processing webhook:', error);
      throw error;
    }
  }

  async handleGitHubWebhook(payload: any, headers: Record<string, string>): Promise<any> {
    try {
      const event = headers['x-github-event'];
      
      switch (event) {
        case 'issues':
          return await this._handleGitHubIssue(payload);
        case 'pull_request':
          return await this._handleGitHubPR(payload);
        case 'push':
          return await this._handleGitHubPush(payload);
        default:
          logger.warn('Unhandled GitHub event', { event });
          return { processed: false, event };
      }
    } catch (error) {
      logger.error('Error handling GitHub webhook:', error);
      throw error;
    }
  }

  async handleNotionWebhook(payload: any, headers: Record<string, string>): Promise<any> {
    try {
      return {
        processed: true,
        type: payload.type,
        data: payload.data
      };
    } catch (error) {
      logger.error('Error handling Notion webhook:', error);
      throw error;
    }
  }

  async handleTrelloWebhook(payload: any, headers: Record<string, string>): Promise<any> {
    try {
      const action = payload.action;
      
      switch (action.type) {
        case 'createCard':
          return await this._handleTrelloCardCreate(action);
        case 'updateCard':
          return await this._handleTrelloCardUpdate(action);
        default:
          return { processed: false, type: action.type };
      }
    } catch (error) {
      logger.error('Error handling Trello webhook:', error);
      throw error;
    }
  }

  private _verifySignature(provider: string, payload: any, signature: string): boolean {
    const secret = process.env[`${provider.toUpperCase()}_WEBHOOK_SECRET`];
    if (!secret) return true;

    const hmac = crypto.createHmac('sha256', secret);
    const digest = hmac.update(JSON.stringify(payload)).digest('hex');
    const expectedSignature = `sha256=${digest}`;

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  }

  private async _handleGitHubIssue(payload: any): Promise<any> {
    return {
      type: 'task_created',
      source: 'github',
      sourceId: payload.issue.id,
      title: payload.issue.title,
      description: payload.issue.body,
      status: payload.issue.state === 'open' ? 'pending' : 'completed'
    };
  }

  private async _handleGitHubPR(payload: any): Promise<any> {
    return {
      type: 'task_created',
      source: 'github',
      sourceId: payload.pull_request.id,
      title: `PR: ${payload.pull_request.title}`,
      description: payload.pull_request.body,
      status: payload.pull_request.state
    };
  }

  private async _handleGitHubPush(payload: any): Promise<any> {
    return {
      type: 'activity',
      source: 'github',
      commits: payload.commits.length
    };
  }

  private async _handleTrelloCardCreate(action: any): Promise<any> {
    return {
      type: 'task_created',
      source: 'trello',
      sourceId: action.data.card.id,
      title: action.data.card.name,
      description: action.data.card.desc,
      status: 'pending'
    };
  }

  private async _handleTrelloCardUpdate(action: any): Promise<any> {
    return {
      type: 'task_updated',
      source: 'trello',
      sourceId: action.data.card.id,
      changes: action.data.old
    };
  }

  getWebhookHistory(provider: string | null = null, limit: number = 100): WebhookHistoryEntry[] {
    let history = this.webhookHistory;
    
    if (provider) {
      history = history.filter(h => h.provider === provider);
    }

    return history.slice(-limit).reverse();
  }
}

export default new WebhookService();

