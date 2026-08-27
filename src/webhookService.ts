import crypto from 'crypto';
import { Request, Response } from 'express';
import axios from 'axios';
import { createLogger, secureLog } from '@team-deepiri/shared-utils';
import { v4 as uuidv4 } from 'uuid';
import { createClient, RedisClientType } from 'redis';
import kafkaProducerService from './kafka/producer';
import beddRedactor from './beddRedactor';

const logger = createLogger('webhook-service');

// Stored in Redis as a JSON string; no longer held in process memory.
interface WebhookHistoryEntry {
  provider: string;
  payload: any;
  result: any;
  timestamp: string; // ISO string — Date is not JSON-serialisable
}

class WebhookService {
  /**
   * Redis client used to persist webhook history across restarts.
   * The history list key is `webhook_history`.
   * We store at most 1 000 entries via LTRIM after every push.
   */
  private redisClient: RedisClientType;

  constructor() {
    this.redisClient = createClient({
      url: `redis://:${process.env.REDIS_PASSWORD || ''}@${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || '6379'}`
    }) as RedisClientType;

    // Connect lazily — errors are caught per-operation so a Redis hiccup
    // does not crash the webhook ingestion path.
    this.redisClient.connect().catch(err =>
      logger.error('WebhookService: Redis connection failed', { error: err?.message })
    );
  }

  async receiveWebhook(req: Request, res: Response): Promise<void> {
    try {
      const startTime = Date.now();
      const { provider } = req.params;
      const payload = req.body;
      const headers = req.headers as Record<string, string>;
      const eventId = uuidv4();
      const correlationId = uuidv4();

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
        provider_event_type:
          payload.type ||
          headers['x-github-event'] ||
          headers['x-trello-webhook-trigger'] ||
          'unknown',
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
        });

      // Persist to Redis (best-effort; don't fail the 202 if Redis is unavailable).
      // Payload is redacted first — third-party webhook bodies routinely carry
      // access_token/client_secret/etc. and this history is queryable via
      // GET /webhooks/:provider/status.
      this.redactAndPushHistory({
        provider,
        payload,
        result: { event_id: eventId, correlation_id: correlationId, status: 'queued' },
        timestamp: new Date().toISOString()
      }).catch(err => logger.warn('Failed to persist webhook history', { error: err?.message }));

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
      secureLog('error', 'Error receiving webhook:', error);
      res.status(500).json({ error: error.message || 'Webhook processing failed' });
    }
  }

  async getStatus(req: Request, res: Response): Promise<void> {
    try {
      const { provider } = req.params;
      const history = await this.getWebhookHistory(provider, 10);
      res.json({ provider, recentWebhooks: history });
    } catch (error: any) {
      secureLog('error', 'Error getting status:', error);
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
        secureLog('error', 'GOOGLE_CLIENT_ID not configured');
        res.status(500).json({ error: 'GOOGLE_CLIENT_ID environment variable is required' });
        return;
      }

      if (!baseUrl) {
        secureLog('error', 'EXTERNAL_BRIDGE_BASE_URL not configured');
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

      secureLog('info', 'Redirecting to Google OAuth', { redirectUri });
      res.redirect(authUrl.toString());
    } catch (error: any) {
      secureLog('error', 'Error initiating OAuth:', error);
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
        secureLog('error', 'Google OAuth error', { error: oauthError });
        res.status(400).json({ error: `OAuth error: ${oauthError}` });
        return;
      }

      if (!code || typeof code !== 'string') {
        res.status(400).json({ error: 'Authorization code is required' });
        return;
      }

      // Verify CSRF state
      const cookieState = (req as any).cookies?.oauth_state;
      if (!cookieState || !queryState || cookieState !== queryState) {
        secureLog('error', 'OAuth state mismatch - possible CSRF attack', {
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
        secureLog('error', 'Google OAuth credentials not configured');
        res.status(500).json({
          error: 'GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables are required'
        });
        return;
      }

      if (!baseUrl) {
        secureLog('error', 'EXTERNAL_BRIDGE_BASE_URL not configured');
        res.status(500).json({ error: 'EXTERNAL_BRIDGE_BASE_URL environment variable is required' });
        return;
      }

      // Build redirect URI from environment variable (must match authorize)
      const redirectUri = `${baseUrl}/oauth/google/callback`;

      // Exchange authorization code for tokens
      secureLog('info', 'Exchanging authorization code for tokens');
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
        secureLog('error', 'No id_token in token response');
        res.status(500).json({ error: 'Failed to obtain ID token from Google' });
        return;
      }

      // Forward id_token to auth-service
      secureLog('info', 'Forwarding ID token to auth-service', { authServiceUrl });
      const authResponse = await axios.post(
        `${authServiceUrl}/auth/google`,
        { idToken: id_token },
        { headers: { 'Content-Type': 'application/json' } }
      );

      // Return auth-service response to frontend
      res.json(authResponse.data);
    } catch (error: any) {
      secureLog('error', 'Error handling OAuth callback:', error);

      // Clear state cookie on error
      res.clearCookie('oauth_state');

      if (error.response) {
        const status = error.response.status || 500;
        const message = error.response.data?.error || error.message || 'OAuth callback failed';
        res.status(status).json({ error: message });
      } else if (error.request) {
        res.status(503).json({ error: 'Auth service unavailable' });
      } else {
        res.status(500).json({ error: 'OAuth callback failed' });
      }
    }
  }

  /**
   * Push one entry to the Redis-backed history list.
   * Keeps the list bounded to 1 000 entries via LTRIM.
   */
  private async redactAndPushHistory(entry: WebhookHistoryEntry): Promise<void> {
    const redactedPayload = await beddRedactor.redact(entry.payload);
    await this.pushHistory({ ...entry, payload: redactedPayload });
  }

  private async pushHistory(entry: WebhookHistoryEntry): Promise<void> {
    if (!this.redisClient.isOpen) return;
    const key = 'webhook_history';
    await this.redisClient.lPush(key, JSON.stringify(entry));
    await this.redisClient.lTrim(key, 0, 999); // keep newest 1 000
  }

  private _verifySignature(provider: string, payload: any, signature: string): boolean {
    const secret = process.env[`${provider.toUpperCase()}_WEBHOOK_SECRET`];
    if (!secret) return true;

    const hmac = crypto.createHmac('sha256', secret);
    const digest = hmac.update(JSON.stringify(payload)).digest('hex');
    const expectedSignature = `sha256=${digest}`;

    // timingSafeEqual requires both buffers to have the same byte-length.
    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expectedSignature);
    if (sigBuf.length !== expBuf.length) return false;

    return crypto.timingSafeEqual(sigBuf, expBuf);
  }

  /**
   * Retrieve recent webhook history from Redis.
   * Returns entries in reverse-chronological order (newest first).
   */
  async getWebhookHistory(
    provider: string | null = null,
    limit: number = 100
  ): Promise<WebhookHistoryEntry[]> {
    if (!this.redisClient.isOpen) return [];

    try {
      const raw = await this.redisClient.lRange('webhook_history', 0, 999);
      let entries: WebhookHistoryEntry[] = raw
        .map(s => {
          try {
            return JSON.parse(s) as WebhookHistoryEntry;
          } catch {
            return null;
          }
        })
        .filter((e): e is WebhookHistoryEntry => e !== null);

      if (provider) {
        entries = entries.filter(h => h.provider === provider);
      }

      return entries.slice(0, limit);
    } catch (err) {
      logger.warn('Failed to fetch webhook history from Redis', { error: (err as Error)?.message });
      return [];
    }
  }
}

export default new WebhookService();