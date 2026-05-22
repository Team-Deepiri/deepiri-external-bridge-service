import crypto from 'crypto';
import { Request, Response } from 'express';

jest.mock('./kafka/producer', () => ({
  __esModule: true,
  default: {
    publishEvent: jest.fn()
  }
}));

jest.mock('redis', () => {
  const client = {
    isOpen: false,
    connect: jest.fn(async () => undefined),
    lPush: jest.fn(async () => undefined),
    lTrim: jest.fn(async () => undefined),
    lRange: jest.fn(async () => [])
  };
  return {
    createClient: jest.fn(() => client)
  };
});

import webhookService from './webhookService';
import kafkaProducerService from './kafka/producer';

function createMockResponse(): Response & { status: jest.Mock; json: jest.Mock } {
  const res: Partial<Response> & { status: jest.Mock; json: jest.Mock } = {
    status: jest.fn(),
    json: jest.fn()
  } as any;
  res.status.mockReturnValue(res);
  res.json.mockReturnValue(res);
  return res as Response & { status: jest.Mock; json: jest.Mock };
}

function createGithubRequest(payload: Record<string, unknown>, headers: Record<string, string>): Request {
  const rawBody = JSON.stringify(payload);
  const req = {
    params: { provider: 'github' },
    body: payload,
    headers,
    ip: '127.0.0.1',
    rawBody
  };
  return req as unknown as Request;
}

function signGithubBody(rawBody: string, secret: string): string {
  return `sha256=${crypto.createHmac('sha256', secret).update(rawBody).digest('hex')}`;
}

describe('webhookService receiveWebhook', () => {
  const publishEvent = kafkaProducerService.publishEvent as jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.GITHUB_WEBHOOK_SECRET = 'test-secret';
  });

  it('rejects github webhook when required headers are missing', async () => {
    const payload = { action: 'opened' };
    const req = createGithubRequest(payload, {});
    const res = createMockResponse();

    await webhookService.receiveWebhook(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: expect.stringContaining('Missing required GitHub webhook headers')
      })
    );
    expect(publishEvent).not.toHaveBeenCalled();
  });

  it('rejects github webhook when signature is invalid', async () => {
    const payload = { action: 'opened' };
    const req = createGithubRequest(payload, {
      'x-github-delivery': 'delivery-1',
      'x-github-event': 'issues',
      'x-hub-signature-256': 'sha256=bad'
    });
    const res = createMockResponse();

    await webhookService.receiveWebhook(req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'Invalid GitHub webhook signature'
      })
    );
    expect(publishEvent).not.toHaveBeenCalled();
  });

  it('returns 202 when publish succeeds', async () => {
    publishEvent.mockResolvedValue(undefined);
    const payload = { action: 'opened' };
    const rawBody = JSON.stringify(payload);
    const signature = signGithubBody(rawBody, process.env.GITHUB_WEBHOOK_SECRET as string);
    const req = createGithubRequest(payload, {
      'x-github-delivery': 'delivery-2',
      'x-github-event': 'issues',
      'x-hub-signature-256': signature
    });
    const res = createMockResponse();

    await webhookService.receiveWebhook(req, res);

    expect(publishEvent).toHaveBeenCalledTimes(1);
    expect(publishEvent).toHaveBeenCalledWith(
      'integration.webhook.received',
      expect.objectContaining({
        provider: 'github',
        provider_event_id: 'delivery-2',
        provider_event_type: 'issues'
      }),
      expect.any(String)
    );
    expect(res.status).toHaveBeenCalledWith(202);
  });

  it('returns 503 when Kafka publish fails', async () => {
    publishEvent.mockRejectedValue(new Error('broker unavailable'));
    const payload = { action: 'opened' };
    const rawBody = JSON.stringify(payload);
    const signature = signGithubBody(rawBody, process.env.GITHUB_WEBHOOK_SECRET as string);
    const req = createGithubRequest(payload, {
      'x-github-delivery': 'delivery-3',
      'x-github-event': 'issues',
      'x-hub-signature-256': signature
    });
    const res = createMockResponse();

    await webhookService.receiveWebhook(req, res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 'retry',
        error: 'Webhook queue temporarily unavailable'
      })
    );
  });
});
