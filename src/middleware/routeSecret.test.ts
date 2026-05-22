import { Request, Response } from 'express';
import { requireRouteSecret } from './routeSecret';

function createMockResponse() {
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    }
  };
  return res as Response & { statusCode: number; body: unknown };
}

describe('requireRouteSecret', () => {
  const originalSecret = process.env.ROUTE_SECRET;

  afterEach(() => {
    process.env.ROUTE_SECRET = originalSecret;
  });

  it('rejects missing secret', () => {
    process.env.ROUTE_SECRET = 'test-route-secret';
    const req = { header: () => undefined } as unknown as Request;
    const res = createMockResponse();
    const next = jest.fn();

    requireRouteSecret(req, res, next);

    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('accepts valid x-boardman-route-secret header', () => {
    process.env.ROUTE_SECRET = 'test-route-secret';
    const req = {
      header: (name: string) => (name.toLowerCase() === 'x-boardman-route-secret' ? 'test-route-secret' : undefined)
    } as unknown as Request;
    const res = createMockResponse();
    const next = jest.fn();

    requireRouteSecret(req, res, next);

    expect(res.statusCode).toBe(200);
    expect(next).toHaveBeenCalledTimes(1);
  });
});
