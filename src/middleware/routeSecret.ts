import { NextFunction, Request, Response } from 'express';
import { requiredEnv } from '../boardman/boardmanConfig';

function readRouteSecret(req: Request): string | null {
  const headerSecret = req.header('x-boardman-route-secret');
  if (headerSecret && headerSecret.trim()) {
    return headerSecret.trim();
  }

  const authHeader = req.header('authorization');
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.slice('Bearer '.length).trim();
  }

  return null;
}

export function requireRouteSecret(req: Request, res: Response, next: NextFunction): void {
  try {
    const expected = requiredEnv('ROUTE_SECRET');
    const provided = readRouteSecret(req);

    if (!provided || provided !== expected) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    next();
  } catch (error) {
    res.status(503).json({
      error: 'Boardman route secret is not configured',
      message: error instanceof Error ? error.message : 'Unknown configuration error'
    });
  }
}
