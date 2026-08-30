import express, { Router, Request, Response } from 'express';
import { createLogger } from '@team-deepiri/shared-utils';
import { getGithubConfig, isGithubConfigured } from './config';
import { getOverview, getMemberStats, getPullDetail, invalidate } from './service';

const logger = createLogger('github-router');
const router: Router = express.Router();

const LOGIN_RE = /^[a-zA-Z0-9-]{1,39}$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;

function parseLogins(raw: unknown): string[] {
  if (typeof raw !== 'string' || !raw.trim()) return [];
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => LOGIN_RE.test(s))
    .slice(0, 40);
}

function notConfigured(res: Response): void {
  res.status(503).json({
    error: 'GitHub App is not configured on external-bridge-service',
    notConfigured: true,
  });
}

/** Non-sensitive config echo so the frontend can show a "connect GitHub" hint. */
router.get('/status', (_req: Request, res: Response) => {
  const cfg = getGithubConfig();
  res.json({
    configured: !!cfg,
    org: cfg?.org ?? process.env.GITHUB_ORG ?? 'Team-Deepiri',
    repoAllowList: cfg?.repoAllowList ?? [],
    cacheTtlSeconds: cfg?.cacheTtlSeconds ?? null,
  });
});

/** Whole-team open-PR + review picture for the People page. */
router.get('/overview', async (req: Request, res: Response) => {
  if (!isGithubConfigured()) return notConfigured(res);
  try {
    const overview = await getOverview(parseLogins(req.query.logins));
    res.json(overview);
  } catch (err: any) {
    logger.error('overview failed', { error: err?.message });
    res.status(502).json({ error: err?.message || 'Failed to fetch GitHub overview' });
  }
});

/** Open PRs across the org, optionally filtered to one repo. */
router.get('/pulls', async (req: Request, res: Response) => {
  if (!isGithubConfigured()) return notConfigured(res);
  try {
    const overview = await getOverview();
    const repo = typeof req.query.repo === 'string' ? req.query.repo.toLowerCase() : null;
    const pulls = repo ? overview.pulls.filter((p) => p.repo.toLowerCase() === repo) : overview.pulls;
    res.json({ generatedAt: overview.generatedAt, org: overview.org, count: pulls.length, pulls });
  } catch (err: any) {
    logger.error('pulls failed', { error: err?.message });
    res.status(502).json({ error: err?.message || 'Failed to fetch GitHub pulls' });
  }
});

/** One PR with its submitted reviews resolved (state per reviewer). */
router.get('/pulls/:repo/:number', async (req: Request, res: Response) => {
  if (!isGithubConfigured()) return notConfigured(res);
  const repo = String(req.params.repo || '');
  const numRaw = String(req.params.number || '');
  const number = Number(numRaw);
  if (!REPO_RE.test(repo) || !/^\d{1,7}$/.test(numRaw) || number < 1) {
    return void res.status(400).json({ error: 'Invalid repo or PR number' });
  }
  try {
    res.json(await getPullDetail(repo, number));
  } catch (err: any) {
    logger.error('pull detail failed', { repo, number, error: err?.message });
    res.status(502).json({ error: err?.message || 'Failed to fetch PR detail' });
  }
});

/** One member's open PRs + review load + 30-day review count. */
router.get('/members/:login/stats', async (req: Request, res: Response) => {
  if (!isGithubConfigured()) return notConfigured(res);
  const login = String(req.params.login || '');
  if (!LOGIN_RE.test(login)) {
    return void res.status(400).json({ error: 'Invalid GitHub login' });
  }
  try {
    res.json(await getMemberStats(login));
  } catch (err: any) {
    logger.error('member stats failed', { login, error: err?.message });
    res.status(502).json({ error: err?.message || 'Failed to fetch member stats' });
  }
});

/** Ops / webhook hook: drop the cached GitHub payloads. */
router.post('/refresh', async (_req: Request, res: Response) => {
  await invalidate();
  res.status(202).json({ status: 'cache cleared' });
});

export default router;
