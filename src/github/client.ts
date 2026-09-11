import axios, { AxiosRequestConfig } from 'axios';
import { createLogger } from '@team-deepiri/shared-utils';
import { getGithubConfig } from './config';
import { getInstallationToken } from './appAuth';

const logger = createLogger('github-client');

export interface GithubRequestOptions {
  params?: Record<string, string | number | boolean | undefined>;
  /** Max seconds we are willing to sleep for a rate-limit reset before giving up. */
  maxRateLimitWaitSeconds?: number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Single authenticated GitHub REST call. Retries once on a primary rate-limit
 * (403 / 429 with x-ratelimit-remaining: 0) when the reset is soon, and once on
 * a 401 (token may have just rotated). All other errors propagate.
 */
export async function githubRequest<T = any>(
  path: string,
  opts: GithubRequestOptions = {}
): Promise<{ data: T; headers: Record<string, string> }> {
  const cfg = getGithubConfig();
  if (!cfg) throw new Error('GitHub App is not configured');
  const url = path.startsWith('http') ? path : `${cfg.apiBaseUrl}${path}`;
  const maxWait = opts.maxRateLimitWaitSeconds ?? 20;

  let attempt = 0;
  // attempt 0: normal, attempt 1: after rate-limit sleep or token refresh.
  while (true) {
    const token = await getInstallationToken();
    const requestConfig: AxiosRequestConfig = {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      params: opts.params,
      timeout: 20000,
      // We handle status ourselves so we can inspect rate-limit headers.
      validateStatus: () => true,
    };

    const res = await axios.get(url, requestConfig);
    const headers = (res.headers || {}) as Record<string, string>;

    if (res.status >= 200 && res.status < 300) {
      return { data: res.data as T, headers };
    }

    const remaining = headers['x-ratelimit-remaining'];
    const reset = Number(headers['x-ratelimit-reset'] || 0);
    const isRateLimited =
      (res.status === 403 || res.status === 429) && remaining === '0' && reset > 0;

    if (isRateLimited && attempt < 1) {
      const waitSec = Math.max(0, reset - Math.floor(Date.now() / 1000)) + 1;
      if (waitSec <= maxWait) {
        logger.warn('GitHub rate-limited — sleeping until reset', { path, waitSec });
        await sleep(waitSec * 1000);
        attempt++;
        continue;
      }
      throw new Error(`GitHub rate limit exceeded; resets in ${waitSec}s`);
    }

    if (res.status === 401 && attempt < 1) {
      logger.warn('GitHub 401 — retrying once with a fresh token', { path });
      attempt++;
      continue;
    }

    const message = res.data?.message || `HTTP ${res.status}`;
    throw new Error(`GitHub request failed for ${path}: ${message}`);
  }
}

/** Follows RFC 5988 `Link: rel="next"` pagination, capped to `maxPages`. */
export async function githubPaginate<T = any>(
  path: string,
  opts: GithubRequestOptions & { maxPages?: number } = {}
): Promise<T[]> {
  const maxPages = opts.maxPages ?? 10;
  const perPage = 100;
  let page = 1;
  const out: T[] = [];

  while (page <= maxPages) {
    const { data, headers } = await githubRequest<T[] | { items: T[] }>(path, {
      ...opts,
      params: { per_page: perPage, page, ...(opts.params || {}) },
    });
    const batch = Array.isArray(data) ? data : Array.isArray((data as any).items) ? (data as any).items : [];
    out.push(...batch);
    const link = headers['link'] || '';
    if (batch.length < perPage || !/\brel="next"/.test(link)) break;
    page++;
  }
  return out;
}
