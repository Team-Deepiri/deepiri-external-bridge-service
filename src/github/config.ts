import { createLogger } from '@team-deepiri/shared-utils';

const logger = createLogger('github-config');

export interface GithubConfig {
  appId: string;
  installationId: string;
  privateKey: string;
  org: string;
  /** Optional allow-list. When empty, every non-archived org repo is scanned. */
  repoAllowList: string[];
  /** Seconds a computed overview/stats payload is cached in Redis. */
  cacheTtlSeconds: number;
  apiBaseUrl: string;
}

/**
 * Reads the GitHub App credentials from the environment.
 *
 * The private key may be supplied either as a raw PEM (with real newlines or
 * `\n` escapes) via GITHUB_APP_PRIVATE_KEY, or base64-encoded via
 * GITHUB_APP_PRIVATE_KEY_BASE64 — the latter is friendlier to k8s secrets and
 * shell exports that mangle multi-line values.
 */
function readPrivateKey(): string {
  const b64 = process.env.GITHUB_APP_PRIVATE_KEY_BASE64;
  if (b64 && b64.trim()) {
    return Buffer.from(b64.trim(), 'base64').toString('utf8');
  }
  const raw = process.env.GITHUB_APP_PRIVATE_KEY || '';
  // Allow `\n`-escaped single-line values (common in .env files).
  return raw.includes('\\n') ? raw.replace(/\\n/g, '\n') : raw;
}

let cached: GithubConfig | null | undefined;

export function getGithubConfig(): GithubConfig | null {
  if (cached !== undefined) return cached;

  const appId = (process.env.GITHUB_APP_ID || '').trim();
  const installationId = (process.env.GITHUB_APP_INSTALLATION_ID || '').trim();
  const privateKey = readPrivateKey().trim();
  const org = (process.env.GITHUB_ORG || 'Team-Deepiri').trim();

  if (!appId || !installationId || !privateKey) {
    logger.warn(
      'GitHub App not configured — set GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID and ' +
        'GITHUB_APP_PRIVATE_KEY(_BASE64). GitHub endpoints will report notConfigured.'
    );
    cached = null;
    return cached;
  }

  const repoAllowList = (process.env.GITHUB_REPOS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  const cacheTtlSeconds = Math.max(
    30,
    parseInt(process.env.GITHUB_CACHE_TTL_SECONDS || '600', 10) || 600
  );

  cached = {
    appId,
    installationId,
    privateKey,
    org,
    repoAllowList,
    cacheTtlSeconds,
    apiBaseUrl: (process.env.GITHUB_API_BASE_URL || 'https://api.github.com').replace(/\/$/, ''),
  };
  return cached;
}

export function isGithubConfigured(): boolean {
  return getGithubConfig() !== null;
}

/** Test seam — forces the next getGithubConfig() call to re-read the environment. */
export function resetGithubConfigCache(): void {
  cached = undefined;
}
