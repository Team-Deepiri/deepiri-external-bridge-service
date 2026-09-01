import crypto from 'crypto';
import axios from 'axios';
import { createLogger } from '@team-deepiri/shared-utils';
import { getGithubConfig } from './config';

const logger = createLogger('github-app-auth');

function base64url(input: Buffer | string): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Signs a short-lived GitHub App JWT (RS256) with the App private key.
 * GitHub caps the lifetime at 10 minutes; we ask for 9 and back-date `iat`
 * by 60s to tolerate minor clock skew between us and GitHub.
 */
function signAppJwt(appId: string, privateKey: string): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = { iat: now - 60, exp: now + 9 * 60, iss: appId };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const signature = crypto.createSign('RSA-SHA256').update(signingInput).sign(privateKey);
  return `${signingInput}.${base64url(signature)}`;
}

interface InstallationToken {
  token: string;
  /** epoch ms */
  expiresAt: number;
}

let tokenCache: InstallationToken | null = null;
let inFlight: Promise<string> | null = null;

/**
 * Returns a valid installation access token, minting a new one when the cached
 * token is missing or within 5 minutes of expiry. Concurrent callers share a
 * single in-flight mint.
 */
export async function getInstallationToken(): Promise<string> {
  const cfg = getGithubConfig();
  if (!cfg) throw new Error('GitHub App is not configured');

  const skewMs = 5 * 60 * 1000;
  if (tokenCache && tokenCache.expiresAt - Date.now() > skewMs) {
    return tokenCache.token;
  }
  if (inFlight) return inFlight;

  inFlight = (async () => {
    const appJwt = signAppJwt(cfg.appId, cfg.privateKey);
    const url = `${cfg.apiBaseUrl}/app/installations/${cfg.installationId}/access_tokens`;
    try {
      const res = await axios.post(
        url,
        {},
        {
          headers: {
            Authorization: `Bearer ${appJwt}`,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
          },
          timeout: 15000,
        }
      );
      const token = res.data?.token as string;
      const expiresAt = res.data?.expires_at
        ? new Date(res.data.expires_at).getTime()
        : Date.now() + 55 * 60 * 1000;
      if (!token) throw new Error('installation token response had no token');
      tokenCache = { token, expiresAt };
      logger.info('Minted GitHub installation token', {
        installationId: cfg.installationId,
        expiresAt: new Date(expiresAt).toISOString(),
      });
      return token;
    } catch (err: any) {
      const status = err?.response?.status;
      logger.error('Failed to mint GitHub installation token', {
        status,
        message: err?.response?.data?.message || err?.message,
      });
      throw new Error(
        `Could not mint GitHub installation token${status ? ` (HTTP ${status})` : ''}`
      );
    } finally {
      inFlight = null;
    }
  })();

  return inFlight;
}

/** Test seam. */
export function _clearInstallationTokenCache(): void {
  tokenCache = null;
  inFlight = null;
}
