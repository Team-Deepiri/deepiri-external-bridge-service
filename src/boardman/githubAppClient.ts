import crypto from 'crypto';
import axios, { AxiosInstance } from 'axios';
import { requiredEnv } from './boardmanConfig';

interface InstallationTokenResponse {
  token: string;
  expires_at: string;
}

interface GithubBlobResponse {
  data?: {
    repository?: {
      object?: {
        text?: string | null;
        isBinary?: boolean;
      } | null;
    } | null;
  };
}

const REPO_OWNER_OR_NAME_PATTERN = /^[A-Za-z0-9_.-]+$/;
const REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;
const DEFAULT_REF = 'HEAD';

function parseRepoFullName(repoFullName: string): { owner: string; repo: string } {
  const parts = repoFullName.trim().split('/');
  if (parts.length !== 2) {
    throw new Error(`Invalid repo full name: ${repoFullName}`);
  }

  const [owner, repo] = parts;
  if (!REPO_OWNER_OR_NAME_PATTERN.test(owner) || !REPO_OWNER_OR_NAME_PATTERN.test(repo)) {
    throw new Error(`Invalid repo full name: ${repoFullName}`);
  }

  return { owner, repo };
}

function normalizeRepoFilePath(filePath: string): string {
  const normalized = filePath.trim().replace(/^\/+/, '');
  if (!normalized || normalized.includes('..') || normalized.includes('\\') || normalized.length > 512) {
    throw new Error(`Invalid repo file path: ${filePath}`);
  }
  return normalized;
}

function normalizeRef(ref?: string): string {
  const normalized = ref?.trim() || DEFAULT_REF;
  if (!REF_PATTERN.test(normalized) || normalized.includes('..')) {
    throw new Error(`Invalid GitHub ref: ${ref}`);
  }
  return normalized;
}

export class GithubAppClient {
  private readonly appId: string;
  private readonly privateKey: string;
  private readonly installationId: string;
  private cachedInstallationToken: { token: string; expiresAtMs: number } | null = null;

  constructor(
    appId = requiredEnv('GITHUB_APP_ID'),
    privateKey = requiredEnv('GITHUB_APP_PRIVATE_KEY'),
    installationId = requiredEnv('GITHUB_INSTALLATION_ID')
  ) {
    this.appId = appId;
    this.privateKey = privateKey.replace(/\\n/g, '\n');
    this.installationId = installationId;
  }

  async fetchRepoFileText(repoFullName: string, filePath: string, ref?: string): Promise<string | null> {
    const { owner, repo } = parseRepoFullName(repoFullName);
    const normalizedPath = normalizeRepoFilePath(filePath);
    const expression = `${normalizeRef(ref)}:${normalizedPath}`;

    const token = await this.getInstallationAccessToken();
    const http = axios.create({
      baseURL: 'https://api.github.com',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
      },
      timeout: 15000
    });

    const response = await http.post<GithubBlobResponse>('/graphql', {
      query: `
        query BoardmanRepoFile($owner: String!, $repo: String!, $expression: String!) {
          repository(owner: $owner, name: $repo) {
            object(expression: $expression) {
              ... on Blob {
                text
                isBinary
              }
            }
          }
        }
      `,
      variables: { owner, repo, expression }
    });

    const blob = response.data?.data?.repository?.object;
    if (!blob || blob.isBinary || typeof blob.text !== 'string') {
      return null;
    }

    return blob.text;
  }

  private async getInstallationAccessToken(): Promise<string> {
    const now = Date.now();
    if (this.cachedInstallationToken && this.cachedInstallationToken.expiresAtMs > now + 60_000) {
      return this.cachedInstallationToken.token;
    }

    const appJwt = this.createAppJwt();
    const http = axios.create({
      baseURL: 'https://api.github.com',
      headers: {
        Authorization: `Bearer ${appJwt}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
      },
      timeout: 15000
    });

    const response = await http.post<InstallationTokenResponse>(
      `/app/installations/${this.installationId}/access_tokens`
    );

    if (!response.data?.token) {
      throw new Error('GitHub installation token response missing token');
    }

    const expiresAtMs = response.data.expires_at
      ? Date.parse(response.data.expires_at)
      : now + 50 * 60 * 1000;

    this.cachedInstallationToken = {
      token: response.data.token,
      expiresAtMs
    };

    return response.data.token;
  }

  private createAppJwt(): string {
    const issuedAt = Math.floor(Date.now() / 1000) - 30;
    const expiresAt = issuedAt + 9 * 60;
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        iat: issuedAt,
        exp: expiresAt,
        iss: this.appId
      })
    ).toString('base64url');
    const unsigned = `${header}.${payload}`;
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(unsigned);
    signer.end();
    const signature = signer.sign(this.privateKey).toString('base64url');
    return `${unsigned}.${signature}`;
  }
}
