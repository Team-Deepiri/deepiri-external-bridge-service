import crypto from 'crypto';
import axios, { AxiosInstance } from 'axios';
import { requiredEnv } from './boardmanConfig';

interface InstallationTokenResponse {
  token: string;
  expires_at: string;
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
    const [owner, repo] = repoFullName.split('/');
    if (!owner || !repo) {
      throw new Error(`Invalid repo full name: ${repoFullName}`);
    }

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

    const response = await http.get<{ content?: string; encoding?: string }>(
      `/repos/${owner}/${repo}/contents/${encodeURIComponent(filePath)}`,
      { params: ref ? { ref } : undefined }
    );

    if (!response.data?.content || response.data.encoding !== 'base64') {
      return null;
    }

    return Buffer.from(response.data.content, 'base64').toString('utf8');
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
