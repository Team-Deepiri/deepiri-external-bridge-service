import { syncGithubWebhookToPlaky } from './githubWebhookSync';

describe('githubWebhookSync', () => {
  it('skips unsupported github event types', async () => {
    const result = await syncGithubWebhookToPlaky({ provider_event_type: 'release' });
    expect(result.skipped).toBe(true);
    expect(result.reason).toContain('unsupported_github_event_type');
  });
});
