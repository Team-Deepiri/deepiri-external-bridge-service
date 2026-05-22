import {
  isSupportedGithubIssueAction,
  normalizeGithubIssuePayload
} from './githubIssueNormalizer';

describe('githubIssueNormalizer', () => {
  const basePayload = {
    action: 'opened',
    repository: {
      full_name: 'Team-Deepiri/boardman'
    },
    issue: {
      number: 42,
      title: 'Fix webhook dedupe',
      body: 'Body text',
      state: 'open',
      html_url: 'https://github.com/Team-Deepiri/boardman/issues/42',
      labels: [{ name: 'bug' }, { name: 'backend' }],
      assignees: [{ login: 'kyle' }]
    }
  };

  it('normalizes payload into deterministic external key', () => {
    const normalized = normalizeGithubIssuePayload(basePayload);

    expect(normalized.externalKey).toBe('github:issue:Team-Deepiri/boardman#42');
    expect(normalized.repoOwner).toBe('Team-Deepiri');
    expect(normalized.repoName).toBe('boardman');
    expect(normalized.issueState).toBe('open');
    expect(normalized.labels).toEqual(['bug', 'backend']);
    expect(normalized.assignees).toEqual(['kyle']);
  });

  it('treats unsupported state as open fallback', () => {
    const normalized = normalizeGithubIssuePayload({
      ...basePayload,
      issue: {
        ...basePayload.issue,
        state: 'draft'
      }
    });
    expect(normalized.issueState).toBe('open');
  });

  it('throws when repository is missing', () => {
    expect(() => normalizeGithubIssuePayload({
      ...basePayload,
      repository: undefined
    })).toThrow('repository.full_name');
  });

  it('reports supported actions', () => {
    expect(isSupportedGithubIssueAction('opened')).toBe(true);
    expect(isSupportedGithubIssueAction('edited')).toBe(true);
    expect(isSupportedGithubIssueAction('closed')).toBe(true);
    expect(isSupportedGithubIssueAction('labeled')).toBe(false);
  });
});
