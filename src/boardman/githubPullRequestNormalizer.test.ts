import {
  buildIssueExternalKey,
  extractLinkedIssueNumbers,
  normalizeGithubPullRequestPayload,
  resolvePullRequestMergeState
} from './githubPullRequestNormalizer';

describe('githubPullRequestNormalizer', () => {
  it('builds deterministic PR external key', () => {
    const normalized = normalizeGithubPullRequestPayload({
      action: 'opened',
      repository: { full_name: 'Team-Deepiri/boardman' },
      pull_request: {
        number: 7,
        title: 'Fix webhook dedupe (#42)',
        body: 'Closes #42',
        state: 'open',
        html_url: 'https://github.com/Team-Deepiri/boardman/pull/7'
      }
    });

    expect(normalized.externalKey).toBe('github:pr:Team-Deepiri/boardman#7');
    expect(normalized.linkedIssueNumbers).toEqual([42]);
    expect(buildIssueExternalKey('Team-Deepiri/boardman', 42)).toBe(
      'github:issue:Team-Deepiri/boardman#42'
    );
  });

  it('does not treat PR number as linked issue', () => {
    const linked = extractLinkedIssueNumbers(['PR #7: follow-up'], [7]);
    expect(linked).toEqual([]);
  });

  it('maps merged and draft states', () => {
    expect(
      resolvePullRequestMergeState({ state: 'closed', merged: true }, 'closed')
    ).toBe('merged');
    expect(
      resolvePullRequestMergeState({ state: 'open', draft: true }, 'converted_to_draft')
    ).toBe('draft');
  });
});
