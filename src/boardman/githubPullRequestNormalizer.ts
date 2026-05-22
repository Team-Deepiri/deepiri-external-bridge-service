export type GithubPullRequestMergeState = 'draft' | 'open' | 'merged' | 'closed';

export interface NormalizedGithubPullRequest {
  action: string;
  externalKey: string;
  repoFullName: string;
  prNumber: number;
  prTitle: string;
  prUrl: string;
  mergeState: GithubPullRequestMergeState;
  linkedIssueNumbers: number[];
}

export const SUPPORTED_GITHUB_PULL_REQUEST_ACTIONS = new Set([
  'opened',
  'edited',
  'reopened',
  'closed',
  'synchronize',
  'ready_for_review',
  'converted_to_draft'
]);

export function isSupportedGithubPullRequestAction(action: string): boolean {
  return SUPPORTED_GITHUB_PULL_REQUEST_ACTIONS.has(action);
}

export function extractLinkedIssueNumbers(
  texts: Array<string | undefined>,
  excludeNumbers: number[] = []
): number[] {
  const issueNumbers = new Set<number>();
  const excluded = new Set(excludeNumbers);
  const pattern = /#(\d+)\b/g;

  for (const text of texts) {
    if (!text) continue;
    let match: RegExpExecArray | null;
    const localPattern = new RegExp(pattern.source, pattern.flags);
    while ((match = localPattern.exec(text)) !== null) {
      const issueNumber = Number(match[1]);
      if (Number.isInteger(issueNumber) && issueNumber > 0 && !excluded.has(issueNumber)) {
        issueNumbers.add(issueNumber);
      }
    }
  }

  return [...issueNumbers].sort((a, b) => a - b);
}

export function resolvePullRequestMergeState(
  pullRequest: Record<string, any>,
  action: string
): GithubPullRequestMergeState {
  if (pullRequest?.draft === true || action === 'converted_to_draft') {
    return 'draft';
  }

  const state = typeof pullRequest?.state === 'string' ? pullRequest.state.toLowerCase() : 'open';
  const merged = pullRequest?.merged === true;

  if (state === 'closed') {
    return merged ? 'merged' : 'closed';
  }

  return 'open';
}

export function buildIssueExternalKey(repoFullName: string, issueNumber: number): string {
  return `github:issue:${repoFullName}#${issueNumber}`;
}

export function normalizeGithubPullRequestPayload(payload: Record<string, any>): NormalizedGithubPullRequest {
  const actionRaw = typeof payload?.action === 'string' ? payload.action : '';
  const action = actionRaw.toLowerCase();

  const repository = payload?.repository;
  const pullRequest = payload?.pull_request;

  if (!repository || typeof repository.full_name !== 'string' || repository.full_name.trim() === '') {
    throw new Error('GitHub pull_request payload missing repository.full_name');
  }
  if (!pullRequest || typeof pullRequest.number !== 'number') {
    throw new Error('GitHub pull_request payload missing pull_request.number');
  }

  const repoFullName = repository.full_name.trim();
  const prNumber = pullRequest.number;
  if (!Number.isInteger(prNumber) || prNumber <= 0) {
    throw new Error(`GitHub pull_request number is invalid: ${prNumber}`);
  }

  const prTitle = typeof pullRequest.title === 'string' && pullRequest.title.trim()
    ? pullRequest.title.trim()
    : `PR #${prNumber}`;

  const prUrl = typeof pullRequest.html_url === 'string' && pullRequest.html_url.trim()
    ? pullRequest.html_url.trim()
    : `https://github.com/${repoFullName}/pull/${prNumber}`;

  const linkedIssueNumbers = extractLinkedIssueNumbers(
    [pullRequest.title, pullRequest.body],
    [prNumber]
  );
  const mergeState = resolvePullRequestMergeState(pullRequest, action);

  return {
    action,
    externalKey: `github:pr:${repoFullName}#${prNumber}`,
    repoFullName,
    prNumber,
    prTitle,
    prUrl,
    mergeState,
    linkedIssueNumbers
  };
}

export function mapMergeStateToPlakyValue(
  mergeState: GithubPullRequestMergeState,
  values: {
    draft: string;
    open: string;
    merged: string;
    closed: string;
  }
): string {
  switch (mergeState) {
    case 'draft':
      return values.draft;
    case 'merged':
      return values.merged;
    case 'closed':
      return values.closed;
    case 'open':
    default:
      return values.open;
  }
}
