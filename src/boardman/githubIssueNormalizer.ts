export type GithubIssueState = 'open' | 'closed';

export interface NormalizedGithubIssueTask {
  action: string;
  externalKey: string;
  repoFullName: string;
  repoOwner: string;
  repoName: string;
  issueNumber: number;
  issueTitle: string;
  issueBody: string;
  issueState: GithubIssueState;
  issueUrl: string;
  labels: string[];
  assignees: string[];
}

export const SUPPORTED_GITHUB_ISSUE_ACTIONS = new Set([
  'opened',
  'edited',
  'reopened',
  'closed',
  'assigned',
  'unassigned'
]);

export function isSupportedGithubIssueAction(action: string): boolean {
  return SUPPORTED_GITHUB_ISSUE_ACTIONS.has(action);
}

export function normalizeGithubIssuePayload(payload: Record<string, any>): NormalizedGithubIssueTask {
  const actionRaw = typeof payload?.action === 'string' ? payload.action : '';
  const action = actionRaw.toLowerCase();

  const repository = payload?.repository;
  const issue = payload?.issue;

  if (!repository || typeof repository.full_name !== 'string' || repository.full_name.trim() === '') {
    throw new Error('GitHub issue payload missing repository.full_name');
  }
  if (!issue || typeof issue.number !== 'number') {
    throw new Error('GitHub issue payload missing issue.number');
  }

  const repoFullName = repository.full_name.trim();
  const repoParts = repoFullName.split('/');
  if (repoParts.length !== 2) {
    throw new Error(`GitHub repository.full_name is invalid: ${repoFullName}`);
  }
  const [repoOwner, repoName] = repoParts;

  const issueNumber = issue.number;
  if (!Number.isInteger(issueNumber) || issueNumber <= 0) {
    throw new Error(`GitHub issue number is invalid: ${issueNumber}`);
  }

  const issueStateRaw = typeof issue.state === 'string' ? issue.state.toLowerCase() : 'open';
  const issueState: GithubIssueState = issueStateRaw === 'closed' ? 'closed' : 'open';

  const issueTitle = typeof issue.title === 'string' && issue.title.trim()
    ? issue.title.trim()
    : `Issue #${issueNumber}`;

  const issueBody = typeof issue.body === 'string' ? issue.body : '';

  const issueUrl = typeof issue.html_url === 'string' && issue.html_url.trim()
    ? issue.html_url.trim()
    : `https://github.com/${repoFullName}/issues/${issueNumber}`;

  const labels = Array.isArray(issue.labels)
    ? issue.labels
      .map((label: any) => (typeof label?.name === 'string' ? label.name.trim() : ''))
      .filter((label: string) => label.length > 0)
    : [];

  const assignees = Array.isArray(issue.assignees)
    ? issue.assignees
      .map((assignee: any) => (typeof assignee?.login === 'string' ? assignee.login.trim() : ''))
      .filter((assignee: string) => assignee.length > 0)
    : [];

  return {
    action,
    externalKey: `github:issue:${repoFullName}#${issueNumber}`,
    repoFullName,
    repoOwner,
    repoName,
    issueNumber,
    issueTitle,
    issueBody,
    issueState,
    issueUrl,
    labels,
    assignees
  };
}
