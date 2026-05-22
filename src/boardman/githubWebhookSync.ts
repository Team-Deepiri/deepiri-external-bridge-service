import { syncGithubIssueToPlaky } from './githubIssueSync';
import { syncGithubPullRequestToPlaky } from './githubPullRequestSync';
import { syncGithubPullRequestReviewToPlaky } from './githubReviewSync';
import { syncGithubIssueCommentToPlaky } from './githubCommentSync';
import { BoardmanSyncResult } from './plakySyncTypes';

export async function syncGithubWebhookToPlaky(event: Record<string, any>): Promise<BoardmanSyncResult> {
  const providerEventType = String(event?.provider_event_type || '').toLowerCase();

  switch (providerEventType) {
    case 'issues':
      return syncGithubIssueToPlaky(event);
    case 'pull_request':
      return syncGithubPullRequestToPlaky(event);
    case 'pull_request_review':
      return syncGithubPullRequestReviewToPlaky(event);
    case 'issue_comment':
      return syncGithubIssueCommentToPlaky(event);
    default:
      return {
        skipped: true,
        reason: `unsupported_github_event_type:${providerEventType || 'unknown'}`
      };
  }
}
