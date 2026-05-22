import { createLogger } from '@team-deepiri/shared-utils';
import { getBoardmanConfig } from './boardmanConfig';
import { BoardmanSyncResult } from './plakySyncTypes';
import { createPlakyClientForRepo, getWorkflowStatusValues } from './plakyClientFactory';
import { getBoardmanMappingStore } from './boardmanMappingStore';
import { resolveLinkedPlakyItemsForPr } from './prTaskLinking';

const logger = createLogger('boardman-github-review-sync');

export async function syncGithubPullRequestReviewToPlaky(
  event: Record<string, any>
): Promise<BoardmanSyncResult> {
  const providerEventType = String(event?.provider_event_type || '').toLowerCase();
  if (providerEventType !== 'pull_request_review') {
    return { skipped: true, reason: `unsupported_github_event_type:${providerEventType || 'unknown'}` };
  }

  const payload = event?.payload;
  if (!payload || typeof payload !== 'object') {
    return { skipped: true, reason: 'missing_payload' };
  }

  const action = String(payload.action || '').toLowerCase();
  if (action !== 'submitted') {
    return { skipped: true, reason: `unsupported_review_action:${action || 'unknown'}` };
  }

  const pullRequest = payload.pull_request;
  const repository = payload.repository;
  if (!pullRequest?.number || !repository?.full_name) {
    return { skipped: true, reason: 'missing_pull_request_context' };
  }

  const repoFullName = String(repository.full_name).trim();
  const prNumber = Number(pullRequest.number);
  const workflowStatuses = getWorkflowStatusValues();
  if (!workflowStatuses.inQa) {
    return { skipped: true, reason: 'in_qa_status_not_configured' };
  }

  const config = getBoardmanConfig();
  const mappingStore = getBoardmanMappingStore();
  const { client } = createPlakyClientForRepo(repoFullName);

  const targets = await resolveLinkedPlakyItemsForPr(
    repoFullName,
    prNumber,
    String(pullRequest.title || ''),
    typeof pullRequest.body === 'string' ? pullRequest.body : undefined,
    { mappingStore, client }
  );

  if (targets.length === 0) {
    return { skipped: true, reason: 'no_linked_task_for_review' };
  }

  for (const target of targets) {
    await client.patchItemField(target.plakyItemId, config.plaky.statusFieldKey, workflowStatuses.inQa);
  }

  logger.info('Moved linked Plaky tasks to in-QA from PR review', {
    repo: repoFullName,
    pr_number: prNumber,
    task_count: targets.length
  });

  return { skipped: false, created: false, action: action, linkedIssueKeys: targets.map((t) => String(t.plakyItemId)) };
}
