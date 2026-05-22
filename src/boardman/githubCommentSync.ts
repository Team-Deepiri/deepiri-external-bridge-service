import { createLogger } from '@team-deepiri/shared-utils';
import { getBoardmanConfig } from './boardmanConfig';
import { BoardmanSyncResult } from './plakySyncTypes';
import { createPlakyClientForRepo, getWorkflowStatusValues } from './plakyClientFactory';
import { getBoardmanMappingStore } from './boardmanMappingStore';
import { resolveLinkedPlakyItemsForPr } from './prTaskLinking';

const logger = createLogger('boardman-github-comment-sync');

export async function syncGithubIssueCommentToPlaky(
  event: Record<string, any>
): Promise<BoardmanSyncResult> {
  const providerEventType = String(event?.provider_event_type || '').toLowerCase();
  if (providerEventType !== 'issue_comment') {
    return { skipped: true, reason: `unsupported_github_event_type:${providerEventType || 'unknown'}` };
  }

  const payload = event?.payload;
  if (!payload || typeof payload !== 'object') {
    return { skipped: true, reason: 'missing_payload' };
  }

  const action = String(payload.action || '').toLowerCase();
  if (action !== 'created') {
    return { skipped: true, reason: `unsupported_comment_action:${action || 'unknown'}` };
  }

  const issue = payload.issue;
  const comment = payload.comment;
  const repository = payload.repository;
  if (!issue || !repository?.full_name) {
    return { skipped: true, reason: 'missing_issue_comment_context' };
  }

  if (!issue.pull_request) {
    return { skipped: true, reason: 'not_a_pull_request_comment' };
  }

  const repoFullName = String(repository.full_name).trim();
  const prNumber = Number(issue.number);
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
    String(issue.title || ''),
    typeof issue.body === 'string' ? issue.body : undefined,
    { mappingStore, client }
  );

  if (targets.length === 0) {
    return { skipped: true, reason: 'no_linked_task_for_comment' };
  }

  for (const target of targets) {
    await client.patchItemField(target.plakyItemId, config.plaky.statusFieldKey, workflowStatuses.inQa);
  }

  logger.info('Moved linked Plaky tasks to in-QA from PR comment', {
    repo: repoFullName,
    pr_number: prNumber,
    commenter: comment?.user?.login
  });

  return { skipped: false, created: false, action: action, linkedIssueKeys: targets.map((t) => String(t.plakyItemId)) };
}
