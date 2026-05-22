import { createLogger } from '@team-deepiri/shared-utils';
import { getBoardmanConfig } from './boardmanConfig';
import {
  isSupportedGithubPullRequestAction,
  mapMergeStateToPlakyValue,
  normalizeGithubPullRequestPayload
} from './githubPullRequestNormalizer';
import { BoardmanSyncResult, PlakySyncClient } from './plakySyncTypes';
import { createPlakyClientForRepo, getWorkflowStatusValues } from './plakyClientFactory';
import { getBoardmanMappingStore, BoardmanMappingStore } from './boardmanMappingStore';
import { resolveLinkedPlakyItemsForPr } from './prTaskLinking';

const logger = createLogger('boardman-github-pr-sync');

export async function syncGithubPullRequestToPlaky(
  event: Record<string, any>,
  deps?: {
    clientOverride?: PlakySyncClient;
    mappingStore?: BoardmanMappingStore;
  }
): Promise<BoardmanSyncResult> {
  const providerEventType = String(event?.provider_event_type || '').toLowerCase();
  if (providerEventType !== 'pull_request') {
    return { skipped: true, reason: `unsupported_github_event_type:${providerEventType || 'unknown'}` };
  }

  const payload = event?.payload;
  if (!payload || typeof payload !== 'object') {
    return { skipped: true, reason: 'missing_payload' };
  }

  const pullRequest = normalizeGithubPullRequestPayload(payload as Record<string, any>);
  if (!isSupportedGithubPullRequestAction(pullRequest.action)) {
    return {
      skipped: true,
      reason: `unsupported_pull_request_action:${pullRequest.action}`,
      action: pullRequest.action
    };
  }

  const config = getBoardmanConfig();
  const mappingStore = deps?.mappingStore || getBoardmanMappingStore();
  const { client } = deps?.clientOverride
    ? { client: deps.clientOverride }
    : createPlakyClientForRepo(pullRequest.repoFullName);

  const linkTargets = await resolveLinkedPlakyItemsForPr(
    pullRequest.repoFullName,
    pullRequest.prNumber,
    pullRequest.prTitle,
    payload.pull_request?.body,
    { mappingStore, client }
  );

  if (linkTargets.length === 0) {
    return {
      skipped: true,
      reason: 'no_pr_task_link',
      action: pullRequest.action,
      externalKey: pullRequest.externalKey
    };
  }

  const mergeStateValue = mapMergeStateToPlakyValue(pullRequest.mergeState, {
    draft: config.plaky.mergeStateDraftValue,
    open: config.plaky.mergeStateOpenValue,
    merged: config.plaky.mergeStateMergedValue,
    closed: config.plaky.mergeStateClosedValue
  });
  const workflowStatuses = getWorkflowStatusValues();

  let updatedCount = 0;
  const linkedIssueKeys: string[] = [];

  for (const target of linkTargets) {
    await client.patchItemField(target.plakyItemId, config.plaky.prUrlFieldKey, pullRequest.prUrl);
    await client.patchItemField(target.plakyItemId, config.plaky.mergeStateFieldKey, mergeStateValue);

    if (pullRequest.action === 'ready_for_review' && workflowStatuses.needsQa) {
      await client.patchItemField(target.plakyItemId, config.plaky.statusFieldKey, workflowStatuses.needsQa);
    }

    if (pullRequest.mergeState === 'merged' && workflowStatuses.prMerge) {
      await client.patchItemField(target.plakyItemId, config.plaky.statusFieldKey, workflowStatuses.prMerge);
    }

    await mappingStore.setPrItemId(pullRequest.repoFullName, pullRequest.prNumber, target.plakyItemId);
    updatedCount += 1;
    linkedIssueKeys.push(`${target.method}:${target.plakyItemId}`);
  }

  logger.info('Updated Plaky items with GitHub PR linkage', {
    pr_external_key: pullRequest.externalKey,
    linked_targets: linkedIssueKeys,
    updated_count: updatedCount,
    merge_state: pullRequest.mergeState,
    action: pullRequest.action
  });

  return {
    skipped: false,
    created: false,
    externalKey: pullRequest.externalKey,
    action: pullRequest.action,
    linkedIssueKeys
  };
}

export function resetGithubPullRequestSyncCachesForTests(): void {
  // routing/config caches reset via boardmanConfig/reposConfig in tests
}
