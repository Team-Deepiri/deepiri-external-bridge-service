import { createLogger } from '@team-deepiri/shared-utils';
import {
  isSupportedGithubIssueAction,
  normalizeGithubIssuePayload,
  NormalizedGithubIssueTask
} from './githubIssueNormalizer';
import { getBoardmanConfig, resetBoardmanConfigCacheForTests } from './boardmanConfig';
import { BoardmanConfig } from './boardmanConfig';
import { BoardmanSyncResult, PlakySyncClient } from './plakySyncTypes';
import { createPlakyClientForRepo } from './plakyClientFactory';
import { getBoardmanMappingStore, BoardmanMappingStore } from './boardmanMappingStore';
import { pickQaAssignee } from './qaPicker';

const logger = createLogger('boardman-github-issue-sync');

function buildPlakyTitle(issue: NormalizedGithubIssueTask, routingLabel?: string): string {
  const prefix = routingLabel ? `[${routingLabel}]` : `[${issue.repoName}]`;
  const candidate = `${prefix} #${issue.issueNumber} ${issue.issueTitle}`;
  return candidate.slice(0, 255);
}

function buildPlakyFields(
  issue: NormalizedGithubIssueTask,
  config: BoardmanConfig,
  routing?: { category?: string; plakyTable?: string }
): Record<string, unknown> {
  const fields: Record<string, unknown> = {
    [config.plaky.externalFieldKey]: issue.externalKey,
    [config.plaky.githubUrlFieldKey]: issue.issueUrl,
    [config.plaky.repoFieldKey]: issue.repoFullName,
    [config.plaky.statusFieldKey]:
      issue.issueState === 'closed'
        ? config.plaky.statusClosedValue
        : config.plaky.statusOpenValue
  };

  if (routing?.category) {
    fields[config.plaky.repoFieldKey] = `${issue.repoFullName} (${routing.category})`;
  }

  return fields;
}

async function applyQaAssignment(
  client: PlakySyncClient,
  config: BoardmanConfig,
  itemId: number,
  tier: number
): Promise<void> {
  if (!config.plaky.qaAssigneeFieldKey) return;

  const assignee = pickQaAssignee(tier);
  if (!assignee) return;

  await client.patchItemField(itemId, config.plaky.qaAssigneeFieldKey, assignee.plaky_user_id);
}

export async function syncGithubIssueToPlaky(
  event: Record<string, any>,
  deps?: {
    clientOverride?: PlakySyncClient;
    mappingStore?: BoardmanMappingStore;
  }
): Promise<BoardmanSyncResult> {
  const providerEventType = String(event?.provider_event_type || '').toLowerCase();
  if (providerEventType !== 'issues') {
    return { skipped: true, reason: `unsupported_github_event_type:${providerEventType || 'unknown'}` };
  }

  const payload = event?.payload;
  if (!payload || typeof payload !== 'object') {
    return { skipped: true, reason: 'missing_payload' };
  }

  const issue = normalizeGithubIssuePayload(payload as Record<string, any>);
  if (!isSupportedGithubIssueAction(issue.action)) {
    return { skipped: true, reason: `unsupported_issue_action:${issue.action}`, action: issue.action };
  }

  const config = getBoardmanConfig();
  const mappingStore = deps?.mappingStore || getBoardmanMappingStore();
  const { client, routing } = deps?.clientOverride
    ? { client: deps.clientOverride, routing: createPlakyClientForRepo(issue.repoFullName).routing }
    : createPlakyClientForRepo(issue.repoFullName);

  const fields = buildPlakyFields(issue, config, routing);

  let existingItemId = await mappingStore.getIssueItemId(issue.repoFullName, issue.issueNumber);
  if (existingItemId === null) {
    existingItemId = await client.findItemIdByExternalKey(
      config.plaky.externalFieldKey,
      issue.externalKey,
      config.plaky.maxScanPages,
      config.plaky.pageSize
    );
  }

  if (existingItemId !== null) {
    await client.patchItemField(existingItemId, config.plaky.githubUrlFieldKey, fields[config.plaky.githubUrlFieldKey]);
    await client.patchItemField(existingItemId, config.plaky.repoFieldKey, fields[config.plaky.repoFieldKey]);
    await client.patchItemField(existingItemId, config.plaky.statusFieldKey, fields[config.plaky.statusFieldKey]);
    await mappingStore.setIssueItemId(issue.repoFullName, issue.issueNumber, existingItemId);

    return {
      skipped: false,
      created: false,
      plakyItemId: existingItemId,
      externalKey: issue.externalKey,
      action: issue.action
    };
  }

  const itemId = await client.createItem(buildPlakyTitle(issue, issue.repoName), fields);
  await mappingStore.setIssueItemId(issue.repoFullName, issue.issueNumber, itemId);
  await applyQaAssignment(client, config, itemId, routing.tier);

  logger.info('Created Plaky item from GitHub issue', {
    plaky_item_id: itemId,
    external_key: issue.externalKey,
    issue_action: issue.action,
    plaky_board_id: routing.plakyBoardId,
    plaky_group_id: routing.plakyGroupId
  });

  return {
    skipped: false,
    created: true,
    plakyItemId: itemId,
    externalKey: issue.externalKey,
    action: issue.action
  };
}

export function resetBoardmanSyncCachesForTests(): void {
  resetBoardmanConfigCacheForTests();
}

export type { PlakySyncClient } from './plakySyncTypes';
