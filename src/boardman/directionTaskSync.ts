import { createLogger } from '@team-deepiri/shared-utils';
import { getBoardmanConfig } from './boardmanConfig';
import { DirectionTaskProposal } from './directionParser';
import { createPlakyClientForRepo } from './plakyClientFactory';
import { BoardmanSyncResult, PlakySyncClient } from './plakySyncTypes';

const logger = createLogger('boardman-direction-task-sync');

function buildPlakyTitle(repoFullName: string, task: DirectionTaskProposal): string {
  const candidate = `[${repoFullName}] ${task.section}: ${task.title}`;
  return candidate.slice(0, 255);
}

export interface DirectionApplyResult {
  externalKey: string;
  created: boolean;
  plakyItemId: number;
}

export async function applyDirectionTasksToPlaky(
  repoFullName: string,
  tasks: DirectionTaskProposal[],
  clientOverride?: PlakySyncClient
): Promise<DirectionApplyResult[]> {
  const config = getBoardmanConfig();
  const client = clientOverride || createPlakyClientForRepo(repoFullName).client;
  const results: DirectionApplyResult[] = [];

  for (const task of tasks) {
    const fields: Record<string, unknown> = {
      [config.plaky.externalFieldKey]: task.externalKey,
      [config.plaky.repoFieldKey]: repoFullName,
      [config.plaky.statusFieldKey]: config.plaky.statusOpenValue
    };

    const existingItemId = await client.findItemIdByExternalKey(
      config.plaky.externalFieldKey,
      task.externalKey,
      config.plaky.maxScanPages,
      config.plaky.pageSize
    );

    if (existingItemId !== null) {
      await client.patchItemField(existingItemId, config.plaky.repoFieldKey, repoFullName);
      await client.patchItemField(existingItemId, config.plaky.statusFieldKey, config.plaky.statusOpenValue);
      results.push({ externalKey: task.externalKey, created: false, plakyItemId: existingItemId });
      continue;
    }

    const itemId = await client.createItem(buildPlakyTitle(repoFullName, task), fields);
    logger.info('Created Plaky item from DIRECTION.md task', {
      plaky_item_id: itemId,
      external_key: task.externalKey,
      repo: repoFullName
    });
    results.push({ externalKey: task.externalKey, created: true, plakyItemId: itemId });
  }

  return results;
}

export async function syncDirectionTasksToPlaky(
  repoFullName: string,
  tasks: DirectionTaskProposal[],
  clientOverride?: PlakySyncClient
): Promise<BoardmanSyncResult> {
  if (tasks.length === 0) {
    return { skipped: true, reason: 'no_actionable_direction_tasks' };
  }

  const applied = await applyDirectionTasksToPlaky(repoFullName, tasks, clientOverride);
  const createdCount = applied.filter((entry) => entry.created).length;

  return {
    skipped: false,
    created: createdCount > 0,
    externalKey: applied[0]?.externalKey,
    plakyItemId: applied[0]?.plakyItemId
  };
}

export function resetDirectionTaskSyncCachesForTests(): void {
  // no-op: clients are created per repo
}
