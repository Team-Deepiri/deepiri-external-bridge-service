import { getBoardmanConfig, parsePositiveIntEnv, requiredEnv } from './boardmanConfig';
import { PlakyClient } from './plakyClient';
import { getRepoRouting, RepoRouting } from './reposConfig';
import { PlakySyncClient } from './plakySyncTypes';

export interface RepoPlakyContext {
  client: PlakySyncClient;
  routing: RepoRouting;
}

export function createPlakyClientForRepo(repoFullName: string): RepoPlakyContext {
  const routing = getRepoRouting(repoFullName);
  const client = new PlakyClient({
    apiKey: requiredEnv('PLAKY_API_KEY'),
    baseUrl: requiredEnv('PLAKY_BASE_URL'),
    spaceId: parsePositiveIntEnv('PLAKY_WORKSPACE_ID'),
    boardId: routing.plakyBoardId,
    groupId: routing.plakyGroupId
  });

  return { client, routing };
}

export function getWorkflowStatusValues(): {
  needsQa: string | null;
  inQa: string | null;
  prMerge: string | null;
} {
  const config = getBoardmanConfig();
  return {
    needsQa: config.plaky.needsQaStatusValue ?? null,
    inQa: config.plaky.inQaStatusValue ?? null,
    prMerge: config.plaky.prMergeStatusValue ?? null
  };
}
