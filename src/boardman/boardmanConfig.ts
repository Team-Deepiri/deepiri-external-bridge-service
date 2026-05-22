export interface BoardmanPlakyConfig {
  externalFieldKey: string;
  githubUrlFieldKey: string;
  repoFieldKey: string;
  statusFieldKey: string;
  prUrlFieldKey: string;
  mergeStateFieldKey: string;
  qaAssigneeFieldKey?: string;
  statusOpenValue: string;
  statusClosedValue: string;
  mergeStateOpenValue: string;
  mergeStateMergedValue: string;
  mergeStateClosedValue: string;
  mergeStateDraftValue: string;
  needsQaStatusValue?: string;
  inQaStatusValue?: string;
  prMergeStatusValue?: string;
  maxScanPages: number;
  pageSize: number;
}

export interface BoardmanConfig {
  plaky: BoardmanPlakyConfig;
}

let cachedConfig: BoardmanConfig | null = null;

export function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.trim() === '') {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  const normalized = value.trim();
  const lower = normalized.toLowerCase();
  if (
    lower.startsWith('your-') ||
    lower === 'change-me' ||
    lower === 'replace-me'
  ) {
    throw new Error(`Environment variable ${name} contains placeholder value`);
  }
  return normalized;
}

export function optionalEnv(name: string): string | undefined {
  const value = process.env[name];
  if (!value || value.trim() === '') return undefined;
  const normalized = value.trim();
  const lower = normalized.toLowerCase();
  if (
    lower.startsWith('your-') ||
    lower === 'change-me' ||
    lower === 'replace-me'
  ) {
    return undefined;
  }
  return normalized;
}

export function parsePositiveIntEnv(name: string, fallback?: number): number {
  const raw = process.env[name];
  if (!raw || raw.trim() === '') {
    if (fallback !== undefined) return fallback;
    throw new Error(`Missing required environment variable: ${name}`);
  }

  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`Invalid positive integer for ${name}: ${raw}`);
  }
  return parsed;
}

export function getBoardmanConfig(): BoardmanConfig {
  if (cachedConfig) return cachedConfig;
  cachedConfig = {
    plaky: {
      externalFieldKey: requiredEnv('PLAKY_FIELD_EXTERNAL_KEY_ID'),
      githubUrlFieldKey: requiredEnv('PLAKY_FIELD_GITHUB_URL_ID'),
      repoFieldKey: requiredEnv('PLAKY_FIELD_REPO_ID'),
      statusFieldKey: requiredEnv('PLAKY_FIELD_STATUS_ID'),
      prUrlFieldKey: requiredEnv('PLAKY_FIELD_PR_URL_ID'),
      mergeStateFieldKey: requiredEnv('PLAKY_FIELD_MERGE_STATE_ID'),
      statusOpenValue: requiredEnv('PLAKY_STATUS_OPEN_VALUE'),
      statusClosedValue: requiredEnv('PLAKY_STATUS_CLOSED_VALUE'),
      mergeStateOpenValue: requiredEnv('PLAKY_MERGE_STATE_OPEN_VALUE'),
      mergeStateMergedValue: requiredEnv('PLAKY_MERGE_STATE_MERGED_VALUE'),
      mergeStateClosedValue: requiredEnv('PLAKY_MERGE_STATE_CLOSED_VALUE'),
      mergeStateDraftValue: requiredEnv('PLAKY_MERGE_STATE_DRAFT_VALUE'),
      qaAssigneeFieldKey: optionalEnv('PLAKY_FIELD_QA_ASSIGNEE_ID'),
      needsQaStatusValue: optionalEnv('PLAKY_NEEDS_QA_STATUS'),
      inQaStatusValue: optionalEnv('PLAKY_IN_QA_STATUS'),
      prMergeStatusValue: optionalEnv('PLAKY_PR_MERGE_STATUS'),
      maxScanPages: parsePositiveIntEnv('PLAKY_MAX_SCAN_PAGES', 20),
      pageSize: parsePositiveIntEnv('PLAKY_PAGE_SIZE', 100)
    }
  };
  return cachedConfig;
}

export function resetBoardmanConfigCacheForTests(): void {
  cachedConfig = null;
}
