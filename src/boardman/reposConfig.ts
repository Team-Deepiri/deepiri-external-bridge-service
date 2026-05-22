import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';
import { parsePositiveIntEnv, requiredEnv } from './boardmanConfig';

export interface RepoRoutingEntry {
  plaky_board_id?: number | string;
  plaky_group_id?: number | string;
  tier?: number;
  category?: string;
  plaky_table?: string;
}

export interface ReposYaml {
  defaults?: RepoRoutingEntry;
  repos?: Record<string, RepoRoutingEntry>;
}

export interface RepoRouting {
  repoFullName: string;
  plakyBoardId: number;
  plakyGroupId: number;
  tier: number;
  category?: string;
  plakyTable?: string;
}

let cachedReposYaml: ReposYaml | null = null;

export function getBoardmanConfigDir(): string {
  return process.env.BOARDMAN_CONFIG_DIR || path.join(process.cwd(), 'config');
}

export function loadReposYaml(forceReload = false): ReposYaml {
  if (cachedReposYaml && !forceReload) return cachedReposYaml;

  const configPath = path.join(getBoardmanConfigDir(), 'repos.yml');
  if (!fs.existsSync(configPath)) {
    cachedReposYaml = {};
    return cachedReposYaml;
  }

  const raw = fs.readFileSync(configPath, 'utf8');
  cachedReposYaml = (yaml.load(raw) as ReposYaml) || { defaults: {}, repos: {} };
  return cachedReposYaml;
}

function parseId(value: number | string | undefined, fallbackEnv: string): number {
  if (value !== undefined && value !== null && value !== '') {
    const parsed = Number(value);
    if (Number.isInteger(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return parsePositiveIntEnv(fallbackEnv);
}

export function getRepoRouting(repoFullName: string): RepoRouting {
  const config = loadReposYaml();
  const entry =
    config.repos?.[repoFullName] ||
    config.repos?.[repoFullName.toLowerCase()] ||
    config.defaults;

  if (!entry) {
    return {
      repoFullName,
      plakyBoardId: parsePositiveIntEnv('PLAKY_BOARD_ID'),
      plakyGroupId: parsePositiveIntEnv('PLAKY_ITEM_GROUP_ID'),
      tier: 2
    };
  }

  return {
    repoFullName,
    plakyBoardId: parseId(entry.plaky_board_id, 'PLAKY_BOARD_ID'),
    plakyGroupId: parseId(entry.plaky_group_id, 'PLAKY_ITEM_GROUP_ID'),
    tier: entry.tier ?? config.defaults?.tier ?? 2,
    category: entry.category,
    plakyTable: entry.plaky_table
  };
}

export function listConfiguredRepos(): string[] {
  const config = loadReposYaml();
  return Object.keys(config.repos || {}).sort();
}

export function resetReposConfigCacheForTests(): void {
  cachedReposYaml = null;
}
