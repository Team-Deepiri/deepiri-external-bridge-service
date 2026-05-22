import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';
import { getBoardmanConfigDir } from './reposConfig';

export interface QaAssignee {
  name: string;
  plaky_user_id: number;
  github_login?: string;
  weight: number;
  tiers?: number[];
}

export interface TeamAssignmentsYaml {
  qa_assignees?: QaAssignee[];
}

let cachedAssignments: TeamAssignmentsYaml | null = null;

export function loadTeamAssignments(forceReload = false): TeamAssignmentsYaml {
  if (cachedAssignments && !forceReload) return cachedAssignments;

  const configPath = path.join(getBoardmanConfigDir(), 'team_assignments.yml');
  if (!fs.existsSync(configPath)) {
    cachedAssignments = { qa_assignees: [] };
    return cachedAssignments;
  }

  const raw = fs.readFileSync(configPath, 'utf8');
  cachedAssignments = (yaml.load(raw) as TeamAssignmentsYaml) || { qa_assignees: [] };
  return cachedAssignments;
}

export function resetTeamAssignmentsCacheForTests(): void {
  cachedAssignments = null;
}
