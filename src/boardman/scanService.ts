import axios from 'axios';
import { createLogger } from '@team-deepiri/shared-utils';
import { GithubAppClient } from './githubAppClient';
import {
  filterActionableDirectionTasks,
  parseDirectionMarkdown
} from './directionParser';
import { getRepoRouting } from './reposConfig';
import { optionalEnv } from './boardmanConfig';
import { applyDirectionTasksToPlaky } from './directionTaskSync';
import { getAssistantProposalStore } from './assistantProposalStore';

const logger = createLogger('boardman-scan-service');

export interface ScanTaskProposal {
  title: string;
  rationale: string;
  externalKey?: string;
}

export interface ScanResult {
  repoFullName: string;
  proposalId?: string;
  directionTasks: ScanTaskProposal[];
  applied?: boolean;
}

async function callScanLlm(repoFullName: string, context: string): Promise<ScanTaskProposal[]> {
  const apiKey = optionalEnv('OPENAI_API_KEY');
  if (!apiKey) {
    const directionOnly = parseDirectionMarkdown(repoFullName, context);
    return filterActionableDirectionTasks(directionOnly).map((task) => ({
      title: task.title,
      rationale: `From DIRECTION.md section ${task.section}`,
      externalKey: task.externalKey
    }));
  }

  const model = optionalEnv('OPENAI_MODEL') || 'gpt-4o-mini';
  const response = await axios.post(
    'https://api.openai.com/v1/chat/completions',
    {
      model,
      temperature: 0.2,
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content:
            'You are Boardman, a project operations assistant. Return JSON: {"tasks":[{"title":"...","rationale":"..."}]}. Only actionable engineering tasks, max 8.'
        },
        {
          role: 'user',
          content: `Repository: ${repoFullName}\n\nContext:\n${context.slice(0, 12000)}`
        }
      ]
    },
    {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      timeout: 45000
    }
  );

  const content = response.data?.choices?.[0]?.message?.content;
  if (!content) return [];

  const parsed = JSON.parse(content) as { tasks?: ScanTaskProposal[] };
  return Array.isArray(parsed.tasks) ? parsed.tasks.slice(0, 8) : [];
}

export class BoardmanScanService {
  constructor(private readonly githubClient: GithubAppClient = new GithubAppClient()) {}

  async scanRepository(input: {
    repoFullName: string;
    allowWrites?: boolean;
    directionPath?: string;
  }): Promise<ScanResult> {
    const repoFullName = input.repoFullName.trim();
    const routing = getRepoRouting(repoFullName);

    const directionMarkdown =
      (await this.githubClient.fetchRepoFileText(
        repoFullName,
        input.directionPath || 'DIRECTION.md'
      )) || '';

    const contextParts = [
      `Repo routing tier: ${routing.tier}`,
      directionMarkdown ? `DIRECTION.md:\n${directionMarkdown}` : 'DIRECTION.md: (missing)'
    ];

    const llmTasks = await callScanLlm(repoFullName, contextParts.join('\n\n'));
    const directionTasks = parseDirectionMarkdown(repoFullName, directionMarkdown);
    const actionable = filterActionableDirectionTasks(directionTasks);

    const mergedTitles = new Set<string>();
    const proposals: ScanTaskProposal[] = [];

    for (const task of llmTasks) {
      if (!task.title || mergedTitles.has(task.title)) continue;
      mergedTitles.add(task.title);
      proposals.push(task);
    }

    for (const task of actionable) {
      if (mergedTitles.has(task.title)) continue;
      mergedTitles.add(task.title);
      proposals.push({
        title: task.title,
        rationale: `DIRECTION.md (${task.section})`,
        externalKey: task.externalKey
      });
    }

    const result: ScanResult = {
      repoFullName,
      directionTasks: proposals
    };

    if (!input.allowWrites) {
      const proposal = await getAssistantProposalStore().create(repoFullName, actionable);
      result.proposalId = proposal.proposalId;
      return result;
    }

    if (actionable.length > 0) {
      await applyDirectionTasksToPlaky(repoFullName, actionable);
      result.applied = true;
    }

    logger.info('Completed Boardman repository scan', {
      repo: repoFullName,
      task_count: proposals.length,
      applied: Boolean(result.applied)
    });

    return result;
  }
}
