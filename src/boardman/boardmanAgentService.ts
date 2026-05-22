import axios from 'axios';
import { createLogger } from '@team-deepiri/shared-utils';
import { GithubAppClient } from './githubAppClient';
import { filterActionableDirectionTasks, parseDirectionMarkdown } from './directionParser';
import { getRepoRouting, listConfiguredRepos } from './reposConfig';
import { optionalEnv } from './boardmanConfig';

const logger = createLogger('boardman-agent-service');

export interface AgentChatInput {
  message: string;
  repoFullName?: string;
  allowWrites?: boolean;
}

export interface AgentChatResult {
  reply: string;
  repoFullName?: string;
  suggestedTasks?: string[];
}

function buildOfflineReply(input: AgentChatInput, directionSummary: string): AgentChatResult {
  const repos = listConfiguredRepos();
  const lines = [
    'Boardman agent (read-only mode — set OPENAI_API_KEY for richer answers).',
    '',
    `Your message: ${input.message}`,
    '',
    repos.length > 0 ? `Configured repos: ${repos.join(', ')}` : 'No repos.yml entries yet; using env board fallback.',
    directionSummary ? `\nDIRECTION highlights:\n${directionSummary}` : '\nNo DIRECTION.md loaded for this repo.',
    '',
    'Suggested next steps:',
    '1. Confirm repos.yml board/group ids for this repo.',
    '2. Open or update the highest-priority GitHub issue.',
    '3. Run POST /api/v1/boardman/scan to generate a task proposal batch.',
    '4. Use synthesize → approve → apply before any bulk Plaky writes.'
  ];

  return { reply: lines.join('\n'), repoFullName: input.repoFullName };
}

export class BoardmanAgentService {
  constructor(private readonly githubClient: GithubAppClient = new GithubAppClient()) {}

  async chat(input: AgentChatInput): Promise<AgentChatResult> {
    const repoFullName = input.repoFullName?.trim();
    let directionSummary = '';

    if (repoFullName) {
      const routing = getRepoRouting(repoFullName);
      const markdown = await this.githubClient.fetchRepoFileText(repoFullName, 'DIRECTION.md');
      if (markdown) {
        const tasks = filterActionableDirectionTasks(parseDirectionMarkdown(repoFullName, markdown));
        directionSummary = tasks.slice(0, 5).map((task) => `- [ ] ${task.title} (${task.section})`).join('\n');
      }

      const apiKey = optionalEnv('OPENAI_API_KEY');
      if (!apiKey) {
        return buildOfflineReply(input, directionSummary);
      }

      const model = optionalEnv('OPENAI_MODEL') || 'gpt-4o-mini';
      const response = await axios.post(
        'https://api.openai.com/v1/chat/completions',
        {
          model,
          temperature: 0.3,
          messages: [
            {
              role: 'system',
              content:
                'You are Boardman, an engineering operations assistant. Be concise. Recommend actionable next steps. Never claim you wrote to Plaky unless allow_writes is true.'
            },
            {
              role: 'user',
              content: JSON.stringify({
                message: input.message,
                repoFullName,
                tier: routing.tier,
                allow_writes: Boolean(input.allowWrites),
                direction_tasks: directionSummary
              })
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

      const reply = response.data?.choices?.[0]?.message?.content || 'No response from model.';
      logger.info('Boardman agent chat completed', { repo: repoFullName });
      return {
        reply,
        repoFullName,
        suggestedTasks: directionSummary
          ? directionSummary.split('\n').map((line) => line.replace(/^- \[ \] /, ''))
          : undefined
      };
    }

    return buildOfflineReply(input, directionSummary);
  }
}
