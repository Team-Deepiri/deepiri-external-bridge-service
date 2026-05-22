import { createLogger } from '@team-deepiri/shared-utils';
import {
  filterActionableDirectionTasks,
  parseDirectionMarkdown
} from './directionParser';
import { applyDirectionTasksToPlaky } from './directionTaskSync';
import { PlakySyncClient } from './plakySyncTypes';
import {
  AssistantProposal,
  AssistantProposalStore,
  getAssistantProposalStore
} from './assistantProposalStore';
import { GithubAppClient } from './githubAppClient';

const logger = createLogger('boardman-assistant-service');
const DEFAULT_DIRECTION_PATH = 'DIRECTION.md';

export interface SynthesizeDirectionInput {
  repoFullName: string;
  directionMarkdown?: string;
  directionPath?: string;
  ref?: string;
}

export class BoardmanAssistantService {
  constructor(
    private readonly proposalStore: AssistantProposalStore = getAssistantProposalStore(),
    private readonly githubClient: GithubAppClient = new GithubAppClient(),
    private readonly plakyClientOverride?: PlakySyncClient
  ) {}

  async synthesize(input: SynthesizeDirectionInput): Promise<AssistantProposal> {
    const repoFullName = input.repoFullName.trim();
    if (!repoFullName.includes('/')) {
      throw new Error('repoFullName must be in owner/repo format');
    }

    let markdown = input.directionMarkdown?.trim() || '';
    if (!markdown) {
      const directionPath = input.directionPath?.trim() || DEFAULT_DIRECTION_PATH;
      const fetched = await this.githubClient.fetchRepoFileText(repoFullName, directionPath, input.ref);
      if (!fetched) {
        throw new Error(`DIRECTION file not found at ${directionPath}`);
      }
      markdown = fetched;
    }

    const parsed = parseDirectionMarkdown(repoFullName, markdown);
    const actionable = filterActionableDirectionTasks(parsed);
    const proposal = await this.proposalStore.create(repoFullName, actionable);

    logger.info('Created DIRECTION synthesis proposal', {
      proposal_id: proposal.proposalId,
      repo: repoFullName,
      task_count: actionable.length
    });

    return proposal;
  }

  async approve(proposalId: string): Promise<AssistantProposal> {
    const approved = await this.proposalStore.approve(proposalId);
    if (!approved) {
      throw new Error('Proposal not found');
    }
    return approved;
  }

  async apply(proposalId: string): Promise<{
    proposal: AssistantProposal;
    applied: Awaited<ReturnType<typeof applyDirectionTasksToPlaky>>;
  }> {
    const proposal = await this.proposalStore.get(proposalId);
    if (!proposal) {
      throw new Error('Proposal not found');
    }
    if (proposal.status === 'applied') {
      throw new Error('Proposal has already been applied');
    }
    if (proposal.status !== 'approved') {
      throw new Error('Proposal must be approved before apply');
    }

    const applied = await applyDirectionTasksToPlaky(
      proposal.repoFullName,
      proposal.tasks,
      this.plakyClientOverride
    );
    const updated = await this.proposalStore.markApplied(proposalId);
    if (!updated) {
      throw new Error('Proposal not found after apply');
    }

    logger.info('Applied DIRECTION synthesis proposal', {
      proposal_id: proposalId,
      repo: proposal.repoFullName,
      applied_count: applied.length
    });

    return { proposal: updated, applied };
  }
}
