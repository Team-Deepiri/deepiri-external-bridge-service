import { createClient, RedisClientType } from 'redis';
import { v4 as uuidv4 } from 'uuid';
import { DirectionTaskProposal } from './directionParser';

export type AssistantProposalStatus = 'pending' | 'approved' | 'applied';

export interface AssistantProposal {
  proposalId: string;
  repoFullName: string;
  tasks: DirectionTaskProposal[];
  status: AssistantProposalStatus;
  createdAt: string;
  approvedAt?: string;
  appliedAt?: string;
}

export interface AssistantProposalStore {
  create(repoFullName: string, tasks: DirectionTaskProposal[]): Promise<AssistantProposal>;
  get(proposalId: string): Promise<AssistantProposal | null>;
  approve(proposalId: string): Promise<AssistantProposal | null>;
  markApplied(proposalId: string): Promise<AssistantProposal | null>;
}

const PROPOSAL_TTL_SECONDS = 60 * 60;

function proposalKey(proposalId: string): string {
  return `boardman:proposal:${proposalId}`;
}

export class RedisAssistantProposalStore implements AssistantProposalStore {
  private readonly redisClient: RedisClientType;

  constructor(redisClient?: RedisClientType) {
    this.redisClient = redisClient || (createClient({
      url: `redis://:${process.env.REDIS_PASSWORD || ''}@${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || '6379'}`
    }) as RedisClientType);

    if (!redisClient) {
      this.redisClient.connect().catch(() => undefined);
    }
  }

  async create(repoFullName: string, tasks: DirectionTaskProposal[]): Promise<AssistantProposal> {
    const proposal: AssistantProposal = {
      proposalId: uuidv4(),
      repoFullName,
      tasks,
      status: 'pending',
      createdAt: new Date().toISOString()
    };

    await this.redisClient.set(proposalKey(proposal.proposalId), JSON.stringify(proposal), {
      EX: PROPOSAL_TTL_SECONDS
    });
    return proposal;
  }

  async get(proposalId: string): Promise<AssistantProposal | null> {
    const raw = await this.redisClient.get(proposalKey(proposalId));
    if (!raw) return null;
    return JSON.parse(raw) as AssistantProposal;
  }

  async approve(proposalId: string): Promise<AssistantProposal | null> {
    const proposal = await this.get(proposalId);
    if (!proposal) return null;
    if (proposal.status === 'applied') return proposal;

    const updated: AssistantProposal = {
      ...proposal,
      status: 'approved',
      approvedAt: new Date().toISOString()
    };
    await this.redisClient.set(proposalKey(proposalId), JSON.stringify(updated), {
      EX: PROPOSAL_TTL_SECONDS
    });
    return updated;
  }

  async markApplied(proposalId: string): Promise<AssistantProposal | null> {
    const proposal = await this.get(proposalId);
    if (!proposal) return null;

    const updated: AssistantProposal = {
      ...proposal,
      status: 'applied',
      appliedAt: new Date().toISOString()
    };
    await this.redisClient.set(proposalKey(proposalId), JSON.stringify(updated), {
      EX: PROPOSAL_TTL_SECONDS
    });
    return updated;
  }
}

export class InMemoryAssistantProposalStore implements AssistantProposalStore {
  private readonly proposals = new Map<string, AssistantProposal>();

  async create(repoFullName: string, tasks: DirectionTaskProposal[]): Promise<AssistantProposal> {
    const proposal: AssistantProposal = {
      proposalId: uuidv4(),
      repoFullName,
      tasks,
      status: 'pending',
      createdAt: new Date().toISOString()
    };
    this.proposals.set(proposal.proposalId, proposal);
    return proposal;
  }

  async get(proposalId: string): Promise<AssistantProposal | null> {
    return this.proposals.get(proposalId) || null;
  }

  async approve(proposalId: string): Promise<AssistantProposal | null> {
    const proposal = await this.get(proposalId);
    if (!proposal) return null;
    if (proposal.status === 'applied') return proposal;

    const updated: AssistantProposal = {
      ...proposal,
      status: 'approved',
      approvedAt: new Date().toISOString()
    };
    this.proposals.set(proposalId, updated);
    return updated;
  }

  async markApplied(proposalId: string): Promise<AssistantProposal | null> {
    const proposal = await this.get(proposalId);
    if (!proposal) return null;

    const updated: AssistantProposal = {
      ...proposal,
      status: 'applied',
      appliedAt: new Date().toISOString()
    };
    this.proposals.set(proposalId, updated);
    return updated;
  }

  clearForTests(): void {
    this.proposals.clear();
  }
}

let defaultStore: AssistantProposalStore | null = null;

export function getAssistantProposalStore(): AssistantProposalStore {
  if (!defaultStore) {
    defaultStore = new RedisAssistantProposalStore();
  }
  return defaultStore;
}

export function setAssistantProposalStoreForTests(store: AssistantProposalStore | null): void {
  defaultStore = store;
}
