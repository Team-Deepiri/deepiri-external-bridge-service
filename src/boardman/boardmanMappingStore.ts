import { createClient, RedisClientType } from 'redis';

export interface BoardmanMappingStore {
  getIssueItemId(repoFullName: string, issueNumber: number): Promise<number | null>;
  setIssueItemId(repoFullName: string, issueNumber: number, plakyItemId: number): Promise<void>;
  getPrItemId(repoFullName: string, prNumber: number): Promise<number | null>;
  setPrItemId(repoFullName: string, prNumber: number, plakyItemId: number): Promise<void>;
}

function issueKey(repoFullName: string, issueNumber: number): string {
  return `boardman:issue:${repoFullName}#${issueNumber}`;
}

function prKey(repoFullName: string, prNumber: number): string {
  return `boardman:pr:${repoFullName}#${prNumber}`;
}

export class RedisBoardmanMappingStore implements BoardmanMappingStore {
  private readonly redisClient: RedisClientType;

  constructor(redisClient?: RedisClientType) {
    this.redisClient = redisClient || (createClient({
      url: `redis://:${process.env.REDIS_PASSWORD || ''}@${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || '6379'}`
    }) as RedisClientType);

    if (!redisClient) {
      this.redisClient.connect().catch(() => undefined);
    }
  }

  async getIssueItemId(repoFullName: string, issueNumber: number): Promise<number | null> {
    const raw = await this.redisClient.get(issueKey(repoFullName, issueNumber));
    return raw ? Number(raw) : null;
  }

  async setIssueItemId(repoFullName: string, issueNumber: number, plakyItemId: number): Promise<void> {
    await this.redisClient.set(issueKey(repoFullName, issueNumber), String(plakyItemId));
  }

  async getPrItemId(repoFullName: string, prNumber: number): Promise<number | null> {
    const raw = await this.redisClient.get(prKey(repoFullName, prNumber));
    return raw ? Number(raw) : null;
  }

  async setPrItemId(repoFullName: string, prNumber: number, plakyItemId: number): Promise<void> {
    await this.redisClient.set(prKey(repoFullName, prNumber), String(plakyItemId));
  }
}

export class InMemoryBoardmanMappingStore implements BoardmanMappingStore {
  private readonly issueMap = new Map<string, number>();
  private readonly prMap = new Map<string, number>();

  async getIssueItemId(repoFullName: string, issueNumber: number): Promise<number | null> {
    return this.issueMap.get(issueKey(repoFullName, issueNumber)) ?? null;
  }

  async setIssueItemId(repoFullName: string, issueNumber: number, plakyItemId: number): Promise<void> {
    this.issueMap.set(issueKey(repoFullName, issueNumber), plakyItemId);
  }

  async getPrItemId(repoFullName: string, prNumber: number): Promise<number | null> {
    return this.prMap.get(prKey(repoFullName, prNumber)) ?? null;
  }

  async setPrItemId(repoFullName: string, prNumber: number, plakyItemId: number): Promise<void> {
    this.prMap.set(prKey(repoFullName, prNumber), plakyItemId);
  }

  clearForTests(): void {
    this.issueMap.clear();
    this.prMap.clear();
  }
}

let defaultStore: BoardmanMappingStore | null = null;

export function getBoardmanMappingStore(): BoardmanMappingStore {
  if (!defaultStore) {
    defaultStore = new RedisBoardmanMappingStore();
  }
  return defaultStore;
}

export function setBoardmanMappingStoreForTests(store: BoardmanMappingStore | null): void {
  defaultStore = store;
}
