import { createClient, RedisClientType } from 'redis';
import { createLogger } from '@team-deepiri/shared-utils';

const logger = createLogger('github-cache');

const KEY_PREFIX = 'gh:';

/**
 * Thin Redis-backed JSON cache for computed GitHub payloads. Redis is
 * best-effort: if it is down we simply recompute every time rather than fail
 * the request.
 */
class GithubCache {
  private client: RedisClientType;
  private ready = false;

  constructor() {
    this.client = createClient({
      url: `redis://:${process.env.REDIS_PASSWORD || ''}@${process.env.REDIS_HOST || 'localhost'}:${
        process.env.REDIS_PORT || '6379'
      }`,
    }) as RedisClientType;

    this.client.on('error', (err) =>
      logger.warn('GitHub cache Redis error', { error: err?.message })
    );
    this.client
      .connect()
      .then(() => {
        this.ready = true;
      })
      .catch((err) => logger.warn('GitHub cache Redis connect failed', { error: err?.message }));
  }

  private full(key: string): string {
    return `${KEY_PREFIX}${key}`;
  }

  async get<T>(key: string): Promise<T | null> {
    if (!this.ready) return null;
    try {
      const raw = await this.client.get(this.full(key));
      return raw ? (JSON.parse(raw) as T) : null;
    } catch (err: any) {
      logger.warn('GitHub cache get failed', { key, error: err?.message });
      return null;
    }
  }

  async set(key: string, value: unknown, ttlSeconds: number): Promise<void> {
    if (!this.ready) return;
    try {
      await this.client.set(this.full(key), JSON.stringify(value), { EX: ttlSeconds });
    } catch (err: any) {
      logger.warn('GitHub cache set failed', { key, error: err?.message });
    }
  }

  async getOrSet<T>(key: string, ttlSeconds: number, producer: () => Promise<T>): Promise<T> {
    const hit = await this.get<T>(key);
    if (hit !== null) return hit;
    const fresh = await producer();
    await this.set(key, fresh, ttlSeconds);
    return fresh;
  }

  /** Drops every gh:* key. Called on relevant inbound GitHub webhooks. */
  async invalidateAll(): Promise<void> {
    if (!this.ready) return;
    try {
      let cursor = 0;
      do {
        const res = await this.client.scan(cursor, { MATCH: `${KEY_PREFIX}*`, COUNT: 200 });
        cursor = res.cursor;
        if (res.keys.length) await this.client.del(res.keys);
      } while (cursor !== 0);
      logger.info('GitHub cache invalidated');
    } catch (err: any) {
      logger.warn('GitHub cache invalidateAll failed', { error: err?.message });
    }
  }
}

const githubCache = new GithubCache();
export default githubCache;
