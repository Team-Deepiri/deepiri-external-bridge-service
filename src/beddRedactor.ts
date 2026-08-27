import { spawn, ChildProcessWithoutNullStreams } from 'child_process';
import * as readline from 'readline';
import { createLogger } from '@team-deepiri/shared-utils';

const logger = createLogger('bedd-redactor');

/**
 * Redacts secret-shaped fields (tokens, client secrets, ...) out of
 * third-party webhook payloads before they're persisted to webhook_history.
 * Runs `bedd filter redact` as a single long-lived subprocess and pipes one
 * NDJSON line per payload through it — the "filter" pattern from Bedd's own
 * docs (no extra consumer group, no per-call spawn cost).
 *
 * Fails open: if Bedd is unavailable, unresponsive, or errors, the original
 * payload is returned unchanged rather than blocking webhook ingestion.
 */
class BeddRedactor {
  private proc: ChildProcessWithoutNullStreams | null = null;
  private pending: Array<(line: string) => void> = [];
  private enabled: boolean;

  constructor() {
    this.enabled = process.env.BEDD_REDACT_ENABLED !== 'false';
    if (this.enabled) this.spawnProcess();
  }

  private spawnProcess(): void {
    try {
      const proc = spawn('bedd', ['filter', 'redact'], { stdio: ['pipe', 'pipe', 'pipe'] });
      this.proc = proc;

      readline.createInterface({ input: proc.stdout }).on('line', line => {
        const resolve = this.pending.shift();
        if (resolve) resolve(line);
      });

      proc.stderr.on('data', chunk => {
        logger.warn('bedd filter redact stderr', { message: chunk.toString().trim() });
      });

      proc.on('error', err => {
        logger.warn('bedd filter redact failed to start; redaction disabled', { error: err?.message });
        this.proc = null;
        this.drainPending();
      });

      proc.on('exit', code => {
        logger.warn('bedd filter redact exited; redaction disabled', { code });
        this.proc = null;
        this.drainPending();
      });
    } catch (err: any) {
      logger.warn('Failed to spawn bedd filter redact; redaction disabled', { error: err?.message });
      this.proc = null;
    }
  }

  private drainPending(): void {
    while (this.pending.length) {
      const resolve = this.pending.shift();
      resolve?.('');
    }
  }

  async redact<T>(payload: T, timeoutMs = 200): Promise<T> {
    if (!this.enabled || !this.proc || !this.proc.stdin.writable) return payload;

    return new Promise<T>(resolve => {
      const timer = setTimeout(() => {
        const idx = this.pending.indexOf(onLine);
        if (idx >= 0) this.pending.splice(idx, 1);
        resolve(payload);
      }, timeoutMs);

      const onLine = (line: string): void => {
        clearTimeout(timer);
        if (!line) {
          resolve(payload);
          return;
        }
        try {
          resolve(JSON.parse(line));
        } catch {
          resolve(payload);
        }
      };

      this.pending.push(onLine);
      try {
        this.proc!.stdin.write(JSON.stringify(payload) + '\n');
      } catch (err: any) {
        clearTimeout(timer);
        this.pending.pop();
        logger.warn('bedd filter redact write failed', { error: err?.message });
        resolve(payload);
      }
    });
  }
}

export default new BeddRedactor();
