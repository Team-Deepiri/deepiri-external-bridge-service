import { createLogger } from '@team-deepiri/shared-utils';
import { getBoardmanConfig } from './boardmanConfig';
import { BoardmanMappingStore, getBoardmanMappingStore } from './boardmanMappingStore';
import { buildIssueExternalKey, extractLinkedIssueNumbers } from './githubPullRequestNormalizer';
import { fuzzyMatchBest } from './plakyNameMatch';
import { createPlakyClientForRepo } from './plakyClientFactory';
import { PlakySyncClient } from './plakySyncTypes';

const logger = createLogger('boardman-pr-task-linking');

const KEYWORD_PATTERN = /\b(?:fix(?:es)?|close[sd]?|resolve[sd]?)\s+#(\d+)\b/gi;

export interface PrLinkResolution {
  plakyItemId: number;
  method: 'mapping_store' | 'closing_keyword' | 'issue_hash' | 'fuzzy_title';
  confidence?: number;
}

export function extractClosingIssueNumbers(title?: string, body?: string, prNumber?: number): number[] {
  const found = new Set<number>();
  for (const text of [title, body]) {
    if (!text) continue;
    let match: RegExpExecArray | null;
    const pattern = new RegExp(KEYWORD_PATTERN.source, KEYWORD_PATTERN.flags);
    while ((match = pattern.exec(text)) !== null) {
      const issueNumber = Number(match[1]);
      if (Number.isInteger(issueNumber) && issueNumber > 0 && issueNumber !== prNumber) {
        found.add(issueNumber);
      }
    }
  }
  return [...found].sort((a, b) => a - b);
}

function getAutoLinkThreshold(): number {
  const raw = process.env.BOARDMAN_PR_AUTO_LINK_THRESHOLD;
  if (!raw) return 0.5;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 && parsed <= 1 ? parsed : 0.5;
}

export async function resolveLinkedPlakyItemsForPr(
  repoFullName: string,
  prNumber: number,
  prTitle: string,
  prBody: string | undefined,
  deps?: {
    mappingStore?: BoardmanMappingStore;
    client?: PlakySyncClient;
  }
): Promise<PrLinkResolution[]> {
  const mappingStore = deps?.mappingStore || getBoardmanMappingStore();
  const plakyClient = deps?.client ?? createPlakyClientForRepo(repoFullName).client;
  const config = getBoardmanConfig();
  const resolutions: PrLinkResolution[] = [];
  const seenItemIds = new Set<number>();

  const addResolution = (resolution: PrLinkResolution) => {
    if (seenItemIds.has(resolution.plakyItemId)) return;
    seenItemIds.add(resolution.plakyItemId);
    resolutions.push(resolution);
  };

  const storedPrItem = await mappingStore.getPrItemId(repoFullName, prNumber);
  if (storedPrItem) {
    addResolution({ plakyItemId: storedPrItem, method: 'mapping_store' });
  }

  const closingIssues = extractClosingIssueNumbers(prTitle, prBody, prNumber);
  const hashIssues = extractLinkedIssueNumbers([prTitle, prBody], [prNumber]);
  const issueNumbers = [...new Set([...closingIssues, ...hashIssues])];

  for (const issueNumber of issueNumbers) {
    const mapped = await mappingStore.getIssueItemId(repoFullName, issueNumber);
    if (mapped) {
      addResolution({ plakyItemId: mapped, method: 'mapping_store' });
      continue;
    }

    const externalKey = buildIssueExternalKey(repoFullName, issueNumber);
    const itemId = await plakyClient.findItemIdByExternalKey(
      config.plaky.externalFieldKey,
      externalKey,
      config.plaky.maxScanPages,
      config.plaky.pageSize
    );
    if (itemId !== null) {
      addResolution({ plakyItemId: itemId, method: closingIssues.includes(issueNumber) ? 'closing_keyword' : 'issue_hash' });
    }
  }

  if (resolutions.length > 0) {
    return resolutions;
  }

  if (!plakyClient.listItems) {
    return resolutions;
  }

  const items = await plakyClient.listItems(config.plaky.maxScanPages, config.plaky.pageSize);
  const fuzzy = fuzzyMatchBest(prTitle, items, (item) => item.title, getAutoLinkThreshold());
  if (fuzzy) {
    logger.info('Fuzzy PR to Plaky task match', {
      repo: repoFullName,
      pr_number: prNumber,
      plaky_item_id: fuzzy.match.id,
      score: fuzzy.score
    });
    addResolution({
      plakyItemId: fuzzy.match.id,
      method: 'fuzzy_title',
      confidence: fuzzy.score
    });
  }

  return resolutions;
}
