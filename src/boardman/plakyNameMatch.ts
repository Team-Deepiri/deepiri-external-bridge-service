export function tokenSimilarity(left: string, right: string): number {
  const leftTokens = new Set(
    left.toLowerCase().split(/\W+/).filter((token) => token.length > 2)
  );
  const rightTokens = new Set(
    right.toLowerCase().split(/\W+/).filter((token) => token.length > 2)
  );

  if (leftTokens.size === 0 || rightTokens.size === 0) return 0;

  let overlap = 0;
  for (const token of leftTokens) {
    if (rightTokens.has(token)) overlap += 1;
  }

  return overlap / Math.max(leftTokens.size, rightTokens.size);
}

export function fuzzyMatchBest<T>(
  query: string,
  candidates: T[],
  getLabel: (candidate: T) => string,
  minimumScore = 0.45
): { match: T; score: number } | null {
  let best: { match: T; score: number } | null = null;

  for (const candidate of candidates) {
    const score = tokenSimilarity(query, getLabel(candidate));
    if (score < minimumScore) continue;
    if (!best || score > best.score) {
      best = { match: candidate, score };
    }
  }

  return best;
}
