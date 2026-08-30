/**
 * Standalone smoke test for the GitHub module — no Express, no Kafka, no Redis.
 *
 *   cd ~/dev/deepiri-external-bridge-service-gh
 *   # put GITHUB_APP_ID / GITHUB_APP_INSTALLATION_ID / GITHUB_APP_PRIVATE_KEY_BASE64
 *   # (+ optional GITHUB_ORG) in .env
 *   npx ts-node --transpile-only scripts/gh-smoke.ts [login1 login2 ...]
 *
 * Delete this file before opening the PR (or keep it — your call).
 */
import * as dotenv from 'dotenv';
dotenv.config();

import { getGithubConfig } from '../src/github/config';
import { getInstallationToken } from '../src/github/appAuth';
import { getOverview } from '../src/github/service';

async function main() {
  const cfg = getGithubConfig();
  console.log('1. config:', cfg ? { org: cfg.org, allowList: cfg.repoAllowList, ttl: cfg.cacheTtlSeconds } : 'NOT CONFIGURED — set the GITHUB_APP_* vars in .env');
  if (!cfg) process.exit(1);

  const tok = await getInstallationToken();
  console.log('2. installation token minted:', tok ? `ok (${tok.length} chars, not shown)` : 'FAILED');

  const logins = process.argv.slice(2);
  console.log('3. fetching overview' + (logins.length ? ` with logins=${logins.join(',')}` : '') + ' …');
  const ov = await getOverview(logins);
  console.log('   totals:', ov.totals);
  console.log('   repos:', ov.repos.map((r) => r.name).join(', ') || '(none)');
  console.log('   first 3 open PRs:');
  for (const pr of ov.pulls.slice(0, 3)) {
    console.log(`     ${pr.repo}#${pr.number} "${pr.title}" by @${pr.author.login}` +
      `  reviewers=[${pr.requestedReviewers.join(',')}]  reviews=[${pr.reviews.map((r) => r.login + ':' + r.state).join(',')}]`);
  }
  for (const login of logins) {
    const m = ov.members[login.toLowerCase()];
    console.log(`   member ${login}:`, m ? { openPrs: m.openPrCount, reviewRequested: m.reviewRequestedCount, reviews30d: m.reviews30d } : '(no activity)');
  }
  process.exit(0);
}

main().catch((err) => {
  console.error('SMOKE FAILED:', err?.message || err);
  process.exit(1);
});
