import { createLogger } from '@team-deepiri/shared-utils';
import { getGithubConfig } from './config';
import { githubRequest, githubPaginate } from './client';
import githubCache from './cache';

const logger = createLogger('github-service');

export interface RepoSummary {
  name: string;
  fullName: string;
  url: string;
  private: boolean;
  openIssues: number;
}

export interface ReviewSummary {
  login: string;
  state: string; // APPROVED | CHANGES_REQUESTED | COMMENTED | DISMISSED | PENDING
  submittedAt: string | null;
}

export interface PullSummary {
  id: number;
  number: number;
  title: string;
  url: string;
  repo: string;
  repoUrl: string;
  author: { login: string; avatarUrl: string | null };
  draft: boolean;
  createdAt: string;
  updatedAt: string;
  labels: string[];
  assignees: string[];
  requestedReviewers: string[];
  /**
   * Submitted reviews (who + APPROVED/CHANGES_REQUESTED/…). Populated only by
   * getPullDetail(); the /overview list leaves this empty to stay fast — use
   * `requestedReviewers` there for "who's on QA".
   */
  reviews: ReviewSummary[];
}

export interface MemberActivity {
  login: string;
  openPrs: Array<{ repo: string; number: number; title: string; url: string; draft: boolean }>;
  openPrCount: number;
  reviewRequested: Array<{ repo: string; number: number; title: string; url: string; author: string }>;
  reviewRequestedCount: number;
  /** PRs reviewed org-wide in the last 30 days, or null when not computed. */
  reviews30d: number | null;
}

export interface GithubOverview {
  generatedAt: string;
  org: string;
  repos: RepoSummary[];
  pulls: PullSummary[];
  members: Record<string, MemberActivity>;
  totals: { openPrs: number; awaitingReview: number; repos: number };
}

const OVERVIEW_KEY = 'overview:v2';
const lc = (s: string) => s.toLowerCase();
const daysAgoISODate = (days: number) =>
  new Date(Date.now() - days * 86400_000).toISOString().slice(0, 10);

/** Runs `fn` over `items` with at most `limit` promises in flight at once. */
async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  const worker = async () => {
    while (cursor < items.length) {
      const idx = cursor++;
      results[idx] = await fn(items[idx]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

const REPO_CONCURRENCY = 8;
const REVIEW_SEARCH_CONCURRENCY = 5;

async function listRepos(): Promise<RepoSummary[]> {
  const cfg = getGithubConfig()!;
  const raw = await githubPaginate<any>(`/orgs/${cfg.org}/repos`, {
    params: { type: 'all', sort: 'pushed' },
    maxPages: 10,
  });

  let kept = raw.filter((r) => !r.archived && !r.disabled);

  if (cfg.repoAllowList.length) {
    const allow = new Set(cfg.repoAllowList.map(lc));
    kept = kept.filter((r) => allow.has(lc(r.name)) || allow.has(lc(r.full_name)));
  } else {
    // No explicit list — trim to repos that are actually live: not a fork and
    // pushed to within GITHUB_REPO_ACTIVE_DAYS. Keeps /overview from fanning
    // out across dozens of dormant repos.
    const activeDays = Math.max(1, parseInt(process.env.GITHUB_REPO_ACTIVE_DAYS || '120', 10) || 120);
    const cutoff = Date.now() - activeDays * 86400_000;
    kept = kept.filter((r) => !r.fork && (Date.parse(r.pushed_at || '') || 0) >= cutoff);
  }

  return kept.map<RepoSummary>((r) => ({
    name: r.name,
    fullName: r.full_name,
    url: r.html_url,
    private: !!r.private,
    openIssues: r.open_issues_count ?? 0,
  }));
}

function mapPull(pr: any, repoName: string, repoUrl: string, reviews: ReviewSummary[] = []): PullSummary {
  return {
    id: pr.id,
    number: pr.number,
    title: pr.title,
    url: pr.html_url,
    repo: repoName,
    repoUrl,
    author: { login: pr.user?.login || 'unknown', avatarUrl: pr.user?.avatar_url || null },
    draft: !!pr.draft,
    createdAt: pr.created_at,
    updatedAt: pr.updated_at,
    labels: Array.isArray(pr.labels) ? pr.labels.map((l: any) => l.name).filter(Boolean) : [],
    assignees: Array.isArray(pr.assignees) ? pr.assignees.map((a: any) => a.login).filter(Boolean) : [],
    requestedReviewers: Array.isArray(pr.requested_reviewers)
      ? pr.requested_reviewers.map((u: any) => u.login).filter(Boolean)
      : [],
    reviews,
  };
}

async function listReviews(repoFullName: string, prNumber: number): Promise<ReviewSummary[]> {
  try {
    const rows = await githubPaginate<any>(`/repos/${repoFullName}/pulls/${prNumber}/reviews`, {
      maxPages: 3,
    });
    const latest = new Map<string, ReviewSummary>();
    for (const r of rows) {
      const login = r.user?.login;
      if (!login) continue;
      latest.set(lc(login), {
        login,
        state: r.state || 'COMMENTED',
        submittedAt: r.submitted_at || null,
      });
    }
    return [...latest.values()];
  } catch (err: any) {
    logger.warn('Failed to list PR reviews', { repoFullName, prNumber, error: err?.message });
    return [];
  }
}

/** Open PRs across all tracked repos. Reviewers come from `requested_reviewers`
 *  in the list payload — no extra call per PR. */
async function listOpenPulls(repos: RepoSummary[]): Promise<PullSummary[]> {
  const perRepo = await mapLimit(repos, REPO_CONCURRENCY, async (repo) => {
    try {
      const raw = await githubPaginate<any>(`/repos/${repo.fullName}/pulls`, {
        params: { state: 'open', sort: 'updated', direction: 'desc' },
        maxPages: 5,
      });
      return raw.map((pr) => mapPull(pr, repo.name, repo.url));
    } catch (err: any) {
      logger.warn('Failed to list pulls for repo', { repo: repo.fullName, error: err?.message });
      return [] as PullSummary[];
    }
  });
  return perRepo.flat();
}

/**
 * PRs the given login has reviewed org-wide in the last `days` days.
 * Cached per-login so callers passing different `logins` sets to /overview
 * share the sub-result and can't force a fresh Search API call per request.
 */
async function reviewsGiven(login: string, days = 30): Promise<number | null> {
  const cfg = getGithubConfig()!;
  return githubCache.getOrSet<number | null>(`rev30:${lc(login)}`, cfg.cacheTtlSeconds, async () => {
    try {
      const q = `type:pr org:${cfg.org} reviewed-by:${login} updated:>=${daysAgoISODate(days)}`;
      const { data } = await githubRequest<{ total_count: number }>(`/search/issues`, {
        params: { q, per_page: 1 },
      });
      return data.total_count ?? 0;
    } catch (err: any) {
      logger.warn('reviewsGiven search failed', { login, error: err?.message });
      return null;
    }
  });
}

function emptyMember(login: string): MemberActivity {
  return {
    login,
    openPrs: [],
    openPrCount: 0,
    reviewRequested: [],
    reviewRequestedCount: 0,
    reviews30d: null,
  };
}

function buildMembers(pulls: PullSummary[]): Record<string, MemberActivity> {
  const members: Record<string, MemberActivity> = {};
  const ensure = (login: string) => (members[lc(login)] ||= emptyMember(login));

  for (const pr of pulls) {
    const author = ensure(pr.author.login);
    author.openPrs.push({ repo: pr.repo, number: pr.number, title: pr.title, url: pr.url, draft: pr.draft });
    author.openPrCount++;

    for (const reviewer of pr.requestedReviewers) {
      const m = ensure(reviewer);
      m.reviewRequested.push({
        repo: pr.repo,
        number: pr.number,
        title: pr.title,
        url: pr.url,
        author: pr.author.login,
      });
      m.reviewRequestedCount++;
    }
  }
  return members;
}

/**
 * Full team GitHub picture for the People page. `logins` (Deepiri members'
 * GitHub usernames) get their 30-day review count computed; everyone else is
 * still listed from PR data with reviews30d = null.
 */
export async function getOverview(logins: string[] = []): Promise<GithubOverview> {
  const cfg = getGithubConfig();
  if (!cfg) throw new Error('GitHub App is not configured');

  const wanted = [...new Set(logins.map(lc))].filter(Boolean).sort();
  const cacheKey = `${OVERVIEW_KEY}:${wanted.join(',') || 'none'}`;

  return githubCache.getOrSet<GithubOverview>(cacheKey, cfg.cacheTtlSeconds, async () => {
    const repos = await listRepos();
    const pulls = await listOpenPulls(repos);
    const members = buildMembers(pulls);

    // 30-day review counts for linked members — one Search API call each,
    // capped concurrency to stay under the 30 req/min search limit.
    await mapLimit(wanted, REVIEW_SEARCH_CONCURRENCY, async (login) => {
      const m = (members[login] ||= emptyMember(login));
      m.reviews30d = await reviewsGiven(m.login, 30);
    });

    const awaitingReview = pulls.filter((p) => !p.draft && p.requestedReviewers.length > 0).length;

    return {
      generatedAt: new Date().toISOString(),
      org: cfg.org,
      repos,
      pulls,
      members,
      totals: { openPrs: pulls.length, awaitingReview, repos: repos.length },
    };
  });
}

export async function getMemberStats(login: string): Promise<MemberActivity> {
  const overview = await getOverview([login]);
  return overview.members[lc(login)] || emptyMember(login);
}

/** One PR with its submitted reviews resolved — the on-demand detail the
 *  /overview list omits. */
export async function getPullDetail(repoName: string, number: number): Promise<PullSummary> {
  const cfg = getGithubConfig();
  if (!cfg) throw new Error('GitHub App is not configured');
  const fullName = `${cfg.org}/${repoName}`;
  const cacheKey = `pull:v1:${lc(repoName)}:${number}`;

  return githubCache.getOrSet<PullSummary>(cacheKey, Math.min(cfg.cacheTtlSeconds, 300), async () => {
    const { data: pr } = await githubRequest<any>(`/repos/${fullName}/pulls/${number}`);
    const reviews = await listReviews(fullName, number);
    return mapPull(pr, repoName, pr.base?.repo?.html_url || `https://github.com/${fullName}`, reviews);
  });
}

export async function invalidate(): Promise<void> {
  await githubCache.invalidateAll();
}
