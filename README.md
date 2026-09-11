# External Bridge Service

Manages external service integrations and third-party API connections.

## Responsibilities
- External API integrations (Notion, Trello, GitHub)
- OAuth flows
- Webhook management
- Data synchronization

## Endpoints
- `GET /integrations`
- `POST /integrations/connect`
- `POST /integrations/sync`
- `DELETE /integrations/:id`

### GitHub team activity (portal People page)

Read-only view of org pull-request activity, backed by a GitHub App and a Redis
TTL cache (busted by inbound `pull_request` / `pull_request_review` webhooks).
Exposed through the gateway at `/api/integrations/github/*` (portal-user auth
required there).

- `GET /github/status` — `{ configured, org, repoAllowList, cacheTtlSeconds }`
- `GET /github/overview?logins=a,b,c` — every open PR across the tracked repos with
  author, assignees and requested reviewers, plus a per-login rollup. `logins`
  (Deepiri members' GitHub usernames) additionally get a 30-day "reviews given"
  count. For speed the list does **not** resolve submitted reviews per PR — use
  `requested_reviewers` for "who's on QA", or the PR-detail endpoint below.
- `GET /github/pulls?repo=<name>` — flat open-PR list, optionally one repo.
- `GET /github/pulls/:repo/:number` — one PR with submitted reviews resolved
  (`APPROVED` / `CHANGES_REQUESTED` / … per reviewer). Fetched on demand.
- `GET /github/members/:login/stats` — one member's open PRs, review requests and
  30-day review count.
- `POST /github/refresh` — drop the cache (ops / manual).

Repo fan-out is bounded (8 repos in flight). Set **`GITHUB_REPOS`** to the active
product repos so `/overview` stays fast; otherwise auto-discovery keeps non-fork
repos pushed within `GITHUB_REPO_ACTIVE_DAYS` (default 120).

Configure via the `GITHUB_APP_*` / `GITHUB_ORG` / `GITHUB_REPOS` vars in
`.env.example`. When unset, the endpoints return `503 { notConfigured: true }`.

**Webhook cache-busting (optional).** Point the GitHub App's webhook at
`<gateway>/api/integrations/webhooks/github` (the gateway forwards these with the
body untouched) or straight at this service's `/webhooks/github`, subscribed to
*Pull request* and *Pull request review*. Set `GITHUB_WEBHOOK_SECRET` to the same
value as the App's webhook secret — deliveries are then HMAC-verified
(`X-Hub-Signature-256` over the raw body) and rejected with `401` on mismatch. If
`GITHUB_WEBHOOK_SECRET` is empty the deliveries are accepted unverified (a
warning is logged once) so the cache TTL still bounds staleness either way.

## Current Implementation
See `deepiri-core-api/services/integrationService.js` and `deepiri-core-api/routes/integrationRoutes.js`

## Migration
Extract from `deepiri-core-api/` to this independent service.

