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

## Current Implementation
See `deepiri-core-api/services/integrationService.js` and `deepiri-core-api/routes/integrationRoutes.js`

## Migration
Extract from `deepiri-core-api/` to this independent service.

## Boardman Worker Env Contract
- Required non-secret settings live in `/Users/kyle/Deepiri/deepiri-platform/ops/k8s/configmaps/external-bridge-service-configmap.yaml`.
- Required secret and local-env placeholders live in `/Users/kyle/Deepiri/deepiri-platform/.env.example`.
- `src/worker.ts` now fails fast at startup if required Boardman env vars are missing.
- Webhook ingestion now returns `503` when Kafka publish fails so upstream retries are triggered instead of silently dropping events.
- Run `npm run boardman:status` to see the current readiness gates without exposing secret values.
- Run `npm run boardman:preflight` before deploys to validate required env vars.
- Run `GITHUB_WEBHOOK_SECRET=... npm run boardman:smoke-webhook` for a signed local GitHub webhook smoke test.

## Boardman (GitHub ↔ Plaky)

See `BOARDMAN_SETUP.md` and `BOARDMAN_ROLLOUT_RUNBOOK.md`.

- Per-repo routing: `config/repos.yml`
- QA roster: `config/team_assignments.yml`
- Issue/PR/review/comment webhooks → worker
- Redis mappings for issue/PR → Plaky item ids

## Boardman API (ROUTE_SECRET)
- `POST /boardman/assistant/synthesize` — parse `DIRECTION.md` (body or GitHub fetch) into a proposal
- `POST /boardman/assistant/approve` — approve a proposal before apply
- `POST /boardman/assistant/apply` — upsert approved tasks into Plaky (non-duplicative by external key)

Send `X-Boardman-Route-Secret: <ROUTE_SECRET>` or `Authorization: Bearer <ROUTE_SECRET>`.

## Boardman Wave-One Docker Compose

For the minimum VPS deployment path:

```bash
cp .env.boardman.production.example .env.boardman.production
# Fill only rotated production values.
docker compose --env-file .env.boardman.production -f docker-compose.boardman.yml up -d --build
npm run boardman:status -- --check-health
```

