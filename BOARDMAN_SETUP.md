# Boardman setup (external-bridge)

Boardman runs inside `deepiri-external-bridge-service` (API + worker).

## 1. Copy config

```bash
cd platform-services/backend/deepiri-external-bridge-service
cp config/repos.yml.example config/repos.yml
cp config/team_assignments.yml.example config/team_assignments.yml
```

Fill **Plaky board id** and **group id** per repo after your board reorg.

## 2. Environment

See platform `.env.example` Boardman section. Required for worker:

- GitHub App + webhook secret
- Plaky API + field ids + status values
- `ROUTE_SECRET` for assistant/API routes

Optional workflow columns:

- `PLAKY_NEEDS_QA_STATUS`, `PLAKY_IN_QA_STATUS`, `PLAKY_PR_MERGE_STATUS`
- `PLAKY_FIELD_QA_ASSIGNEE_ID` + `team_assignments.yml`

## 3. GitHub App webhooks

Subscribe: **Issues**, **Pull requests**, **Pull request reviews**, **Issue comments**.

## 4. API (ROUTE_SECRET)

| Method | Path |
|--------|------|
| GET | `/api/v1/boardman/repos` |
| GET | `/api/v1/boardman/plaky/boards/match?q=` |
| POST | `/api/v1/boardman/agent/chat` |
| POST | `/api/v1/boardman/agent/scan` |
| POST | `/api/v1/boardman/assistant/synthesize` |
| POST | `/api/v1/boardman/assistant/approve` |
| POST | `/api/v1/boardman/assistant/apply` |

Legacy paths remain: `/boardman/assistant/*`

Header: `X-Boardman-Route-Secret: <ROUTE_SECRET>`

## 5. Verify

```bash
npm run boardman:status
npm run boardman:preflight
npm test
docker compose -f docker-compose.dev.yml up -d external-bridge-service external-bridge-worker
```

For wave-one VPS/Docker Compose deployment, copy
`.env.boardman.production.example` to `.env.boardman.production`, fill only
rotated production values, and start the Boardman-only stack:

```bash
docker compose --env-file .env.boardman.production -f docker-compose.boardman.yml up -d --build
npm run boardman:status -- --check-health
```
