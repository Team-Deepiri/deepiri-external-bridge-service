# Boardman Rollout Runbook

## 1. Required Credentials
- `GITHUB_APP_ID`
- `GITHUB_APP_PRIVATE_KEY`
- `GITHUB_WEBHOOK_SECRET`
- `GITHUB_INSTALLATION_ID`
- `GITHUB_ORG`
- `PLAKY_API_KEY`
- `PLAKY_BASE_URL`
- `PLAKY_WORKSPACE_ID`
- `PLAKY_BOARD_ID`
- `PLAKY_ITEM_GROUP_ID`
- `PLAKY_FIELD_EXTERNAL_KEY_ID`
- `PLAKY_FIELD_GITHUB_URL_ID`
- `PLAKY_FIELD_REPO_ID`
- `PLAKY_FIELD_STATUS_ID`
- `PLAKY_FIELD_PR_URL_ID`
- `PLAKY_FIELD_MERGE_STATE_ID`
- `PLAKY_STATUS_OPEN_VALUE`
- `PLAKY_STATUS_CLOSED_VALUE`
- `PLAKY_MERGE_STATE_OPEN_VALUE`
- `PLAKY_MERGE_STATE_MERGED_VALUE`
- `PLAKY_MERGE_STATE_CLOSED_VALUE`
- `PLAKY_MERGE_STATE_DRAFT_VALUE`
- `ROUTE_SECRET`

## 2. Rotation Workflow
1. Generate new GitHub App private key and webhook secret.
2. Generate new Plaky API key dedicated to Boardman automation.
3. Update runtime secret store first (not repo files).
4. Restart `external-bridge-service` and `external-bridge-worker`.
5. Verify `/health` endpoints before traffic.
6. Revoke old GitHub key, old webhook secret, and old Plaky key.

## 3. Local Smoke Test
1. Start dependencies and services:
```bash
docker compose -f docker-compose.dev.yml up -d kafka redis external-bridge-service external-bridge-worker
```
2. Run readiness status and env preflight:
```bash
npm run boardman:status
npm run boardman:preflight
```
3. Verify health:
```bash
curl -f http://localhost:5006/health
docker exec deepiri-external-bridge-worker-dev curl -f http://localhost:5007/health
```
4. Send one signed GitHub `issues` webhook payload:
```bash
GITHUB_WEBHOOK_SECRET=... npm run boardman:smoke-webhook
```
5. Replay the same GitHub delivery id.
6. Confirm exactly one Plaky item exists for:
`github:issue:<owner>/<repo>#<number>`.

## 4. Queue Failure Behavior (Reliability Guardrail)
1. Temporarily stop Kafka.
2. Send a signed GitHub webhook event.
3. Confirm API returns HTTP `503` with `status: retry`.
4. Restart Kafka and resend the same delivery id.
5. Confirm event is accepted and only one Plaky item exists (no duplicate).

## 5. PR Linkage Smoke Test
1. Ensure a Plaky item already exists for `github:issue:<owner>/<repo>#<number>`.
2. Open or update a PR whose title/body references that issue (`#<number>`).
3. Confirm the issue Plaky item gets PR URL + merge-state fields updated.
4. Merge or close the PR and confirm merge-state updates again without creating a duplicate issue item.

## 6. DIRECTION.md Assistant Flow
1. Add repo-root `DIRECTION.md` with unchecked tasks (`- [ ] ...`) under `##` sections.
2. Synthesize (does not write to Plaky yet):
```bash
curl -sS -X POST http://localhost:5006/boardman/assistant/synthesize \
  -H "Content-Type: application/json" \
  -H "X-Boardman-Route-Secret: $ROUTE_SECRET" \
  -d '{"repoFullName":"Team-Deepiri/boardman","directionMarkdown":"## Sprint\n- [ ] Ship PR linkage"}'
```
3. Approve proposal:
```bash
curl -sS -X POST http://localhost:5006/boardman/assistant/approve \
  -H "Content-Type: application/json" \
  -H "X-Boardman-Route-Secret: $ROUTE_SECRET" \
  -d '{"proposalId":"<proposal-id-from-synthesize>"}'
```
4. Apply proposal (idempotent upsert by `github:direction:<repo>#<hash>`):
```bash
curl -sS -X POST http://localhost:5006/boardman/assistant/apply \
  -H "Content-Type: application/json" \
  -H "X-Boardman-Route-Secret: $ROUTE_SECRET" \
  -d '{"proposalId":"<proposal-id-from-synthesize>"}'
```
5. Re-run apply with the same `proposalId` and confirm it is rejected after the first successful apply.

## 7. Rollback
1. Stop worker:
```bash
docker compose -f docker-compose.dev.yml stop external-bridge-worker
```
2. Restore previous secrets and restart API/worker.
3. Re-run smoke test before resuming webhook traffic.

## 8. Wave-One VPS Compose
1. Copy `.env.boardman.production.example` to `.env.boardman.production`.
2. Fill only rotated production credentials and real Plaky/GitHub IDs.
3. Start the Boardman-only stack:
```bash
docker compose --env-file .env.boardman.production -f docker-compose.boardman.yml up -d --build
```
4. Run readiness status with health checks:
```bash
npm run boardman:status -- --check-health
```
