#!/usr/bin/env bash
set -euo pipefail

required_vars=(
  GITHUB_APP_ID
  GITHUB_APP_PRIVATE_KEY
  GITHUB_WEBHOOK_SECRET
  GITHUB_INSTALLATION_ID
  GITHUB_ORG
  PLAKY_API_KEY
  PLAKY_BASE_URL
  PLAKY_WORKSPACE_ID
  PLAKY_BOARD_ID
  PLAKY_ITEM_GROUP_ID
  PLAKY_FIELD_EXTERNAL_KEY_ID
  PLAKY_FIELD_GITHUB_URL_ID
  PLAKY_FIELD_REPO_ID
  PLAKY_FIELD_STATUS_ID
  PLAKY_FIELD_PR_URL_ID
  PLAKY_FIELD_MERGE_STATE_ID
  PLAKY_STATUS_OPEN_VALUE
  PLAKY_STATUS_CLOSED_VALUE
  PLAKY_MERGE_STATE_OPEN_VALUE
  PLAKY_MERGE_STATE_MERGED_VALUE
  PLAKY_MERGE_STATE_CLOSED_VALUE
  PLAKY_MERGE_STATE_DRAFT_VALUE
  ROUTE_SECRET
)

is_placeholder() {
  local value
  value="$(echo "${1}" | tr '[:upper:]' '[:lower:]' | xargs)"
  [[ "${value}" == your-* || "${value}" == "change-me" || "${value}" == "replace-me" ]]
}

missing=()
for var_name in "${required_vars[@]}"; do
  value="${!var_name-}"
  if [[ -z "${value}" ]] || is_placeholder "${value}"; then
    missing+=("${var_name}")
  fi
done

if (( ${#missing[@]} > 0 )); then
  echo "Boardman preflight failed. Missing or placeholder values:"
  printf ' - %s\n' "${missing[@]}"
  exit 1
fi

echo "Boardman preflight passed: required env vars are set."

if [[ "${CHECK_HEALTH:-0}" == "1" ]]; then
  api_url="${API_HEALTH_URL:-http://localhost:5006/health}"
  worker_url="${WORKER_HEALTH_URL:-http://localhost:5007/health}"

  if ! command -v curl >/dev/null 2>&1; then
    echo "curl is not installed, skipping health checks."
    exit 0
  fi

  echo "Checking API health at ${api_url}..."
  curl -fsS "${api_url}" >/dev/null
  echo "Checking worker health at ${worker_url}..."
  curl -fsS "${worker_url}" >/dev/null
  echo "Health checks passed."
fi
