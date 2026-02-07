#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT_DIR/src-tauri/bin/litellm_server}"
CONFIG="${CONFIG:-/tmp/litellm_selfcheck.yaml}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-4010}"
NUM_WORKERS="${NUM_WORKERS:-1}"
WAIT_SECS="${WAIT_SECS:-6}"

cat > "$CONFIG" <<'EOF'
model_list:
  - model_name: local-test
    litellm_params:
      model: openai/gpt-3.5-turbo
      api_key: "DUMMY"
EOF

LOG="/tmp/litellm_selfcheck.log"
: > "$LOG"

"$BIN" --config "$CONFIG" --host "$HOST" --port "$PORT" --num_workers "$NUM_WORKERS" >>"$LOG" 2>&1 &
PID=$!

sleep "$WAIT_SECS"

curl -s -o /tmp/litellm_health.out -w "%{http_code}" "http://${HOST}:${PORT}/health" > /tmp/litellm_health.status || true

kill "$PID" >/dev/null 2>&1 || true
wait "$PID" >/dev/null 2>&1 || true

echo "HTTP_STATUS=$(cat /tmp/litellm_health.status 2>/dev/null || echo 000)"
echo "LOG=/tmp/litellm_selfcheck.log"
