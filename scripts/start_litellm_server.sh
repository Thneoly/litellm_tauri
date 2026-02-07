#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT_DIR/src-tauri/bin/litellm_server}"
CONFIG="${CONFIG:-$ROOT_DIR/configs/litellm_config.yaml}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-4001}"
NUM_WORKERS="${NUM_WORKERS:-1}"

if [ ! -x "$BIN" ]; then
  echo "litellm_server not found: $BIN"
  exit 1
fi

if [ ! -f "$CONFIG" ]; then
  echo "Config not found: $CONFIG"
  exit 1
fi

exec "$BIN" --config "$CONFIG" --host "$HOST" --port "$PORT" --num_workers "$NUM_WORKERS"
