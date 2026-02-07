#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${CONFIG:-$ROOT_DIR/configs/litellm_config.yaml}"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-4000}"

if [ -f "$CONFIG" ]; then
  CONFIG_HOST=$(awk -F': ' '/^[[:space:]]*host:[[:space:]]*/ {print $2; exit}' "$CONFIG" | tr -d ' "')
  CONFIG_PORT=$(awk -F': ' '/^[[:space:]]*port:[[:space:]]*/ {print $2; exit}' "$CONFIG" | tr -d ' "')
  if [ -n "${CONFIG_HOST:-}" ]; then
    HOST="$CONFIG_HOST"
  fi
  if [ -n "${CONFIG_PORT:-}" ]; then
    PORT="$CONFIG_PORT"
  fi
fi

curl -v "http://${HOST}:${PORT}/health"
