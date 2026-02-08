#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-/tmp/litellm_build_py313}"
VENV_DIR="${VENV_DIR:-$BUILD_DIR/.venv}"
NUITKA_CACHE_DIR="${NUITKA_CACHE_DIR:-$BUILD_DIR/nuitka_cache}"
OUT_DIR="${OUT_DIR:-$BUILD_DIR/out}"
LITELLM_VERSION="${LITELLM_VERSION:-1.81.6}"
PYTHON_VERSION="${PYTHON_VERSION:-3.13}"
CCACHE_DIR="${CCACHE_DIR:-$ROOT_DIR/.cache/ccache}"
CCACHE_MAXSIZE="${CCACHE_MAXSIZE:-2G}"
FORCE_SIDECAR_REBUILD="${FORCE_SIDECAR_REBUILD:-0}"
ONEFILE_COMPRESS="${ONEFILE_COMPRESS:-0}"

TARGET_TRIPLE="$(rustc --print host-tuple 2>/dev/null || true)"
if [ -z "$TARGET_TRIPLE" ]; then
  TARGET_TRIPLE="$(rustc -Vv | awk '/host:/ {print $2}')"
fi
if [ -z "$TARGET_TRIPLE" ]; then
  echo "Could not determine Rust target triple."
  exit 1
fi

SIDECAR_PATH="$ROOT_DIR/src-tauri/bin/litellm_server"
SIDECAR_TRIPLE_PATH="$ROOT_DIR/src-tauri/bin/litellm_server-${TARGET_TRIPLE}"
SIDECAR_META="$ROOT_DIR/src-tauri/bin/litellm_server.meta"

mkdir -p "$BUILD_DIR" "$NUITKA_CACHE_DIR" "$OUT_DIR"
mkdir -p "$ROOT_DIR/src-tauri/bin"

if [ "$FORCE_SIDECAR_REBUILD" != "1" ] && [ -f "$SIDECAR_PATH" ] && [ -f "$SIDECAR_TRIPLE_PATH" ] && [ -f "$SIDECAR_META" ]; then
  META_LITELLM_VERSION="$(awk -F= '/^LITELLM_VERSION=/{print $2}' "$SIDECAR_META" | head -n1)"
  META_PYTHON_VERSION="$(awk -F= '/^PYTHON_VERSION=/{print $2}' "$SIDECAR_META" | head -n1)"
  META_TARGET_TRIPLE="$(awk -F= '/^TARGET_TRIPLE=/{print $2}' "$SIDECAR_META" | head -n1)"
  META_ONEFILE_COMPRESS="$(awk -F= '/^ONEFILE_COMPRESS=/{print $2}' "$SIDECAR_META" | head -n1)"
  if [ "$META_LITELLM_VERSION" = "$LITELLM_VERSION" ] && [ "$META_PYTHON_VERSION" = "$PYTHON_VERSION" ] && [ "$META_TARGET_TRIPLE" = "$TARGET_TRIPLE" ] && [ "$META_ONEFILE_COMPRESS" = "$ONEFILE_COMPRESS" ]; then
    echo "Sidecar already built (LITELLM_VERSION=$LITELLM_VERSION, PYTHON_VERSION=$PYTHON_VERSION). Skipping."
    exit 0
  fi
fi

PYTHON_BIN=""
if command -v uv >/dev/null 2>&1; then
  uv python install "$PYTHON_VERSION"
  uv venv "$VENV_DIR" --python "$PYTHON_VERSION"
  PYTHON_BIN="$VENV_DIR/bin/python"
  uv pip install --python "$PYTHON_BIN" "litellm[proxy]==${LITELLM_VERSION}" nuitka zstandard
else
  if command -v python3 >/dev/null 2>&1; then
    SYSTEM_PYTHON="python3"
  elif command -v python >/dev/null 2>&1; then
    SYSTEM_PYTHON="python"
  else
    echo "python not found. Install python or uv first."
    exit 1
  fi
  "$SYSTEM_PYTHON" -m venv "$VENV_DIR"
  PYTHON_BIN="$VENV_DIR/bin/python"
  "$PYTHON_BIN" -m pip install --upgrade pip
  "$PYTHON_BIN" -m pip install "litellm[proxy]==${LITELLM_VERSION}" nuitka zstandard
fi

if command -v ccache >/dev/null 2>&1; then
  mkdir -p "$CCACHE_DIR"
  export CCACHE_DIR
  export CCACHE_MAXSIZE
  export CC="ccache gcc"
  export CXX="ccache g++"
fi

cat > "$BUILD_DIR/litellm_server.py" <<'PY'
import os
import sys
from typing import List

import litellm.proxy.proxy_cli as proxy_cli


def _has_flag(args: List[str], flag: str) -> bool:
    for item in args:
        if item == flag or item.startswith(flag + "="):
            return True
    return False


def _inject_arg(args: List[str], flag: str, value: str) -> None:
    if value and not _has_flag(args, flag):
        args.extend([flag, value])


def main() -> None:
    args = list(sys.argv[1:])
    config_path = os.environ.get("LITELLM_CONFIG_PATH")
    port = os.environ.get("LITELLM_PORT")

    if config_path:
        _inject_arg(args, "--config", config_path)
    if port:
        _inject_arg(args, "--port", port)

    proxy_cli.run_server.main(args=args, prog_name="litellm_server")


if __name__ == "__main__":
    main()
PY

SITE_PACKAGES="$("$PYTHON_BIN" - <<'PY'
import sysconfig
print(sysconfig.get_paths()["purelib"])
PY
)"
ENDPOINTS_JSON="$SITE_PACKAGES/litellm/containers/endpoints.json"
SWAGGER_DIR="$SITE_PACKAGES/litellm/proxy/swagger"

if [ ! -f "$ENDPOINTS_JSON" ]; then
  echo "Missing endpoints.json at $ENDPOINTS_JSON"
  exit 1
fi
if [ ! -d "$SWAGGER_DIR" ]; then
  echo "Missing swagger dir at $SWAGGER_DIR"
  exit 1
fi

NUITKA_CACHE_DIR="$NUITKA_CACHE_DIR" \
"$PYTHON_BIN" -m nuitka \
  --onefile \
  $( [ "$ONEFILE_COMPRESS" = "1" ] && printf "%s" "--onefile-compression" ) \
  --assume-yes-for-downloads \
  --static-libpython=no \
  --include-package=litellm \
  --include-package=litellm.litellm_core_utils \
  --include-data-files="$ENDPOINTS_JSON=litellm/containers/endpoints.json" \
  --include-data-dir="$SWAGGER_DIR=litellm/proxy/swagger" \
  --output-filename=litellm_server \
  --output-dir="$OUT_DIR" \
  "$BUILD_DIR/litellm_server.py"

install -m 755 "$OUT_DIR/litellm_server" "$ROOT_DIR/src-tauri/bin/litellm_server"
cp -f "$ROOT_DIR/src-tauri/bin/litellm_server" \
  "$ROOT_DIR/src-tauri/bin/litellm_server-${TARGET_TRIPLE}"
chmod +x "$ROOT_DIR/src-tauri/bin/litellm_server-${TARGET_TRIPLE}"

cat > "$SIDECAR_META" <<EOF
LITELLM_VERSION=$LITELLM_VERSION
PYTHON_VERSION=$PYTHON_VERSION
TARGET_TRIPLE=$TARGET_TRIPLE
BUILD_MODE=onefile
ONEFILE_COMPRESS=$ONEFILE_COMPRESS
EOF
echo "Built: $ROOT_DIR/src-tauri/bin/litellm_server"
