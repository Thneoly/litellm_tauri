# LiteLLM Tauri Progress Log

Date: 2026-02-07

## Goal
Package LiteLLM into a Tauri desktop app (Windows/Linux) with:
- Local login (username/password)
- LiteLLM config editor (YAML)
- Runtime status page (running/stopped, connections, logs, health)
- Embedded Python + LiteLLM sidecar executable

## Current Status
- Tauri v2 + React TS app scaffold created at `litellm_tauri/`.
- UI implemented: login, config, status pages.
- Rust backend commands implemented: auth, config load/save, start/stop, status, health, logs.
- LiteLLM sidecar built with Python 3.13 + Nuitka (onefile, compressed) and placed in `src-tauri/bin/`.
- Build/dev scripts added for sidecar and health checks.
- Tauri build now succeeds with corrected config and identifier.
- GitHub Actions workflow added to build Windows/Linux releases with bundled sidecar (draft releases).
- GitHub Actions now includes optional Windows code signing config + CI caches (Rust/Node/Python/Nuitka).

## Key Changes (Files)
- UI and logic:
  - `litellm_tauri/src/App.tsx`
  - `litellm_tauri/src/App.css`
- Rust commands / process control:
  - `litellm_tauri/src-tauri/src/lib.rs`
- Tauri config:
  - `litellm_tauri/src-tauri/tauri.conf.json`
  - `litellm_tauri/src-tauri/tauri.conf.dev.json`
- Scripts:
  - `litellm_tauri/scripts/build_litellm_server.sh`
  - `litellm_tauri/scripts/build_litellm_server.ps1`
  - `litellm_tauri/scripts/start_litellm_server.sh`
  - `litellm_tauri/scripts/selfcheck.sh`
  - `litellm_tauri/scripts/verify_health.sh`
- CI/CD:
  - `litellm_tauri/.github/workflows/release.yml`
  - `litellm_tauri/.gitignore` (CI cache + Windows signing override ignored)
- Config template:
  - `litellm_tauri/configs/litellm_config.yaml`

## Sidecar Packaging (Linux x86_64)
- Tooling: uv + Python 3.13 + Nuitka + zstandard.
- Sidecar path: `litellm_tauri/src-tauri/bin/litellm_server`.
- Build script creates a target-triple copy (not symlink) for Tauri:
  - `litellm_server-x86_64-unknown-linux-gnu`.

## Tauri Build/Dev
- Dev config (no bundle resources/externalBin enforcement):
  - `tauri.conf.dev.json`
- Build config (bundle externalBin only):
  - `tauri.conf.json`
- Package scripts:
  - `npm run tauri:dev`
  - `npm run tauri:build`

## Runtime Health Check
- LiteLLM /health returns 401 without master_key.
- Backend now reads `general_settings.master_key` from config YAML and sends `Authorization: Bearer <key>` + `x-api-key`.
- UI shows Health with HTTP status if not OK.

## Known Issues / Constraints
- Health check depends on `master_key` being set and visible to app env.
- Connections count not yet implemented (requires metrics endpoint parsing or LiteLLM stats).

## Conversation / Decision Record (Short)
- Initial manual Tauri scaffold replaced with `cargo create-tauri-app` (React TS).
- Sidecar build:
  - Python 3.14 build produced missing module errors.
  - Switched to Python 3.13 + Nuitka + zstandard.
  - Added missing resources (`endpoints.json`, `proxy/swagger`) to Nuitka build.
- Tauri build errors:
  - `bin/**` glob mismatch fixed by removing bundle resources for dev; build uses externalBin only.
  - `identifier` underscore invalid; changed to `com.cc.litellm-tauri`.
  - `TAURI_CONFIG` env var misuse fixed; use `tauri -c` instead.
- Health 401 fixed by sending master_key from config.

## Next Steps (Recommended)
1) Verify health in-app and via `scripts/verify_health.sh` with a valid master_key.
2) Implement connections/metrics on status page (define metrics endpoint + parser).
3) Build Windows sidecar on Windows and place in `src-tauri/bin/`.
4) Final `npm run tauri:build` packaging for Windows/Linux.
