# LiteLLM sidecar

Place a platform-specific executable named `litellm_server` in this folder.

Tauri bundles it as an external binary. At runtime the app will search for:
- `bin/litellm_server`
- `bin/litellm_server.exe`
- any file under `bin/` whose name starts with `litellm_server`

The app passes:
- `--config <path>`
- `--port <port>` (if provided)
- `LITELLM_CONFIG_PATH` and `LITELLM_PORT` env vars

Suggested packaging approach:
- Build a self-contained Python runtime (or use Python embed) with `litellm` installed.
- Provide a small launcher executable named `litellm_server` that runs:
  `python -m litellm --config <path> --port <port>`
- Ensure the launcher exits when the parent process is terminated.

If you want to override the sidecar path during development, set:
`LITELLM_SIDECAR_PATH=/absolute/path/to/litellm_server`
