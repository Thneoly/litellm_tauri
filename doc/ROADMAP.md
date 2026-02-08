# LiteLLM Bridge Roadmap

Date: 2026-02-07

## Product Goals
- Provide a reliable desktop packaging of LiteLLM with local configuration, secure env management, and stable cross-platform builds.
- Minimize time-to-first-success from install to a working proxy.
- Offer clear diagnostics and enterprise-ready controls (audit, policy, updates).

## Primary Use Case (Internal Enterprise)
- Company requires strict confidentiality; only internal LLM APIs are allowed.
- Common CLI tools (Gemini CLI, Claude CLI, etc.) need to work by configuring `api_key` and `base_url` to route through LiteLLM.
- Due to internal network/security restrictions, LiteLLM cannot be run directly from source.
- Therefore, LiteLLM server must be pre-packaged as an executable and launched with one click.
- The desktop app must include user management, config management, and environment variable management.
- When routing to internal LLMs, users must first obtain a token with employee ID/password, then add the token and project metadata into LiteLLM `extra_body` in the config.

## Target User Flow (Internal Enterprise)
1. Install signed desktop package (Windows/Linux).
2. First run: create local account and login.
3. Configure environment variables (internal endpoints, proxy, secrets).
4. Obtain internal token using employee ID/password.
5. Generate or edit LiteLLM config with `extra_body` including token and project metadata.
6. Start LiteLLM sidecar with one click.
7. Verify health and logs.
8. Configure CLI tools with `base_url` and `api_key` to route requests through LiteLLM.

## Requirements (NPDP Perspective)
- Must work without external source builds (pre-packaged sidecar only).
- Must be usable in restricted corporate networks.
- Must provide deterministic, low-friction setup for internal token + `extra_body`.
- Must provide clear diagnostics for failure points.
- Must keep secrets local and masked in UI.

## Implementation Plan (Workstreams)
- Packaging and Compliance: stable cross-platform CI builds (Windows/Linux) with bundled sidecar, plus code signing and integrity checks.
- Token and Auth Flow: internal token retrieval UI (employee ID/password), secure storage, and auto-injection into `extra_body`.
- Config and Template Management: official internal templates, schema validation, and inline errors.
- Environment Management: env editor with masking, import/export, per-entry enable/disable, and runtime application.
- Operations and Diagnostics: health checks, logs, metrics, and one-click diagnostics export.
- UX and Onboarding: first-run wizard, template selection, and CLI tool setup guidance.

## Release Phases

### 0.0.x (MVP)
Scope: Make the product work reliably for a single developer on Windows/Linux.
- Stable build pipeline (CI) for Windows/Linux with bundled sidecar.
- Local login and basic config editing.
- Environment variables editor with preview and safe storage in app config dir.
- Health check and status page (running/stopped, port/host, logs).
- Clear runtime paths visibility.

Exit Criteria:
- 90%+ successful builds on CI for Windows/Linux.
- First-time user can start LiteLLM within 5 minutes.

### 0.1.x (Beta)
Scope: Integrate internal token flow and harden setup experience.
- Token acquisition UI (employee ID/password) with secure local storage.
- Config templates with `extra_body` auto-injection.
- Config schema validation and inline linting.
- Metrics panel (requests, error rate, latency, connections).
- Logs search/filter, structured error summary.
- Env secrets masking + import/export.

Exit Criteria:
- Error rate of first-run below 10%.
- Internal token workflow works end-to-end without manual config edits.

### 1.0 (GA)
Scope: Enterprise readiness and trust.
- Signing and tamper protection on Windows/Linux packages.
- Auto-update or safe update workflow.
- Basic policy controls (allowed models, rate limits, quotas).
- Audit logs export.
- Admin configuration lock (read-only mode for end users).

Exit Criteria:
- Security review pass for local storage and update path.
- Stable upgrade path between minor versions.

## KPIs
- Time-to-first-success (install to healthy proxy) < 5 minutes.
- First-run failure rate < 10%.
- Support resolution time reduced by 50% with diagnostics export.

## Key Risks
- Sidecar build instability across OS/Python/Nuitka versions.
- Token workflow changes by internal IAM systems.
- CI flakiness when external dependencies change.

## Next Tactical Steps
- Add token acquisition flow UI and storage model.
- Implement `extra_body` templating in config editor.
- Add config schema validation in UI.
- Improve CI logs with explicit failure hints.
