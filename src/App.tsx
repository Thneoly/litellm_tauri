import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { openPath } from "@tauri-apps/plugin-opener";
import "./App.css";

type AuthStatus = {
  has_account: boolean;
  username?: string | null;
};

type RunStatus = {
  running: boolean;
  pid?: number | null;
  started_at?: number | null;
  port?: number | null;
  host?: string | null;
  connections?: number | null;
  log_path?: string | null;
};

type HealthStatus = {
  ok: boolean;
  status?: number | null;
  error?: string | null;
};

type RuntimePaths = {
  app_config_dir: string;
  auth_file: string;
  config_file: string;
  env_file: string;
  token_settings_file: string;
  token_info_file: string;
  log_dir: string;
  log_file: string;
  resource_dir?: string | null;
  executable_dir?: string | null;
  sidecar_path?: string | null;
};

type EnvEntry = {
  key: string;
  value: string;
  enabled: boolean;
};

type LogEvent = {
  line: string;
};

type LogFileInfo = {
  name: string;
  bytes: number;
};

type LogStats = {
  max_bytes: number;
  files: LogFileInfo[];
};

type AppSettings = {
  health_interval_seconds: number;
};

type TokenSettings = {
  auth_url: string;
};

type TokenInfo = {
  token: string;
  fetched_at: number;
  expires_at?: number | null;
  project_id?: string | null;
  project_name?: string | null;
  project_extra?: Record<string, unknown> | null;
};

type TokenRequest = {
  auth_url: string;
  employee_id: string;
  password: string;
  project_id?: string | null;
  project_name?: string | null;
  project_extra?: Record<string, unknown> | null;
};

type TabKey = "config" | "status" | "env" | "token";

const ENABLE_TOKEN_PAGE = false;

const sampleConfig = `# LiteLLM config example (YAML)
# https://docs.litellm.ai/docs/proxy/configs

model_list:
  - model_name: gpt-4o-mini
    litellm_params:
      model: openai/gpt-4o-mini
      api_key: "${"${OPENAI_API_KEY}"}"

litellm_settings:
  set_verbose: true
`;

function formatTimestamp(ts?: number | null) {
  if (!ts) return "-";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return "-";
  }
}

function formatBytes(value?: number | null) {
  if (!value || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let idx = 0;
  let size = value;
  while (size >= 1024 && idx < units.length - 1) {
    size /= 1024;
    idx += 1;
  }
  return `${size.toFixed(idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function App() {
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);
  const [loggedIn, setLoggedIn] = useState(false);
  const [tab, setTab] = useState<TabKey>("config");

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const [configText, setConfigText] = useState("");
  const [status, setStatus] = useState<RunStatus>({ running: false });
  const [logs, setLogs] = useState<string[]>([]);
  const [port, setPort] = useState("4000");
  const [host, setHost] = useState("127.0.0.1");
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [runtimePaths, setRuntimePaths] = useState<RuntimePaths | null>(null);
  const [envEntries, setEnvEntries] = useState<EnvEntry[]>([]);
  const [logStats, setLogStats] = useState<LogStats | null>(null);
  const [healthIntervalSec, setHealthIntervalSec] = useState("3");
  const [tokenSettings, setTokenSettings] = useState<TokenSettings>({ auth_url: "" });
  const [tokenInfo, setTokenInfo] = useState<TokenInfo | null>(null);
  const [employeeId, setEmployeeId] = useState("");
  const [employeePassword, setEmployeePassword] = useState("");
  const [projectId, setProjectId] = useState("");
  const [projectName, setProjectName] = useState("");
  const [projectExtra, setProjectExtra] = useState("");
  const [showToken, setShowToken] = useState(false);
  const healthInFlight = useRef(false);

  const MAX_LOG_LINES = 500;
  const [healthGraceUntil, setHealthGraceUntil] = useState<number | null>(null);

  const hasAccount = authStatus?.has_account ?? false;
  const showRegister = authStatus && !hasAccount;

  const connectionDisplay = useMemo(() => {
    if (status.connections == null) return "N/A";
    return status.connections.toString();
  }, [status.connections]);

  const healthLabel = useMemo(() => {
    if (!health) return "-";
    if (health.error === "starting") return "启动中";
    if (health.ok) return "OK";
    if (health.status) return `HTTP ${health.status}`;
    return "FAIL";
  }, [health]);

  async function refreshAuth() {
    const data = await invoke<AuthStatus>("auth_status");
    setAuthStatus(data);
  }

  async function refreshStatus() {
    const next = await invoke<RunStatus>("litellm_status");
    setStatus(next);
  }

  async function refreshHealth() {
    if (healthInFlight.current) return;
    if (healthGraceUntil && Date.now() < healthGraceUntil) {
      setHealth({ ok: false, status: null, error: "starting" });
      return;
    }
    healthInFlight.current = true;
    try {
      const next = await invoke<HealthStatus>("litellm_health");
      setHealth(next);
    } finally {
      healthInFlight.current = false;
    }
  }

  async function loadLogs() {
    const nextLogs = await invoke<string[]>("read_logs", { max_lines: 200 });
    setLogs(nextLogs);
  }

  async function loadLogStats() {
    const stats = await invoke<LogStats>("log_stats");
    setLogStats(stats);
  }

  async function loadConfig() {
    const content = await invoke<string>("load_config");
    setConfigText(content ?? "");
  }

  async function loadEnv() {
    const entries = await invoke<EnvEntry[]>("load_env");
    if (entries.length === 0) {
      setEnvEntries([{ key: "", value: "", enabled: true }]);
    } else {
      setEnvEntries(entries);
    }
  }

  async function loadAppSettings() {
    const settings = await invoke<AppSettings>("load_app_settings");
    const secs = settings.health_interval_seconds || 3;
    setHealthIntervalSec(String(secs));
  }

  async function loadTokenSettings() {
    const settings = await invoke<TokenSettings>("load_token_settings");
    setTokenSettings(settings);
  }

  async function loadTokenInfo() {
    const info = await invoke<TokenInfo | null>("load_token_info");
    setTokenInfo(info ?? null);
  }

  useEffect(() => {
    refreshAuth().catch((err) => setError(String(err)));
  }, []);

  useEffect(() => {
    if (!loggedIn) return;
    loadConfig().catch((err) => setError(String(err)));
    loadEnv().catch((err) => setError(String(err)));
    loadAppSettings().catch((err) => setError(String(err)));
    if (ENABLE_TOKEN_PAGE) {
      loadTokenSettings().catch((err) => setError(String(err)));
      loadTokenInfo().catch((err) => setError(String(err)));
    }
    refreshStatus().catch((err) => setError(String(err)));
  }, [loggedIn]);

  useEffect(() => {
    if (!loggedIn) return;
    if (tab !== "status") return;
    let statusTimer: number | null = null;
    let healthTimer: number | null = null;

    const startTimers = () => {
      if (statusTimer == null) {
        statusTimer = window.setInterval(() => {
          if (document.hidden) return;
          refreshStatus().catch(() => undefined);
          loadLogStats().catch(() => undefined);
        }, 3000);
      }
      if (healthTimer == null) {
        const interval = Math.max(1, Number(healthIntervalSec) || 3) * 1000;
        healthTimer = window.setInterval(() => {
          if (document.hidden) return;
          refreshHealth().catch(() => undefined);
        }, interval);
      }
    };

    const stopTimers = () => {
      if (statusTimer != null) {
        window.clearInterval(statusTimer);
        statusTimer = null;
      }
      if (healthTimer != null) {
        window.clearInterval(healthTimer);
        healthTimer = null;
      }
    };

    const onVisibility = () => {
      if (document.hidden) {
        stopTimers();
      } else {
        refreshStatus().catch(() => undefined);
        refreshHealth().catch(() => undefined);
        startTimers();
      }
    };

    refreshStatus().catch(() => undefined);
    refreshHealth().catch(() => undefined);
    loadLogs().catch(() => undefined);
    loadLogStats().catch(() => undefined);
    startTimers();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stopTimers();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [loggedIn, tab, healthIntervalSec]);

  useEffect(() => {
    if (!loggedIn) return;
    let unlisten: (() => void) | undefined;
    listen<LogEvent>("litellm_log", (event) => {
      const line = event.payload?.line;
      if (!line) return;
      setLogs((prev) => {
        const next = [...prev, line];
        if (next.length > MAX_LOG_LINES) {
          return next.slice(next.length - MAX_LOG_LINES);
        }
        return next;
      });
    })
      .then((fn) => {
        unlisten = fn;
      })
      .catch(() => undefined);
    return () => {
      if (unlisten) unlisten();
    };
  }, [loggedIn]);

  useEffect(() => {
    if (!ENABLE_TOKEN_PAGE && tab === "token") {
      setTab("config");
    }
  }, [tab]);

  async function handleRegister() {
    setError("");
    setMessage("");
    if (!username.trim() || !password.trim()) {
      setError("请输入用户名和密码");
      return;
    }
    if (password !== confirm) {
      setError("两次密码不一致");
      return;
    }
    try {
      await invoke("auth_register", { username, password });
      setMessage("账号已创建，请登录");
      setPassword("");
      setConfirm("");
      await refreshAuth();
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleLogin() {
    setError("");
    setMessage("");
    if (!username.trim() || !password.trim()) {
      setError("请输入用户名和密码");
      return;
    }
    try {
      await invoke("auth_login", { username, password });
      setLoggedIn(true);
      setPassword("");
    } catch (err) {
      setError(String(err));
    }
  }

  function handleAuthKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key !== "Enter") return;
    e.preventDefault();
    if (showRegister) {
      handleRegister();
    } else {
      handleLogin();
    }
  }

  async function handleSaveConfig() {
    setError("");
    setMessage("");
    try {
      await invoke("save_config", { content: configText });
      setMessage("配置已保存");
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleSaveEnv() {
    setError("");
    setMessage("");
    try {
      await invoke("save_env", { entries: envEntries });
      setMessage("环境变量已保存");
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleSaveAppSettings() {
    setError("");
    setMessage("");
    const secs = Math.max(1, Number(healthIntervalSec) || 3);
    try {
      await invoke("save_app_settings", { settings: { health_interval_seconds: secs } });
      setHealthIntervalSec(String(secs));
      setMessage("健康检查间隔已保存");
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleSaveTokenSettings() {
    setError("");
    setMessage("");
    try {
      await invoke("save_token_settings", { settings: tokenSettings });
      setMessage("Token 配置已保存");
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleClearLogs() {
    setError("");
    setMessage("");
    try {
      await invoke("clear_logs");
      await loadLogs();
      await loadLogStats();
      setMessage("日志已清空");
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleOpenLogDir() {
    if (!runtimePaths?.log_dir) return;
    try {
      await openPath(runtimePaths.log_dir);
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleStart(debugEnv = false) {
    setError("");
    setMessage("");
    const parsedPort = Number(port);
    const usePort = Number.isFinite(parsedPort) ? parsedPort : undefined;
    try {
      const next = await invoke<RunStatus>("start_litellm", {
        port: usePort,
        host,
        debug_env: debugEnv,
      });
      setStatus(next);
      setTab("status");
      loadLogs().catch(() => undefined);
      loadLogStats().catch(() => undefined);
      setHealthGraceUntil(Date.now() + 8000);
      setMessage("LiteLLM 已启动");
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleStop() {
    setError("");
    setMessage("");
    try {
      await invoke("stop_litellm");
      await refreshStatus();
      setMessage("LiteLLM 已停止");
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleShowPaths() {
    setError("");
    setMessage("");
    try {
      const data = await invoke<RuntimePaths>("runtime_paths");
      setRuntimePaths(data);
      setMessage("已获取本机路径");
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleFetchToken() {
    setError("");
    setMessage("");
    let extra: Record<string, unknown> | null = null;
    if (projectExtra.trim()) {
      try {
        const parsed = JSON.parse(projectExtra);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          setError("项目扩展 JSON 必须是对象");
          return;
        }
        extra = parsed;
      } catch (err) {
        setError(`项目扩展 JSON 解析失败: ${String(err)}`);
        return;
      }
    }
    try {
      const payload: TokenRequest = {
        auth_url: tokenSettings.auth_url,
        employee_id: employeeId,
        password: employeePassword,
        project_id: projectId || null,
        project_name: projectName || null,
        project_extra: extra,
      };
      const info = await invoke<TokenInfo>("fetch_internal_token", { request: payload });
      setTokenInfo(info);
      setEmployeePassword("");
      setMessage("Token 获取成功");
    } catch (err) {
      setError(String(err));
    }
  }

  function maskToken(token: string) {
    if (token.length <= 8) return "********";
    return `${token.slice(0, 4)}...${token.slice(-4)}`;
  }

  function updateEnvEntry(index: number, patch: Partial<EnvEntry>) {
    setEnvEntries((prev) => {
      const next = [...prev];
      next[index] = { ...next[index], ...patch };
      return next;
    });
  }

  function addEnvEntry() {
    setEnvEntries((prev) => [...prev, { key: "", value: "", enabled: true }]);
  }

  function removeEnvEntry(index: number) {
    setEnvEntries((prev) => prev.filter((_, idx) => idx !== index));
  }

  function escapeDoubleQuotes(value: string) {
    return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  }

  const envPreview = useMemo(() => {
    const rows = envEntries.filter((entry) => entry.key.trim().length > 0);
    const linux = rows
      .map((entry) => {
        const prefix = entry.enabled ? "" : "# ";
        return `${prefix}export ${entry.key}="${escapeDoubleQuotes(entry.value)}"`;
      })
      .join("\n");
    const powershell = rows
      .map((entry) => {
        const prefix = entry.enabled ? "" : "# ";
        return `${prefix}$env:${entry.key}="${escapeDoubleQuotes(entry.value)}"`;
      })
      .join("\n");
    const cmd = rows
      .map((entry) => {
        const prefix = entry.enabled ? "" : "REM ";
        return `${prefix}set "${entry.key}=${entry.value}"`;
      })
      .join("\n");
    return { linux, powershell, cmd };
  }, [envEntries]);

  const extraBodyPreview = useMemo(() => {
    if (!tokenInfo) return "extra_body:\n  # token: <your token>\n";
    const lines = ["extra_body:"];
    lines.push(`  token: "${tokenInfo.token}"`);
    if (tokenInfo.project_id) {
      lines.push(`  project_id: "${tokenInfo.project_id}"`);
    }
    if (tokenInfo.project_name) {
      lines.push(`  project_name: "${tokenInfo.project_name}"`);
    }
    if (tokenInfo.project_extra) {
      Object.entries(tokenInfo.project_extra).forEach(([key, value]) => {
        lines.push(`  ${key}: "${String(value)}"`);
      });
    }
    return lines.join("\n");
  }, [tokenInfo]);

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <div className="brand-mark">LL</div>
          <div>
            <div className="brand-title">LiteLLM Bridge</div>
            <div className="brand-subtitle">内部中转 · Windows / Linux</div>
          </div>
        </div>
        {loggedIn && (
          <div className="tabs">
            <button
              className={tab === "config" ? "tab active" : "tab"}
              onClick={() => setTab("config")}
            >
              配置
            </button>
            <button
              className={tab === "env" ? "tab active" : "tab"}
              onClick={() => setTab("env")}
            >
              环境变量
            </button>
            {ENABLE_TOKEN_PAGE && (
              <button
                className={tab === "token" ? "tab active" : "tab"}
                onClick={() => setTab("token")}
              >
                Token
              </button>
            )}
            <button
              className={tab === "status" ? "tab active" : "tab"}
              onClick={() => setTab("status")}
            >
              运行状况
            </button>
          </div>
        )}
      </header>

      <main className="app-main">
        {!loggedIn && (
          <section className="card auth-card">
            <h2>{showRegister ? "创建本地账号" : "登录"}</h2>
            <p className="muted">
              {showRegister
                ? "首次使用请创建本地账号，密码仅保存在本机配置目录。"
                : "请输入本地账号密码。"}
            </p>
            <div className="form-grid">
              <label>
                用户名
                <input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="例如：admin"
                  onKeyDown={handleAuthKeyDown}
                />
              </label>
              <label>
                密码
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  onKeyDown={handleAuthKeyDown}
                />
              </label>
              {showRegister && (
                <label>
                  确认密码
                  <input
                    type="password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    placeholder="••••••••"
                    onKeyDown={handleAuthKeyDown}
                  />
                </label>
              )}
            </div>
            <div className="button-row">
              {showRegister ? (
                <button className="primary" onClick={handleRegister}>
                  创建账号
                </button>
              ) : (
                <button className="primary" onClick={handleLogin}>
                  登录
                </button>
              )}
            </div>
            {error && <div className="alert error">{error}</div>}
            {message && <div className="alert success">{message}</div>}
          </section>
        )}

        {loggedIn && tab === "config" && (
          <section className="card config-card">
            <h2>LiteLLM 配置</h2>
            <p className="muted">
              按 LiteLLM 官方 config 规则填写。保存后再启动服务。
            </p>
            <div className="textarea-wrap">
              <textarea
                value={configText}
                onChange={(e) => setConfigText(e.target.value)}
                spellCheck={false}
              />
            </div>
            <div className="button-row">
              <button className="ghost" onClick={() => setConfigText(sampleConfig)}>
                载入示例
              </button>
              <button className="primary" onClick={handleSaveConfig}>
                保存配置
              </button>
            </div>
            <div className="button-row">
              <label className="inline-field">
                Host
                <input
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  placeholder="127.0.0.1"
                />
              </label>
              <label className="inline-field">
                端口
                <input
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  placeholder="4000"
                />
              </label>
              <button className="primary" onClick={() => handleStart(false)}>
                启动 LiteLLM
              </button>
              <button className="ghost" onClick={() => handleStart(true)}>
                Debug 启动
              </button>
            </div>
            <div className="button-row">
              <button className="ghost" onClick={handleShowPaths}>
                显示本机路径
              </button>
            </div>
            {runtimePaths && (
              <div className="path-panel">
                <div className="path-row">
                  <div className="label">配置目录</div>
                  <div className="path-value">{runtimePaths.app_config_dir}</div>
                </div>
                <div className="path-row">
                  <div className="label">账号文件</div>
                  <div className="path-value">{runtimePaths.auth_file}</div>
                </div>
                <div className="path-row">
                  <div className="label">配置文件</div>
                  <div className="path-value">{runtimePaths.config_file}</div>
                </div>
                <div className="path-row">
                  <div className="label">环境变量文件</div>
                  <div className="path-value">{runtimePaths.env_file}</div>
                </div>
                <div className="path-row">
                  <div className="label">日志目录</div>
                  <div className="path-value">{runtimePaths.log_dir}</div>
                </div>
                <div className="path-row">
                  <div className="label">日志文件</div>
                  <div className="path-value">{runtimePaths.log_file}</div>
                </div>
                {runtimePaths.sidecar_path && (
                  <div className="path-row">
                    <div className="label">Sidecar</div>
                    <div className="path-value">{runtimePaths.sidecar_path}</div>
                  </div>
                )}
                {runtimePaths.resource_dir && (
                  <div className="path-row">
                    <div className="label">资源目录</div>
                    <div className="path-value">{runtimePaths.resource_dir}</div>
                  </div>
                )}
                {runtimePaths.executable_dir && (
                  <div className="path-row">
                    <div className="label">可执行目录</div>
                    <div className="path-value">{runtimePaths.executable_dir}</div>
                  </div>
                )}
              </div>
            )}
            {error && <div className="alert error">{error}</div>}
            {message && <div className="alert success">{message}</div>}
          </section>
        )}

        {loggedIn && tab === "env" && (
          <section className="card env-card">
            <h2>环境变量</h2>
            <p className="muted">
              仅影响本应用启动的 LiteLLM sidecar。保存后再次启动服务生效。
            </p>
            <div className="env-table">
              <div className="env-header">
                <span>启用</span>
                <span>键名</span>
                <span>值</span>
                <span>操作</span>
              </div>
              {envEntries.map((entry, index) => (
                <div className="env-row" key={`env-${index}`}>
                  <input
                    type="checkbox"
                    className="env-toggle"
                    checked={entry.enabled}
                    onChange={(e) => updateEnvEntry(index, { enabled: e.target.checked })}
                  />
                  <input
                    className="env-key"
                    value={entry.key}
                    onChange={(e) => updateEnvEntry(index, { key: e.target.value })}
                    placeholder="OPENAI_API_KEY"
                  />
                  <input
                    className="env-value"
                    value={entry.value}
                    onChange={(e) => updateEnvEntry(index, { value: e.target.value })}
                    placeholder="sk-..."
                  />
                  <button
                    className="ghost env-action"
                    onClick={() => removeEnvEntry(index)}
                  >
                    删除
                  </button>
                </div>
              ))}
            </div>
            <div className="button-row">
              <button className="ghost" onClick={addEnvEntry}>
                添加一行
              </button>
              <button className="ghost" onClick={handleShowPaths}>
                显示路径
              </button>
              <button className="primary" onClick={handleSaveEnv}>
                保存环境变量
              </button>
            </div>
            <div className="env-preview">
              <div className="env-preview-block">
                <div className="label">Linux / macOS (bash)</div>
                <pre>{envPreview.linux || "# 无配置"}</pre>
              </div>
              <div className="env-preview-block">
                <div className="label">Windows (PowerShell)</div>
                <pre>{envPreview.powershell || "# 无配置"}</pre>
              </div>
              <div className="env-preview-block">
                <div className="label">Windows (CMD)</div>
                <pre>{envPreview.cmd || "REM 无配置"}</pre>
              </div>
            </div>
            {runtimePaths && (
              <div className="path-panel">
                <div className="path-row">
                  <div className="label">环境变量文件</div>
                  <div className="path-value">{runtimePaths.env_file}</div>
                </div>
              </div>
            )}
            {error && <div className="alert error">{error}</div>}
            {message && <div className="alert success">{message}</div>}
          </section>
        )}

        {ENABLE_TOKEN_PAGE && loggedIn && tab === "token" && (
          <section className="card token-card">
            <h2>内部 Token 获取</h2>
            <p className="muted">
              使用工号/密码获取内部 Token。保存配置后可重复使用。
            </p>
            <div className="form-grid">
              <label>
                Auth URL
                <input
                  value={tokenSettings.auth_url}
                  onChange={(e) =>
                    setTokenSettings({ ...tokenSettings, auth_url: e.target.value })
                  }
                  placeholder="https://internal-auth.example.com/token"
                />
              </label>
            </div>
            <div className="button-row">
              <button className="ghost" onClick={handleSaveTokenSettings}>
                保存 Auth 配置
              </button>
            </div>

            <div className="form-grid token-form">
              <label>
                工号
                <input
                  value={employeeId}
                  onChange={(e) => setEmployeeId(e.target.value)}
                  placeholder="EMP00123"
                />
              </label>
              <label>
                密码
                <input
                  type="password"
                  value={employeePassword}
                  onChange={(e) => setEmployeePassword(e.target.value)}
                  placeholder="••••••••"
                />
              </label>
              <label>
                项目 ID
                <input
                  value={projectId}
                  onChange={(e) => setProjectId(e.target.value)}
                  placeholder="project-xyz"
                />
              </label>
              <label>
                项目名称
                <input
                  value={projectName}
                  onChange={(e) => setProjectName(e.target.value)}
                  placeholder="内部大模型项目"
                />
              </label>
            </div>
            <label>
              项目扩展信息（JSON，可选）
              <textarea
                className="token-extra"
                value={projectExtra}
                onChange={(e) => setProjectExtra(e.target.value)}
                placeholder='{\"department\":\"R&D\",\"scope\":\"prod\"}'
              />
            </label>
            <div className="button-row">
              <button className="primary" onClick={handleFetchToken}>
                获取 Token
              </button>
              <button className="ghost" onClick={handleShowPaths}>
                显示路径
              </button>
            </div>

            {tokenInfo && (
              <div className="token-panel">
                <div className="path-row">
                  <div className="label">Token</div>
                  <div className="token-value">
                    {showToken ? tokenInfo.token : maskToken(tokenInfo.token)}
                  </div>
                  <button className="ghost" onClick={() => setShowToken((v) => !v)}>
                    {showToken ? "隐藏" : "显示"}
                  </button>
                </div>
                <div className="path-row">
                  <div className="label">获取时间</div>
                  <div className="path-value">{formatTimestamp(tokenInfo.fetched_at)}</div>
                </div>
                <div className="path-row">
                  <div className="label">过期时间</div>
                  <div className="path-value">
                    {tokenInfo.expires_at ? formatTimestamp(tokenInfo.expires_at) : "-"}
                  </div>
                </div>
                <div className="path-row">
                  <div className="label">项目 ID</div>
                  <div className="path-value">{tokenInfo.project_id ?? "-"}</div>
                </div>
                <div className="path-row">
                  <div className="label">项目名称</div>
                  <div className="path-value">{tokenInfo.project_name ?? "-"}</div>
                </div>
                {runtimePaths && (
                  <div className="path-row">
                    <div className="label">Token 文件</div>
                    <div className="path-value">{runtimePaths.token_info_file}</div>
                  </div>
                )}
              </div>
            )}

            <div className="env-preview">
              <div className="env-preview-block">
                <div className="label">LiteLLM extra_body 模板</div>
                <pre>{extraBodyPreview}</pre>
              </div>
            </div>

            {runtimePaths && (
              <div className="path-panel">
                <div className="path-row">
                  <div className="label">Token 配置文件</div>
                  <div className="path-value">{runtimePaths.token_settings_file}</div>
                </div>
              </div>
            )}

            {error && <div className="alert error">{error}</div>}
            {message && <div className="alert success">{message}</div>}
          </section>
        )}

        {loggedIn && tab === "status" && (
          <section className="card status-card">
            <h2>运行状况</h2>
            <div className="status-grid">
              <div>
                <div className="label">状态</div>
                <div className={status.running ? "value running" : "value stopped"}>
                  {status.running ? "运行中" : "已停止"}
                </div>
              </div>
              <div>
                <div className="label">Health</div>
                <div className={health?.ok ? "value running" : "value stopped"}>
                  {healthLabel}
                </div>
              </div>
              <div>
                <div className="label">PID</div>
                <div className="value">{status.pid ?? "-"}</div>
              </div>
              <div>
                <div className="label">端口</div>
                <div className="value">{status.port ?? port}</div>
              </div>
              <div>
                <div className="label">Host</div>
                <div className="value">{status.host ?? host}</div>
              </div>
              <div>
                <div className="label">连接数</div>
                <div className="value">{connectionDisplay}</div>
              </div>
              <div>
                <div className="label">启动时间</div>
                <div className="value">{formatTimestamp(status.started_at)}</div>
              </div>
            </div>
            <div className="form-grid">
              <label>
                健康检查间隔（秒）
                <input
                  type="number"
                  min={1}
                  value={healthIntervalSec}
                  onChange={(e) => setHealthIntervalSec(e.target.value)}
                />
              </label>
            </div>
            <div className="button-row">
              <button className="ghost" onClick={handleSaveAppSettings}>
                保存健康检查间隔
              </button>
            </div>
            <div className="button-row">
              <button className="ghost" onClick={refreshStatus}>
                刷新状态
              </button>
              <button className="ghost" onClick={handleClearLogs}>
                清空日志
              </button>
              <button className="ghost" onClick={handleOpenLogDir}>
                打开日志目录
              </button>
              <button className="primary" onClick={handleStop}>
                停止 LiteLLM
              </button>
            </div>
            <div className="log-panel">
              <div className="log-header">
                <span>日志输出</span>
                <span className="muted">
                  {logStats
                    ? `${formatBytes(logStats.files.find((f) => f.name === "litellm.log")?.bytes)} / ${formatBytes(
                      logStats.max_bytes,
                    )}`
                    : status.log_path ?? "-"}
                </span>
              </div>
              <pre className="log-body">{logs.length ? logs.join("\n") : "暂无日志"}</pre>
            </div>
            {error && <div className="alert error">{error}</div>}
            {message && <div className="alert success">{message}</div>}
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
