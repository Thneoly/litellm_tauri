import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
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

type TabKey = "config" | "status" | "env";

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

  const hasAccount = authStatus?.has_account ?? false;
  const showRegister = authStatus && !hasAccount;

  const connectionDisplay = useMemo(() => {
    if (status.connections == null) return "N/A";
    return status.connections.toString();
  }, [status.connections]);

  const healthLabel = useMemo(() => {
    if (!health) return "-";
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
    const nextLogs = await invoke<string[]>("read_logs", { max_lines: 200 });
    setLogs(nextLogs);
  }

  async function refreshHealth() {
    const next = await invoke<HealthStatus>("litellm_health");
    setHealth(next);
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

  useEffect(() => {
    refreshAuth().catch((err) => setError(String(err)));
  }, []);

  useEffect(() => {
    if (!loggedIn) return;
    loadConfig().catch((err) => setError(String(err)));
    loadEnv().catch((err) => setError(String(err)));
    refreshStatus().catch((err) => setError(String(err)));
    refreshHealth().catch(() => undefined);
    const timer = window.setInterval(() => {
      refreshStatus().catch(() => undefined);
      refreshHealth().catch(() => undefined);
    }, 3000);
    return () => window.clearInterval(timer);
  }, [loggedIn]);

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

  async function handleStart() {
    setError("");
    setMessage("");
    const parsedPort = Number(port);
    const usePort = Number.isFinite(parsedPort) ? parsedPort : undefined;
    try {
      const next = await invoke<RunStatus>("start_litellm", {
        port: usePort,
        host,
      });
      setStatus(next);
      setTab("status");
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

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <div className="brand-mark">LL</div>
          <div>
            <div className="brand-title">LiteLLM Desktop</div>
            <div className="brand-subtitle">本地封装 · Windows / Linux</div>
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
                />
              </label>
              <label>
                密码
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
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
              <button className="primary" onClick={handleStart}>
                启动 LiteLLM
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
            <div className="button-row">
              <button className="ghost" onClick={refreshStatus}>
                刷新状态
              </button>
              <button className="primary" onClick={handleStop}>
                停止 LiteLLM
              </button>
            </div>
            <div className="log-panel">
              <div className="log-header">
                <span>日志输出</span>
                <span className="muted">{status.log_path ?? "-"}</span>
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
