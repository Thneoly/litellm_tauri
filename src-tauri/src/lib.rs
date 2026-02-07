// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};

#[derive(Default)]
struct ProcessState {
    child: Option<Child>,
    started_at: Option<u64>,
    port: Option<u16>,
    host: Option<String>,
    log_path: Option<PathBuf>,
}

#[derive(Default)]
struct AppState {
    process: Mutex<ProcessState>,
}

#[derive(Serialize, Deserialize)]
struct AuthFile {
    username: String,
    salt_hex: String,
    password_hash_hex: String,
    created_at: u64,
}

#[derive(Serialize)]
struct AuthStatus {
    has_account: bool,
    username: Option<String>,
}

#[derive(Serialize)]
struct RunStatus {
    running: bool,
    pid: Option<u32>,
    started_at: Option<u64>,
    port: Option<u16>,
    host: Option<String>,
    connections: Option<u32>,
    log_path: Option<String>,
}

#[derive(Serialize)]
struct HealthStatus {
    ok: bool,
    status: Option<u16>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct EnvEntry {
    key: String,
    value: String,
    #[serde(default = "default_env_enabled")]
    enabled: bool,
}

fn default_env_enabled() -> bool {
    true
}

#[derive(Serialize)]
struct RuntimePaths {
    app_config_dir: String,
    auth_file: String,
    config_file: String,
    env_file: String,
    log_dir: String,
    log_file: String,
    resource_dir: Option<String>,
    executable_dir: Option<String>,
    sidecar_path: Option<String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn app_config_dir(app: &AppHandle) -> Result<PathBuf> {
    let dir = app
        .path()
        .app_config_dir()
        .context("app_config_dir unavailable")?;
    fs::create_dir_all(&dir).context("create app config dir")?;
    Ok(dir)
}

fn app_log_dir(app: &AppHandle) -> Result<PathBuf> {
    let dir = app.path().app_log_dir().context("app_log_dir unavailable")?;
    fs::create_dir_all(&dir).context("create app log dir")?;
    Ok(dir)
}

fn auth_file_path(app: &AppHandle) -> Result<PathBuf> {
    Ok(app_config_dir(app)?.join("auth.json"))
}

fn config_file_path(app: &AppHandle) -> Result<PathBuf> {
    let dir = app_config_dir(app)?.join("litellm");
    fs::create_dir_all(&dir).context("create litellm config dir")?;
    Ok(dir.join("config.yaml"))
}

fn env_file_path(app: &AppHandle) -> Result<PathBuf> {
    Ok(app_config_dir(app)?.join("env.json"))
}

fn read_auth_file(app: &AppHandle) -> Result<AuthFile> {
    let path = auth_file_path(app)?;
    let raw = fs::read_to_string(&path).context("read auth file")?;
    let auth = serde_json::from_str(&raw).context("parse auth file")?;
    Ok(auth)
}

fn write_auth_file(app: &AppHandle, auth: &AuthFile) -> Result<()> {
    let path = auth_file_path(app)?;
    let raw = serde_json::to_string_pretty(auth).context("serialize auth file")?;
    fs::write(&path, raw).context("write auth file")?;
    Ok(())
}

fn normalize_env_entries(entries: Vec<EnvEntry>) -> Result<Vec<EnvEntry>> {
    let mut normalized = Vec::new();
    for entry in entries {
        let key = entry.key.trim().to_string();
        if key.is_empty() {
            continue;
        }
        if key.contains('=') || key.contains(char::is_whitespace) {
            return Err(anyhow!("invalid env key: {key}"));
        }
        normalized.push(EnvEntry {
            key,
            value: entry.value,
            enabled: entry.enabled,
        });
    }
    Ok(normalized)
}

fn read_env_entries(app: &AppHandle) -> Result<Vec<EnvEntry>> {
    let path = env_file_path(app)?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let raw = fs::read_to_string(&path).context("read env file")?;
    let entries = serde_json::from_str(&raw).context("parse env file")?;
    Ok(entries)
}

fn write_env_entries(app: &AppHandle, entries: Vec<EnvEntry>) -> Result<()> {
    let normalized = normalize_env_entries(entries)?;
    let path = env_file_path(app)?;
    let raw = serde_json::to_string_pretty(&normalized).context("serialize env file")?;
    fs::write(&path, raw).context("write env file")?;
    Ok(())
}

fn apply_env_entries(cmd: &mut Command, entries: &[EnvEntry]) {
    for entry in entries {
        if entry.enabled {
            cmd.env(&entry.key, &entry.value);
        }
    }
}

fn hash_password(salt: &[u8], password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

fn find_sidecar(app: &AppHandle) -> Result<PathBuf> {
    if let Ok(path) = std::env::var("LITELLM_SIDECAR_PATH") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
    }

    let mut checked: Vec<PathBuf> = Vec::new();

    let mut try_bin_dir = |bin_dir: PathBuf| -> Result<Option<PathBuf>> {
        checked.push(bin_dir.clone());
        let direct = ["litellm_server", "litellm_server.exe"]
            .iter()
            .map(|name| bin_dir.join(name))
            .find(|path| path.exists());

        if let Some(path) = direct {
            return Ok(Some(path));
        }

        if bin_dir.exists() {
            for entry in fs::read_dir(&bin_dir).context("read bin dir")? {
                let entry = entry.context("read bin entry")?;
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("litellm_server") {
                        return Ok(Some(path));
                    }
                }
            }
        }
        Ok(None)
    };

    let resource_dir = app.path().resource_dir().context("resource_dir unavailable")?;
    if let Some(path) = try_bin_dir(resource_dir.join("bin"))? {
        return Ok(path);
    }

    if let Ok(current_dir) = std::env::current_dir() {
        if let Some(path) = try_bin_dir(current_dir.join("bin"))? {
            return Ok(path);
        }
        if let Some(path) = try_bin_dir(current_dir.join("..").join("src-tauri").join("bin"))? {
            return Ok(path);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if let Some(path) = try_bin_dir(dir.join("bin"))? {
                return Ok(path);
            }
        }
    }

    let checked_list = checked
        .iter()
        .map(|p| p.to_string_lossy())
        .collect::<Vec<_>>()
        .join(", ");
    Err(anyhow!(
        "litellm sidecar not found; set LITELLM_SIDECAR_PATH or place it under one of: {checked_list}"
    ))
}

fn open_log_file(path: &Path) -> Result<(Stdio, Stdio)> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .context("open log file")?;
    let stdout = Stdio::from(file.try_clone().context("clone log file")?);
    let stderr = Stdio::from(file);
    Ok((stdout, stderr))
}

fn normalize_config(content: &str) -> String {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        content.to_string()
    }
}

fn resolve_master_key_value(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(env_key) = trimmed.strip_prefix("os.environ/") {
        return std::env::var(env_key).ok();
    }
    Some(trimmed.to_string())
}

fn read_master_key(app: &AppHandle) -> Option<String> {
    let path = config_file_path(app).ok()?;
    let raw = fs::read_to_string(path).ok()?;
    let doc: YamlValue = serde_yaml::from_str(&raw).ok()?;
    let general = doc.get("general_settings")?;
    let master = general.get("master_key")?;
    master.as_str().and_then(resolve_master_key_value)
}

#[tauri::command]
fn auth_status(app: AppHandle) -> Result<AuthStatus, String> {
    let path = auth_file_path(&app).map_err(|e| e.to_string())?;
    if !path.exists() {
        return Ok(AuthStatus {
            has_account: false,
            username: None,
        });
    }
    let auth = read_auth_file(&app).map_err(|e| e.to_string())?;
    Ok(AuthStatus {
        has_account: true,
        username: Some(auth.username),
    })
}

#[tauri::command]
fn auth_register(app: AppHandle, username: String, password: String) -> Result<AuthStatus, String> {
    let path = auth_file_path(&app).map_err(|e| e.to_string())?;
    if path.exists() {
        return Err("account already exists".to_string());
    }
    if username.trim().is_empty() || password.trim().is_empty() {
        return Err("username and password are required".to_string());
    }

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let auth = AuthFile {
        username: username.trim().to_string(),
        salt_hex: hex::encode(salt),
        password_hash_hex: hash_password(&salt, &password),
        created_at: now_unix(),
    };

    write_auth_file(&app, &auth).map_err(|e| e.to_string())?;

    Ok(AuthStatus {
        has_account: true,
        username: Some(auth.username),
    })
}

#[tauri::command]
fn auth_login(app: AppHandle, username: String, password: String) -> Result<bool, String> {
    let auth = read_auth_file(&app).map_err(|e| e.to_string())?;
    if auth.username != username.trim() {
        return Err("invalid username or password".to_string());
    }
    let salt = hex::decode(auth.salt_hex).map_err(|_| "corrupt auth file")?;
    let candidate = hash_password(&salt, &password);
    if candidate != auth.password_hash_hex {
        return Err("invalid username or password".to_string());
    }
    Ok(true)
}

#[tauri::command]
fn load_config(app: AppHandle) -> Result<String, String> {
    let path = config_file_path(&app).map_err(|e| e.to_string())?;
    if !path.exists() {
        return Ok(String::new());
    }
    fs::read_to_string(&path)
        .map_err(|e| e.to_string())
        .map(|content| normalize_config(&content))
}

#[tauri::command]
fn save_config(app: AppHandle, content: String) -> Result<String, String> {
    let path = config_file_path(&app).map_err(|e| e.to_string())?;
    let normalized = normalize_config(&content);
    fs::write(&path, normalized).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
fn load_env(app: AppHandle) -> Result<Vec<EnvEntry>, String> {
    read_env_entries(&app).map_err(|e| e.to_string())
}

#[tauri::command]
fn save_env(app: AppHandle, entries: Vec<EnvEntry>) -> Result<bool, String> {
    write_env_entries(&app, entries).map_err(|e| e.to_string())?;
    Ok(true)
}

#[tauri::command]
fn start_litellm(
    app: AppHandle,
    state: tauri::State<AppState>,
    port: Option<u16>,
    host: Option<String>,
) -> Result<RunStatus, String> {
    let mut process = state.process.lock().map_err(|_| "process lock poisoned")?;

    if let Some(child) = &mut process.child {
        if let Ok(Some(_)) = child.try_wait() {
            process.child = None;
        }
    }

    if process.child.is_some() {
        return Err("litellm already running".to_string());
    }

    let config_path = config_file_path(&app).map_err(|e| e.to_string())?;
    if !config_path.exists() {
        return Err("config.yaml not found; save config first".to_string());
    }

    let log_dir = app_log_dir(&app).map_err(|e| e.to_string())?;
    let log_path = log_dir.join("litellm.log");

    let sidecar = find_sidecar(&app).map_err(|e| e.to_string())?;
    let env_entries = read_env_entries(&app).map_err(|e| e.to_string())?;

    let (stdout, stderr) = open_log_file(&log_path).map_err(|e| e.to_string())?;

    let host = host
        .and_then(|h| if h.trim().is_empty() { None } else { Some(h) })
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let mut cmd = Command::new(&sidecar);
    apply_env_entries(&mut cmd, &env_entries);
    cmd.env("LITELLM_CONFIG_PATH", &config_path);
    if let Some(port) = port {
        cmd.env("LITELLM_PORT", port.to_string());
        cmd.arg("--port");
        cmd.arg(port.to_string());
    }
    cmd.arg("--host");
    cmd.arg(&host);
    cmd.arg("--config");
    cmd.arg(config_path.clone());
    cmd.stdout(stdout);
    cmd.stderr(stderr);

    let child = cmd.spawn().map_err(|e| format!("start litellm: {e}"))?;
    let pid = child.id();

    process.child = Some(child);
    process.started_at = Some(now_unix());
    process.port = port;
    process.host = Some(host.clone());
    process.log_path = Some(log_path.clone());

    Ok(RunStatus {
        running: true,
        pid: Some(pid),
        started_at: process.started_at,
        port: process.port,
        host: process.host.clone(),
        connections: None,
        log_path: Some(log_path.to_string_lossy().to_string()),
    })
}

#[tauri::command]
fn stop_litellm(state: tauri::State<AppState>) -> Result<bool, String> {
    let mut process = state.process.lock().map_err(|_| "process lock poisoned")?;
    if let Some(mut child) = process.child.take() {
        let _ = child.kill();
        let _ = child.wait();
        return Ok(true);
    }
    Ok(false)
}

#[tauri::command]
fn litellm_status(state: tauri::State<AppState>) -> Result<RunStatus, String> {
    let mut process = state.process.lock().map_err(|_| "process lock poisoned")?;

    if let Some(child) = &mut process.child {
        if let Ok(Some(_)) = child.try_wait() {
            process.child = None;
        }
    }

    Ok(RunStatus {
        running: process.child.is_some(),
        pid: process.child.as_ref().map(|c| c.id()),
        started_at: process.started_at,
        port: process.port,
        host: process.host.clone(),
        connections: None,
        log_path: process
            .log_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
    })
}

#[tauri::command]
fn litellm_health(app: AppHandle, state: tauri::State<AppState>) -> Result<HealthStatus, String> {
    let process = state.process.lock().map_err(|_| "process lock poisoned")?;
    let host = process
        .host
        .clone()
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = match process.port {
        Some(port) => port,
        None => {
            return Ok(HealthStatus {
                ok: false,
                status: None,
                error: Some("port not set".to_string()),
            })
        }
    };

    let url = format!("http://{host}:{port}/health");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|e| e.to_string())?;
    // Try to read master_key from config if present, to avoid 401 on /health.
    let master_key = read_master_key(&app);

    let mut req = client.get(url);
    if let Some(key) = master_key {
        let bearer = format!("Bearer {key}");
        req = req.header("Authorization", bearer).header("x-api-key", key);
    }

    match req.send() {
        Ok(resp) => Ok(HealthStatus {
            ok: resp.status().is_success(),
            status: Some(resp.status().as_u16()),
            error: None,
        }),
        Err(err) => Ok(HealthStatus {
            ok: false,
            status: None,
            error: Some(err.to_string()),
        }),
    }
}

#[tauri::command]
fn read_logs(app: AppHandle, max_lines: Option<usize>) -> Result<Vec<String>, String> {
    let log_dir = app_log_dir(&app).map_err(|e| e.to_string())?;
    let log_path = log_dir.join("litellm.log");
    if !log_path.exists() {
        return Ok(vec![]);
    }

    let file = File::open(&log_path).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader
        .lines()
        .filter_map(|line| line.ok())
        .collect();

    let limit = max_lines.unwrap_or(200);
    if lines.len() <= limit {
        return Ok(lines);
    }
    Ok(lines[lines.len() - limit..].to_vec())
}

#[tauri::command]
fn runtime_paths(app: AppHandle) -> Result<RuntimePaths, String> {
    let config_dir = app_config_dir(&app).map_err(|e| e.to_string())?;
    let auth_file = auth_file_path(&app).map_err(|e| e.to_string())?;
    let config_file = config_file_path(&app).map_err(|e| e.to_string())?;
    let env_file = env_file_path(&app).map_err(|e| e.to_string())?;
    let log_dir = app_log_dir(&app).map_err(|e| e.to_string())?;
    let log_file = log_dir.join("litellm.log");

    let resource_dir = app
        .path()
        .resource_dir()
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    let executable_dir = app
        .path()
        .executable_dir()
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    let sidecar_path = find_sidecar(&app)
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    Ok(RuntimePaths {
        app_config_dir: config_dir.to_string_lossy().to_string(),
        auth_file: auth_file.to_string_lossy().to_string(),
        config_file: config_file.to_string_lossy().to_string(),
        env_file: env_file.to_string_lossy().to_string(),
        log_dir: log_dir.to_string_lossy().to_string(),
        log_file: log_file.to_string_lossy().to_string(),
        resource_dir,
        executable_dir,
        sidecar_path,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            auth_status,
            auth_register,
            auth_login,
            load_config,
            save_config,
            load_env,
            save_env,
            start_litellm,
            stop_litellm,
            litellm_status,
            litellm_health,
            read_logs,
            runtime_paths
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
