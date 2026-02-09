// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

use anyhow::{anyhow, Context, Result};
use argon2::PasswordHash;
use argon2::PasswordHasher;
use argon2::PasswordVerifier;
use argon2::password_hash::SaltString;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Emitter, Manager, RunEvent};

#[derive(Default)]
struct ProcessState {
    child: Option<Child>,
    started_at: Option<u64>,
    port: Option<u16>,
    host: Option<String>,
    log_path: Option<PathBuf>,
    log_state: Option<Arc<Mutex<LogState>>>,
    debug_env: bool,
}

#[derive(Clone)]
struct AppState {
    process: Arc<Mutex<ProcessState>>,
    health_client: reqwest::Client,
}

impl Default for AppState {
    fn default() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            process: Arc::new(Mutex::new(ProcessState::default())),
            health_client: client,
        }
    }
}

const LOG_FILE_NAME: &str = "litellm.log";
const MAX_LOG_BYTES: u64 = 100 * 1024 * 1024;
const LOG_HISTORY: usize = 3;
const LOG_EVENT_NAME: &str = "litellm_log";

#[derive(Serialize, Deserialize)]
struct AuthFile {
    username: String,
    #[serde(default)]
    salt_hex: Option<String>,
    #[serde(default)]
    password_hash_hex: Option<String>,
    #[serde(default)]
    password_hash: String,
    created_at: u64,
    #[serde(default)]
    failed_attempts: u32,
    #[serde(default)]
    locked_until: Option<u64>,
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

#[derive(Serialize, Deserialize, Clone)]
struct TokenSettings {
    auth_url: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct TokenInfo {
    token: String,
    fetched_at: u64,
    expires_at: Option<u64>,
    project_id: Option<String>,
    project_name: Option<String>,
    project_extra: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
struct TokenRequest {
    auth_url: String,
    employee_id: String,
    password: String,
    project_id: Option<String>,
    project_name: Option<String>,
    project_extra: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone)]
struct AppSettings {
    health_interval_seconds: u64,
}

#[derive(Serialize, Clone)]
struct LogEvent {
    line: String,
}

#[derive(Serialize)]
struct RuntimePaths {
    app_config_dir: String,
    auth_file: String,
    config_file: String,
    env_file: String,
    token_settings_file: String,
    token_info_file: String,
    log_dir: String,
    log_file: String,
    resource_dir: Option<String>,
    executable_dir: Option<String>,
    sidecar_path: Option<String>,
}

#[derive(Serialize)]
struct LogFileInfo {
    name: String,
    bytes: u64,
}

#[derive(Serialize)]
struct LogStats {
    max_bytes: u64,
    files: Vec<LogFileInfo>,
}
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
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

fn pid_file_path(app: &AppHandle) -> Result<PathBuf> {
    Ok(app_config_dir(app)?.join("litellm.pid"))
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

fn token_settings_path(app: &AppHandle) -> Result<PathBuf> {
    Ok(app_config_dir(app)?.join("token_settings.json"))
}

fn token_info_path(app: &AppHandle) -> Result<PathBuf> {
    Ok(app_config_dir(app)?.join("token_info.json"))
}

fn write_pid_file(app: &AppHandle, pid: u32) -> Result<()> {
    let path = pid_file_path(app)?;
    fs::write(&path, pid.to_string()).context("write pid file")?;
    Ok(())
}

fn clear_pid_file(app: &AppHandle) -> Result<()> {
    let path = pid_file_path(app)?;
    if path.exists() {
        fs::remove_file(&path).context("remove pid file")?;
    }
    Ok(())
}

fn read_pid_file(app: &AppHandle) -> Result<Option<u32>> {
    let path = pid_file_path(app)?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path).context("read pid file")?;
    let pid: u32 = raw.trim().parse().context("parse pid")?;
    Ok(Some(pid))
}

fn kill_pid(pid: u32) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill")
            .arg("-9")
            .arg(pid.to_string())
            .status();
    }
}

fn process_matches_sidecar(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let text = String::from_utf8_lossy(&cmdline);
        return text.contains("litellm_server");
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        return true;
    }
}

fn cleanup_orphan_sidecar(app: &AppHandle) {
    let pid = match read_pid_file(app) {
        Ok(Some(pid)) => pid,
        _ => return,
    };

    if process_matches_sidecar(pid) {
        kill_pid(pid);
    }
    let _ = clear_pid_file(app);
}

fn app_settings_path(app: &AppHandle) -> Result<PathBuf> {
    Ok(app_config_dir(app)?.join("app_settings.json"))
}

fn default_app_settings() -> AppSettings {
    AppSettings {
        health_interval_seconds: 3,
    }
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

fn read_token_settings(app: &AppHandle) -> Result<TokenSettings> {
    let path = token_settings_path(app)?;
    if !path.exists() {
        return Ok(TokenSettings {
            auth_url: String::new(),
        });
    }
    let raw = fs::read_to_string(&path).context("read token settings")?;
    let settings = serde_json::from_str(&raw).context("parse token settings")?;
    Ok(settings)
}

fn write_token_settings(app: &AppHandle, settings: TokenSettings) -> Result<()> {
    let path = token_settings_path(app)?;
    let raw = serde_json::to_string_pretty(&settings).context("serialize token settings")?;
    fs::write(&path, raw).context("write token settings")?;
    Ok(())
}

fn read_app_settings(app: &AppHandle) -> Result<AppSettings> {
    let path = app_settings_path(app)?;
    if !path.exists() {
        return Ok(default_app_settings());
    }
    let raw = fs::read_to_string(&path).context("read app settings")?;
    let settings = serde_json::from_str(&raw).context("parse app settings")?;
    Ok(settings)
}

fn write_app_settings(app: &AppHandle, settings: AppSettings) -> Result<()> {
    let path = app_settings_path(app)?;
    let raw = serde_json::to_string_pretty(&settings).context("serialize app settings")?;
    fs::write(&path, raw).context("write app settings")?;
    Ok(())
}

fn read_token_info(app: &AppHandle) -> Result<Option<TokenInfo>> {
    let path = token_info_path(app)?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path).context("read token info")?;
    let info = serde_json::from_str(&raw).context("parse token info")?;
    Ok(Some(info))
}

fn write_token_info(app: &AppHandle, info: &TokenInfo) -> Result<()> {
    let path = token_info_path(app)?;
    let raw = serde_json::to_string_pretty(info).context("serialize token info")?;
    fs::write(&path, raw).context("write token info")?;
    Ok(())
}

fn extract_token(value: &serde_json::Value) -> Option<String> {
    let direct = value.get("token").and_then(|v| v.as_str());
    if let Some(token) = direct {
        return Some(token.to_string());
    }
    let access = value.get("access_token").and_then(|v| v.as_str());
    if let Some(token) = access {
        return Some(token.to_string());
    }
    value
        .get("data")
        .and_then(|v| v.get("token"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn extract_expires(value: &serde_json::Value) -> Option<u64> {
    if let Some(ts) = value.get("expires_at").and_then(|v| v.as_u64()) {
        return Some(ts);
    }
    if let Some(secs) = value.get("expires_in").and_then(|v| v.as_u64()) {
        return Some(now_unix().saturating_add(secs));
    }
    value
        .get("data")
        .and_then(|v| v.get("expires_at"))
        .and_then(|v| v.as_u64())
}

fn hash_password(salt: &[u8], password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

fn hash_password_argon2(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = argon2::Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!(e))?;
    Ok(hash.to_string())
}

fn verify_password_argon2(hash: &str, password: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow!(e))?;
    let argon2 = argon2::Argon2::default();
    Ok(argon2.verify_password(password.as_bytes(), &parsed).is_ok())
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
            if let Some(path) = try_bin_dir(dir.to_path_buf())? {
                return Ok(path);
            }
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

struct LogState {
    log_dir: PathBuf,
    file: File,
    size: u64,
}

fn log_file_path(log_dir: &Path, index: usize) -> PathBuf {
    if index == 0 {
        log_dir.join(LOG_FILE_NAME)
    } else {
        log_dir.join(format!("{LOG_FILE_NAME}.{index}"))
    }
}

fn rotate_logs(log_dir: &Path) -> Result<()> {
    let oldest = log_file_path(log_dir, LOG_HISTORY);
    if oldest.exists() {
        fs::remove_file(&oldest).context("remove oldest log")?;
    }

    for idx in (1..LOG_HISTORY).rev() {
        let src = log_file_path(log_dir, idx);
        let dst = log_file_path(log_dir, idx + 1);
        if src.exists() {
            fs::rename(&src, &dst).context("rotate log")?;
        }
    }

    let current = log_file_path(log_dir, 0);
    if current.exists() {
        fs::rename(&current, log_file_path(log_dir, 1)).context("rotate current log")?;
    }
    Ok(())
}

fn open_log_state(log_dir: &Path) -> Result<LogState> {
    let path = log_file_path(log_dir, 0);
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .context("open log file")?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    Ok(LogState {
        log_dir: log_dir.to_path_buf(),
        file,
        size,
    })
}

fn rotate_log_state(state: &mut LogState) -> Result<()> {
    state.file.flush().context("flush log file")?;
    rotate_logs(&state.log_dir)?;
    let path = log_file_path(&state.log_dir, 0);
    state.file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .context("open rotated log file")?;
    state.size = 0;
    Ok(())
}

fn write_log_line(state: &mut LogState, line: &str) -> Result<()> {
    state
        .file
        .write_all(line.as_bytes())
        .context("write log line")?;
    state.file.write_all(b"\n").context("write log newline")?;
    state.size = state.size.saturating_add((line.len() + 1) as u64);
    if state.size >= MAX_LOG_BYTES {
        rotate_log_state(state)?;
    }
    Ok(())
}

fn format_log_line(kind: &str, line: &str) -> String {
    format!("[{}] [{}] {}", now_millis(), kind, line)
}

fn spawn_log_thread(
    kind: &'static str,
    stream: impl Read + Send + 'static,
    state: Arc<Mutex<LogState>>,
    app: AppHandle,
) {
    thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines() {
            if let Ok(line) = line {
                let formatted = format_log_line(kind, &line);
                if let Ok(mut guard) = state.lock() {
                    let _ = write_log_line(&mut guard, &formatted);
                }
                let _ = app.emit(LOG_EVENT_NAME, LogEvent { line: formatted });
            }
        }
    });
}

fn tail_lines(path: &Path, max_lines: usize) -> Result<Vec<String>> {
    if max_lines == 0 {
        return Ok(Vec::new());
    }
    let mut file = File::open(path).context("open log file")?;
    let mut pos = file.seek(SeekFrom::End(0)).context("seek log")?;
    if pos == 0 {
        return Ok(Vec::new());
    }

    const CHUNK: usize = 64 * 1024;
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut newline_count = 0usize;

    while pos > 0 && newline_count <= max_lines {
        let read_size = std::cmp::min(CHUNK as u64, pos) as usize;
        pos -= read_size as u64;
        file.seek(SeekFrom::Start(pos)).context("seek log chunk")?;
        let mut buf = vec![0u8; read_size];
        file.read_exact(&mut buf).context("read log chunk")?;
        newline_count += buf.iter().filter(|b| **b == b'\n').count();
        chunks.push(buf);
    }

    chunks.reverse();
    let mut data = Vec::new();
    for chunk in chunks {
        data.extend_from_slice(&chunk);
    }

    let text = String::from_utf8_lossy(&data);
    let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    if lines.len() > max_lines {
        lines = lines.split_off(lines.len() - max_lines);
    }
    Ok(lines)
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

    let hash = hash_password_argon2(&password).map_err(|e| e.to_string())?;

    let auth = AuthFile {
        username: username.trim().to_string(),
        salt_hex: None,
        password_hash_hex: None,
        password_hash: hash,
        created_at: now_unix(),
        failed_attempts: 0,
        locked_until: None,
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
    let now = now_unix();
    if let Some(locked_until) = auth.locked_until {
        if locked_until > now {
            return Err(format!("account locked until {locked_until}"));
        }
    }

    let mut next = auth;

    let mut verified = false;
    if !next.password_hash.trim().is_empty() {
        verified = verify_password_argon2(&next.password_hash, &password)
            .map_err(|e| e.to_string())?;
    } else if let (Some(salt_hex), Some(hash_hex)) =
        (next.salt_hex.as_ref(), next.password_hash_hex.as_ref())
    {
        let salt = hex::decode(salt_hex).map_err(|_| "corrupt auth file")?;
        let candidate = hash_password(&salt, &password);
        verified = candidate == *hash_hex;
        if verified {
            if let Ok(new_hash) = hash_password_argon2(&password) {
                next.password_hash = new_hash;
                next.salt_hex = None;
                next.password_hash_hex = None;
            }
        }
    }

    if !verified {
        next.failed_attempts = next.failed_attempts.saturating_add(1);
        if next.failed_attempts >= 5 {
            next.locked_until = Some(now.saturating_add(60));
        }
        write_auth_file(&app, &next).map_err(|e| e.to_string())?;
        return Err("invalid username or password".to_string());
    }

    next.failed_attempts = 0;
    next.locked_until = None;
    write_auth_file(&app, &next).map_err(|e| e.to_string())?;
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
fn save_env(
    app: AppHandle,
    state: tauri::State<AppState>,
    entries: Vec<EnvEntry>,
) -> Result<bool, String> {
    let previous = read_env_entries(&app).map_err(|e| e.to_string())?;
    write_env_entries(&app, entries).map_err(|e| e.to_string())?;

    let mut process = state.process.lock().map_err(|_| "process lock poisoned")?;
    let was_running = process.child.is_some();
    let port = process.port;
    let host = process.host.clone();
    let debug_env = process.debug_env;

    if !was_running {
        return Ok(true);
    }

    stop_child(&app, &mut process);
    match spawn_litellm(&app, &mut process, port, host.clone(), debug_env) {
        Ok(_) => Ok(true),
        Err(err) => {
            // rollback to previous env settings
            let _ = write_env_entries(&app, previous);
            if was_running {
                let _ = spawn_litellm(&app, &mut process, port, host, debug_env);
            }
            Err(format!("env applied but restart failed; rolled back: {err}"))
        }
    }
}

#[tauri::command]
fn load_app_settings(app: AppHandle) -> Result<AppSettings, String> {
    read_app_settings(&app).map_err(|e| e.to_string())
}

#[tauri::command]
fn save_app_settings(app: AppHandle, settings: AppSettings) -> Result<bool, String> {
    let mut next = settings;
    if next.health_interval_seconds == 0 {
        next = default_app_settings();
    }
    write_app_settings(&app, next).map_err(|e| e.to_string())?;
    Ok(true)
}

#[tauri::command]
fn load_token_settings(app: AppHandle) -> Result<TokenSettings, String> {
    read_token_settings(&app).map_err(|e| e.to_string())
}

#[tauri::command]
fn save_token_settings(app: AppHandle, settings: TokenSettings) -> Result<bool, String> {
    write_token_settings(&app, settings).map_err(|e| e.to_string())?;
    Ok(true)
}

#[tauri::command]
fn load_token_info(app: AppHandle) -> Result<Option<TokenInfo>, String> {
    read_token_info(&app).map_err(|e| e.to_string())
}

#[tauri::command]
fn fetch_internal_token(app: AppHandle, request: TokenRequest) -> Result<TokenInfo, String> {
    let auth_url = request.auth_url.trim();
    if auth_url.is_empty() {
        return Err("auth_url is required".to_string());
    }
    if request.employee_id.trim().is_empty() || request.password.trim().is_empty() {
        return Err("employee_id and password are required".to_string());
    }

    let mut payload = serde_json::json!({
        "employee_id": request.employee_id.trim(),
        "password": request.password,
    });

    if let Some(project_id) = request.project_id.clone().filter(|s| !s.trim().is_empty()) {
        payload["project_id"] = serde_json::Value::String(project_id);
    }
    if let Some(project_name) = request
        .project_name
        .clone()
        .filter(|s| !s.trim().is_empty())
    {
        payload["project_name"] = serde_json::Value::String(project_name);
    }
    if let Some(extra) = request.project_extra.clone() {
        let extra_map = extra
            .as_object()
            .ok_or_else(|| "project_extra must be an object".to_string())?;
        if let Some(map) = payload.as_object_mut() {
            for (key, val) in extra_map {
                map.insert(key.clone(), val.clone());
            }
        }
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .post(auth_url)
        .json(&payload)
        .send()
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let text = resp.text().map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("auth failed: HTTP {} {}", status.as_u16(), text));
    }
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("invalid json: {e}"))?;
    let token = extract_token(&json).ok_or_else(|| "token not found in response".to_string())?;
    let expires_at = extract_expires(&json);

    let info = TokenInfo {
        token,
        fetched_at: now_unix(),
        expires_at,
        project_id: request
            .project_id
            .clone()
            .filter(|s| !s.trim().is_empty()),
        project_name: request
            .project_name
            .clone()
            .filter(|s| !s.trim().is_empty()),
        project_extra: request.project_extra.clone(),
    };
    write_token_info(&app, &info).map_err(|e| e.to_string())?;
    Ok(info)
}

fn stop_child(app: &AppHandle, process: &mut ProcessState) -> bool {
    if let Some(mut child) = process.child.take() {
        let _ = child.kill();
        let _ = child.wait();
        process.started_at = None;
        process.port = None;
        process.host = None;
        process.log_path = None;
        process.log_state = None;
        process.debug_env = false;
        let _ = clear_pid_file(app);
        return true;
    }
    false
}

fn spawn_litellm(
    app: &AppHandle,
    process: &mut ProcessState,
    port: Option<u16>,
    host: Option<String>,
    debug_env: bool,
) -> Result<RunStatus, String> {
    if let Some(child) = &mut process.child {
        if let Ok(Some(_)) = child.try_wait() {
            process.child = None;
        }
    }

    if process.child.is_some() {
        return Err("litellm already running".to_string());
    }

    let config_path = config_file_path(app).map_err(|e| e.to_string())?;
    if !config_path.exists() {
        return Err("config.yaml not found; save config first".to_string());
    }

    let log_dir = app_log_dir(app).map_err(|e| e.to_string())?;
    rotate_logs(&log_dir).map_err(|e| e.to_string())?;
    let log_path = log_file_path(&log_dir, 0);

    let sidecar = find_sidecar(app).map_err(|e| e.to_string())?;
    let env_entries = read_env_entries(app).map_err(|e| e.to_string())?;

    let host = host
        .and_then(|h| if h.trim().is_empty() { None } else { Some(h) })
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let mut cmd = Command::new(&sidecar);
    apply_env_entries(&mut cmd, &env_entries);
    cmd.env("LITELLM_CONFIG_PATH", &config_path);
    if debug_env {
        cmd.env("LITELLM_DEBUG_ENV", "1");
    }
    if let Some(port) = port {
        cmd.env("LITELLM_PORT", port.to_string());
        cmd.arg("--port");
        cmd.arg(port.to_string());
    }
    cmd.arg("--host");
    cmd.arg(&host);
    cmd.arg("--config");
    cmd.arg(config_path.clone());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("start litellm: {e}"))?;
    let pid = child.id();
    let _ = write_pid_file(app, pid);

    let log_state = Arc::new(Mutex::new(
        open_log_state(&log_dir).map_err(|e| e.to_string())?,
    ));
    if let Some(stdout) = child.stdout.take() {
        spawn_log_thread("stdout", stdout, log_state.clone(), app.clone());
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_log_thread("stderr", stderr, log_state.clone(), app.clone());
    }

    process.child = Some(child);
    process.started_at = Some(now_unix());
    process.port = port;
    process.host = Some(host.clone());
    process.log_path = Some(log_path.clone());
    process.log_state = Some(log_state.clone());
    process.debug_env = debug_env;

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
async fn start_litellm(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    port: Option<u16>,
    host: Option<String>,
    debug_env: Option<bool>,
) -> Result<RunStatus, String> {
    let app = app.clone();
    let process = state.process.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut process = process.lock().map_err(|_| "process lock poisoned")?;
        spawn_litellm(&app, &mut process, port, host, debug_env.unwrap_or(false))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn stop_litellm(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    let process = state.process.clone();
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut process = process.lock().map_err(|_| "process lock poisoned")?;
        Ok(stop_child(&app, &mut process))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn litellm_status(state: tauri::State<'_, AppState>) -> Result<RunStatus, String> {
    let process = state.process.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut process = process.lock().map_err(|_| "process lock poisoned")?;

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
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn litellm_health(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<HealthStatus, String> {
    let (host, port, master_key) = {
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
        let master_key = read_master_key(&app);
        (host, port, master_key)
    };

    let url = format!("http://{host}:{port}/health");
    let client = state.health_client.clone();

    let mut req = client.get(url);
    if let Some(key) = master_key {
        let bearer = format!("Bearer {key}");
        req = req.header("Authorization", bearer).header("x-api-key", key);
    }

    match req.send().await {
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
async fn read_logs(app: AppHandle, max_lines: Option<usize>) -> Result<Vec<String>, String> {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let log_dir = app_log_dir(&app).map_err(|e| e.to_string())?;
        let log_path = log_file_path(&log_dir, 0);
        if !log_path.exists() {
            return Ok(vec![]);
        }
        let limit = max_lines.unwrap_or(200);
        tail_lines(&log_path, limit).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn log_stats(app: AppHandle) -> Result<LogStats, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let log_dir = app_log_dir(&app).map_err(|e| e.to_string())?;
        let mut files = Vec::new();
        for idx in 0..=LOG_HISTORY {
            let path = log_file_path(&log_dir, idx);
            if let Ok(meta) = fs::metadata(&path) {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("log")
                    .to_string();
                files.push(LogFileInfo {
                    name,
                    bytes: meta.len(),
                });
            }
        }
        Ok(LogStats {
            max_bytes: MAX_LOG_BYTES,
            files,
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn clear_logs(state: tauri::State<'_, AppState>, app: AppHandle) -> Result<bool, String> {
    let process = state.process.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if let Ok(guard) = process.lock() {
            if let Some(state) = guard.log_state.as_ref() {
                if let Ok(mut log_state) = state.lock() {
                    rotate_log_state(&mut log_state).map_err(|e| e.to_string())?;
                    return Ok(true);
                }
            }
        }

        let log_dir = app_log_dir(&app).map_err(|e| e.to_string())?;
        for idx in 0..=LOG_HISTORY {
            let path = log_file_path(&log_dir, idx);
            if path.exists() {
                let _ = fs::remove_file(&path);
            }
        }
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file_path(&log_dir, 0));
        Ok(true)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn runtime_paths(app: AppHandle) -> Result<RuntimePaths, String> {
    let config_dir = app_config_dir(&app).map_err(|e| e.to_string())?;
    let auth_file = auth_file_path(&app).map_err(|e| e.to_string())?;
    let config_file = config_file_path(&app).map_err(|e| e.to_string())?;
    let env_file = env_file_path(&app).map_err(|e| e.to_string())?;
    let token_settings_file = token_settings_path(&app).map_err(|e| e.to_string())?;
    let token_info_file = token_info_path(&app).map_err(|e| e.to_string())?;
    let log_dir = app_log_dir(&app).map_err(|e| e.to_string())?;
    let log_file = log_file_path(&log_dir, 0);

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
        token_settings_file: token_settings_file.to_string_lossy().to_string(),
        token_info_file: token_info_file.to_string_lossy().to_string(),
        log_dir: log_dir.to_string_lossy().to_string(),
        log_file: log_file.to_string_lossy().to_string(),
        resource_dir,
        executable_dir,
        sidecar_path,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            cleanup_orphan_sidecar(&app.handle());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let process = window.app_handle().state::<AppState>().process.clone();
                if let Ok(mut guard) = process.lock() {
                    stop_child(&window.app_handle(), &mut guard);
                };
            }
        })
        .invoke_handler(tauri::generate_handler![
            auth_status,
            auth_register,
            auth_login,
            load_config,
            save_config,
            load_env,
            save_env,
            log_stats,
            clear_logs,
            load_app_settings,
            save_app_settings,
            load_token_settings,
            save_token_settings,
            load_token_info,
            fetch_internal_token,
            start_litellm,
            stop_litellm,
            litellm_status,
            litellm_health,
            read_logs,
            runtime_paths
        ])
        .build(tauri::generate_context!())
        .expect("error while running tauri application");

    app.run(|app_handle, event| {
        if matches!(event, RunEvent::Exit | RunEvent::ExitRequested { .. }) {
            let process = app_handle.state::<AppState>().process.clone();
            if let Ok(mut guard) = process.lock() {
                stop_child(app_handle, &mut guard);
            };
        }
    });
}
