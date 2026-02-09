# LiteLLM Bridge

面向企业内网场景的 LiteLLM 桌面封装，提供一键启动的本地代理服务，并带有配置管理、环境变量管理与运行状态监控。适合在无法从源码直接启动 LiteLLM 的环境中使用。

## 功能概览
- 一键启动/停止 LiteLLM sidecar
- LiteLLM 配置文件管理（YAML）
- 环境变量管理（Linux / Windows 格式预览）
- 运行状态与健康检查
- 日志查看、清空与轮转（单文件 100MB，最多 3 份）

## 使用流程
1. 下载并安装发布包  
   - Linux: `AppImage` / `deb`
   - Windows: `msi`

2. 首次启动创建本地账号  
   - 账号与密码仅保存在本机配置目录

3. 配置 LiteLLM  
   - 打开「配置」页面，填写 LiteLLM `config.yaml` 内容
   - 保存后再启动服务

4. （可选）配置环境变量  
   - 在「环境变量」页面添加/启用变量
   - 保存后会自动重启 sidecar 使其生效

5. 启动服务  
   - 在「运行状况」页点击“启动”
   - 健康检查会按设置间隔轮询

6. 查看日志  
   - 运行状况页展示实时日志
   - 可一键清空日志，或打开日志目录

## 关键路径（以 UI 中“显示路径”为准）
应用内提供“显示路径”按钮以查看实际路径，常用文件包括：
- LiteLLM 配置文件：`config.yaml`
- 环境变量文件：`env.json`
- 日志目录与日志文件：`litellm.log`
- sidecar 可执行文件：`litellm_server`

## 常见问题
**1) sidecar 未找到**  
请设置环境变量 `LITELLM_SIDECAR_PATH` 指向 `litellm_server` 可执行文件。

**2) 环境变量未生效**  
请在保存环境变量后确认 sidecar 已自动重启（或手动重启）。

**3) 日志太大**  
默认单文件 100MB，超过自动轮转，最多保留 3 份。

## 开发与构建
### 本地开发
```bash
npm install
npm run tauri:dev
```

### 打包构建
```bash
npm run tauri:build
```

### Sidecar 构建
构建流程已在 CI 中集成（Linux/Windows）并启用缓存。  
如需本地构建，可参考 `scripts/build_litellm_server.sh` / `scripts/build_litellm_server.ps1`。

如果需要强制重建 sidecar（例如修改了 `litellm_server.py`），请使用：
```bash
FORCE_SIDECAR_REBUILD=1 bash scripts/build_litellm_server.sh
# 或（Windows PowerShell）
FORCE_SIDECAR_REBUILD=1 pwsh scripts/build_litellm_server.ps1
```

## License
MIT
