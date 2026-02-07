# Mock Token Service

用于本地测试内部 Token 获取流程。

## 启动
```bash
node scripts/mock_token_server.js
```

默认地址：
- `http://localhost:8787/token`

## 环境变量
- `PORT`: 端口，默认 `8787`
- `MOCK_TOKEN`: 固定返回的 token（可选）
- `EXPIRES_IN`: 过期秒数，默认 `3600`

## 请求示例
```bash
curl -X POST http://localhost:8787/token \
  -H 'Content-Type: application/json' \
  -d '{"employee_id":"EMP001","password":"pass","project_id":"proj-1","project_name":"demo"}'
```

## 返回示例
```json
{
  "token": "test-token-1700000000000",
  "expires_in": 3600,
  "project_id": "proj-1",
  "project_name": "demo"
}
```
