#!/usr/bin/env node
/*
  Mock Token Server (for local testing)

  Usage:
    node scripts/mock_token_server.js

  Env:
    PORT=8787
    MOCK_TOKEN=demo-token
    EXPIRES_IN=3600
*/

const http = require('http');
const { parse } = require('url');

const port = Number(process.env.PORT || 8787);
const staticToken = process.env.MOCK_TOKEN || '';
const expiresIn = Number(process.env.EXPIRES_IN || 3600);

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1024 * 1024) {
        reject(new Error('payload too large'));
      }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const { pathname } = parse(req.url || '/');

  if (req.method === 'GET' && pathname === '/health') {
    return json(res, 200, { ok: true });
  }

  if (req.method !== 'POST' || pathname !== '/token') {
    return json(res, 404, { error: 'not_found' });
  }

  try {
    const bodyRaw = await readBody(req);
    const payload = bodyRaw ? JSON.parse(bodyRaw) : {};
    const employeeId = String(payload.employee_id || '').trim();
    const password = String(payload.password || '').trim();

    if (!employeeId || !password) {
      return json(res, 400, { error: 'employee_id and password required' });
    }

    const token = staticToken || `test-token-${Date.now()}`;
    const response = {
      token,
      expires_in: expiresIn,
      project_id: payload.project_id || null,
      project_name: payload.project_name || null,
    };

    return json(res, 200, response);
  } catch (err) {
    return json(res, 400, { error: String(err.message || err) });
  }
});

server.listen(port, () => {
  console.log(`Mock token server listening on http://localhost:${port}/token`);
});
