#!/usr/bin/env node
// EDEN Guild - shared data server (merge + authoritative APIs)
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = '/var/lib/eden';
const DATA_FILE = path.join(DATA_DIR, 'data.json');
const PORT = 8080;

const EMPTY = {
  users: [],
  codes: [],
  donations: [],
  power: [],
  formations: [],
  donateRankHistory: {},
  vault: {},
  building: { tower: 1, magic: {}, hall: 1 }
};

function ensureData() {
  try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(EMPTY));
  }
}

function readData() {
  try {
    const d = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    for (const k of Object.keys(EMPTY)) {
      if (!(k in d)) d[k] = JSON.parse(JSON.stringify(EMPTY[k]));
    }
    return d;
  } catch (e) {
    return JSON.parse(JSON.stringify(EMPTY));
  }
}

function writeData(obj) {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj));
  fs.renameSync(tmp, DATA_FILE);
}

function send(res, code, body) {
  const payload = JSON.stringify(body);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(payload);
}

function readBody(req, cb) {
  let raw = '';
  req.on('data', (chunk) => { raw += chunk; if (raw.length > 30 * 1024 * 1024) { req.destroy(); } });
  req.on('end', () => {
    try { cb(JSON.parse(raw || '{}')); }
    catch (e) { cb(null); }
  });
}

function now() { return new Date().toISOString(); }

// Merge a client full-state push into server data.
// Server data is authoritative. users/codes/donations/power are ONLY written
// via dedicated APIs, so client push must NOT re-add locally cached records
// (otherwise deleted users/codes/reviews get resurrected).
function mergeState(cur, inc) {
  if (!inc || typeof inc !== 'object') return;
  // users: 服务器为主；仅服务器为空（首次初始化 seed）时接受客户端
  if (Array.isArray(inc.users) && cur.users.length === 0) {
    cur.users = inc.users.filter(u => u && u.username);
  }
  // codes: 服务器为主；仅服务器为空时接受客户端 seed
  if (Array.isArray(inc.codes) && cur.codes.length === 0) {
    cur.codes = inc.codes.filter(c => c && c.code);
  }
  // donations / power: 完全服务器权威（所有变更走 API），客户端 push 忽略
  if (inc.vault && typeof inc.vault === 'object') {
    const curVault = cur.vault || {};
    for (const k of Object.keys(inc.vault)) {
      // 服务器为准；客户端有而服务器没有的资源项并入（保护已有数据）
      if (!(k in curVault)) curVault[k] = inc.vault[k];
    }
    cur.vault = curVault;
  }
  if (inc.building && typeof inc.building === 'object') {
    const curB = cur.building || {};
    for (const k of Object.keys(inc.building)) {
      if (!(k in curB)) curB[k] = inc.building[k];
    }
    cur.building = curB;
  }
  // formations & donateRankHistory: server wins entirely (rarely written)
}

ensureData();

// ================= security layer =================
const AUTH_LOG = path.join(DATA_DIR, 'auth.log');
const SESSION_TTL = 24 * 3600 * 1000; // 登录会话有效期 24 小时
const MAX_ATTEMPTS = 5;               // 同一 IP+账号 5 次失败
const LOCK_MS = 15 * 60 * 1000;       // 锁定 15 分钟
const sessions = new Map();           // token -> { username, role, expiresAt }
const failMap = new Map();            // 'ip|username' -> { count, firstAt }

function clientIP(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return req.socket.remoteAddress || '?';
}
function authLog(line) {
  try { fs.appendFileSync(AUTH_LOG, '[' + new Date().toLocaleString('zh-CN') + '] ' + line + '\n'); } catch (e) {}
}
function isLocked(ip, username) {
  const rec = failMap.get(ip + '|' + username);
  if (!rec) return false;
  if (Date.now() - rec.firstAt > LOCK_MS) { failMap.delete(ip + '|' + username); return false; }
  return rec.count >= MAX_ATTEMPTS;
}
function recordFail(ip, username) {
  const key = ip + '|' + username;
  const rec = failMap.get(key);
  if (!rec || Date.now() - rec.firstAt > LOCK_MS) failMap.set(key, { count: 1, firstAt: Date.now() });
  else rec.count++;
  return failMap.get(key).count;
}
function clearFails(ip, username) { failMap.delete(ip + '|' + username); }
function issueSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, role: user.role, expiresAt: Date.now() + SESSION_TTL });
  return token;
}
function getSession(req) {
  const token = String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (s.expiresAt < Date.now()) { sessions.delete(token); return null; }
  return s;
}
function requireAdmin(req, res, next) {
  const s = getSession(req);
  if (!s) return send(res, 401, { ok: false, error: '未登录或登录已过期' });
  if (s.role !== 'admin') return send(res, 403, { ok: false, error: '无管理权限' });
  next(s);
}
function requireUser(req, res, next) {
  const s = getSession(req);
  if (!s) return send(res, 401, { ok: false, error: '未登录或登录已过期' });
  next(s);
}
// 对外下发的用户对象必须脱敏：任何响应都不携带明文密码
function publicUser(u) {
  if (!u) return u;
  const clean = {};
  for (const k of Object.keys(u)) if (k !== 'password') clean[k] = u[k];
  return clean;
}
function publicData(d) {
  const out = JSON.parse(JSON.stringify(d));
  if (Array.isArray(out.users)) out.users = out.users.map(publicUser);
  return out;
}
// ==================================================

const server = http.createServer((req, res) => {
  const url = req.url || '/';
  const api = url.split('?')[0];

  // ---- unified auth gate ----
  // admin-only endpoints: need an admin session token
  const ADMIN_ONLY = ['/api/admin/add-codes', '/api/admin/gen-codes', '/api/admin/set-perm', '/api/admin/del-code', '/api/admin/del-user', '/api/admin/review', '/api/admin/set-title', '/api/admin/unbind-machine', '/api/admin/allow-device', '/api/admin/change-password', '/api/vault', '/api/vault-del'];
  if (ADMIN_ONLY.indexOf(api) !== -1) {
    const s = getSession(req);
    if (!s) return send(res, 401, { ok: false, error: '未登录或登录已过期' });
    if (s.role !== 'admin') return send(res, 403, { ok: false, error: '无管理权限' });
    req.authSession = s;
  }
  // user-only endpoints: need any valid session token (owner check done inside)
  const USER_ONLY = ['/api/user-update', '/api/donation', '/api/power-report', '/api/building'];
  if (USER_ONLY.indexOf(api) !== -1) {
    const s = getSession(req);
    if (!s) return send(res, 401, { ok: false, error: '未登录或登录已过期' });
    req.authSession = s;
  }
  // session-only endpoints: any valid session token (data sync carries sensitive data)
  const SESSION_ONLY = ['/api/sync'];
  if (SESSION_ONLY.indexOf(api) !== -1) {
    const s = getSession(req);
    if (!s) return send(res, 401, { ok: false, error: '未登录或登录已过期' });
    req.authSession = s;
  }
  // ---- read full state (sanitized: no plaintext passwords) ----
  if (req.method === 'GET' && api === '/api/sync') {
    send(res, 200, publicData(readData()));
    return;
  }

  // ---- full-state push (merge, server authoritative) ----
  if (req.method === 'POST' && api === '/api/sync') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const cur = readData();
      mergeState(cur, b);
      writeData(cur);
      send(res, 200, { ok: true });
    });
    return;
  }

  // ---- register: server-authoritative code validation + atomic consume ----
  if (req.method === 'POST' && api === '/api/register') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const username = String(b.username || '').trim();
      const gameId = String(b.gameId || '').trim();
      const password = String(b.password || '');
      const code = String(b.code || '').trim().toUpperCase();
      if (!username || !gameId || !password || !code) return send(res, 400, { ok: false, error: '参数不完整' });
      const machine = String(b.machine || '').trim().slice(0, 64);
      if (!machine) return send(res, 400, { ok: false, error: '缺少设备信息，请刷新浏览器后重试' });
      const dt = b.deviceType === 'mobile' ? 'mobile' : 'desktop'; // 设备类型：mobile/desktop
      const cur = readData();
      if (cur.users.some(u => u.username === username)) return send(res, 409, { ok: false, error: '用户名已存在' });
      const ci = cur.codes.findIndex(c => c.code === code && !c.used);
      if (ci === -1) return send(res, 400, { ok: false, error: '激活码无效或已被使用' });
      cur.codes[ci].used = true; cur.codes[ci].usedBy = username; cur.codes[ci].usedAt = now();
      const user = { username, gameId, password, avatar: '', role: 'member', joinDate: now(), machine1: machine, deviceType1: dt };
      cur.users.push(user);
      writeData(cur);
      const regToken = issueSession(user);
      send(res, 200, { ok: true, user: publicUser(user), token: regToken });
    });
    return;
  }

  // ---- login (member: device-bound) ----
  if (req.method === 'POST' && api === '/api/login') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const ip = clientIP(req);
      const username = String(b.username || '').trim();
      if (isLocked(ip, username)) return send(res, 429, { ok: false, error: '尝试次数过多，请 15 分钟后再试' });
      const machine = String(b.machine || '').trim().slice(0, 64);
      if (!machine) return send(res, 400, { ok: false, error: '缺少设备信息，请刷新浏览器后重试' });
      const dt = b.deviceType === 'mobile' ? 'mobile' : 'desktop';
      const cur = readData();
      const u = cur.users.find(x => x.username === username && x.password === String(b.password || ''));
      if (!u) {
        const n = recordFail(ip, username);
        authLog('LOGIN_FAIL ip=' + ip + ' user=' + username + ' attempt=' + n);
        return send(res, 401, { ok: false, error: '用户名或密码错误' });
      }
      clearFails(ip, username);
      // 管理员账号只能在管理端（/admin）登录，客户端仅服务会员
      if (u.role === 'admin') return send(res, 403, { ok: false, error: '管理员账号请通过管理入口登录（网址后加 /admin）' });
      // 设备绑定：仅会员账号受控（管理员账号为公会自用，多设备可登录）
      // 每账号最多 2 台设备（machine1/machine2），新设备登录需管理员授权
      if (u.role !== 'admin') {
        const m1 = u.machine1 || u.machine || '';
        if (!m1) {
          u.machine1 = machine;
          u.deviceType1 = dt;
          writeData(cur);
          authLog('LOGIN_BIND ip=' + ip + ' user=' + username);
        } else if (m1 === machine || (u.machine2 && u.machine2 === machine)) {
          // 已绑定设备，放行
        } else {
          // 异设备：记录待授权指纹与设备类型，403 提示
          u.pendingMachine = machine;
          u.pendingDeviceType = dt;
          writeData(cur);
          if (u.machine2) {
            authLog('LOGIN_PENDING_FULL ip=' + ip + ' user=' + username);
            return send(res, 403, { ok: false, error: '该账号已绑定 2 台设备，如需更换设备请联系管理员解绑', code: 'device_full' });
          }
          authLog('LOGIN_PENDING_DEVICE ip=' + ip + ' user=' + username);
          return send(res, 403, { ok: false, error: '新设备登录申请已提交，请等待管理员授权后重试', code: 'pending_device' });
        }
      }
      const token = issueSession(u);
      authLog('LOGIN_OK ip=' + ip + ' user=' + username);
      send(res, 200, { ok: true, user: publicUser(u), token: token });
    });
    return;
  }

  // ---- admin: account/password login (no device binding) ----
  if (req.method === 'POST' && api === '/api/admin/login') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const ip = clientIP(req);
      const username = String(b.username || '').trim();
      if (isLocked(ip, username)) return send(res, 429, { ok: false, error: '尝试次数过多，账号已锁定 15 分钟' });
      const u = readData().users.find(x => x.username === username && x.password === String(b.password || '') && x.role === 'admin');
      if (!u) {
        const n = recordFail(ip, username);
        authLog('ADMIN_LOGIN_FAIL ip=' + ip + ' user=' + username + ' attempt=' + n);
        return send(res, 401, { ok: false, error: '管理员账号或密码错误' });
      }
      clearFails(ip, username);
      const token = issueSession(u);
      authLog('ADMIN_LOGIN_OK ip=' + ip + ' user=' + username);
      send(res, 200, { ok: true, user: publicUser(u), token: token });
    });
    return;
  }

  // ---- admin: add activation codes (single or batch) ----
  if (req.method === 'POST' && api === '/api/admin/add-codes') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const list = Array.isArray(b.codes) ? b.codes : [];
      const cur = readData();
      const map = {};
      cur.codes.forEach(c => { map[c.code] = c; });
      let added = 0;
      list.forEach(raw => {
        const code = String(raw || '').trim().toUpperCase();
        if (!/^EDEN-[A-Z0-9]+$/.test(code) || map[code]) return;
        map[code] = { code, used: false, createdBy: 'admin', createdAt: now() };
        added++;
      });
      cur.codes = Object.values(map);
      writeData(cur);
      send(res, 200, { ok: true, added });
    });
    return;
  }

  // ---- admin: generate N random codes ----
  if (req.method === 'POST' && api === '/api/admin/gen-codes') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const count = Math.min(500, Math.max(1, parseInt(b.count, 10) || 1));
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      const cur = readData();
      const map = {};
      cur.codes.forEach(c => { map[c.code] = c; });
      let added = 0, tries = 0;
      while (added < count && tries < count * 20) {
        let code = 'EDEN-';
        for (let i = 0; i < 8; i++) code += chars.charAt(Math.floor(Math.random() * chars.length));
        tries++;
        if (map[code]) continue;
        map[code] = { code, used: false, createdBy: 'admin', createdAt: now() };
        added++;
      }
      cur.codes = Object.values(map);
      writeData(cur);
      send(res, 200, { ok: true, added });
    });
    return;
  }

  // ---- admin: set vault access permission for a user ----
  if (req.method === 'POST' && api === '/api/admin/set-perm') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const username = String(b.username || '').trim();
      const perm = String(b.perm || ''); // 'vault' | 'formation'
      const enabled = !!b.enabled;
      const cur = readData();
      const idx = cur.users.findIndex(u => u.username === username);
      if (idx === -1) return send(res, 404, { ok: false, error: '用户不存在' });
      if (perm === 'formation') {
        if (enabled) cur.users[idx].permFormation = true; else delete cur.users[idx].permFormation;
      } else if (perm === 'building') {
        if (enabled) cur.users[idx].permBuilding = true; else delete cur.users[idx].permBuilding;
      } else {
        if (enabled) cur.users[idx].permVault = true; else delete cur.users[idx].permVault;
      }
      writeData(cur);
      send(res, 200, { ok: true, user: publicUser(cur.users[idx]) });
    });
    return;
  }

  // ---- admin: delete a code ----
  if (req.method === 'POST' && api === '/api/admin/del-code') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const code = String(b.code || '').trim().toUpperCase();
      const cur = readData();
      cur.codes = cur.codes.filter(c => c.code !== code);
      writeData(cur);
      send(res, 200, { ok: true });
    });
    return;
  }

  // ---- admin: change own password (backend-only) ----
  if (req.method === 'POST' && api === '/api/admin/change-password') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const username = req.authSession ? req.authSession.username : '';
      if (!username) return send(res, 401, { ok: false, error: '未登录' });
      const oldPwd = String(b.oldPassword || '');
      const newPwd = String(b.newPassword || '');
      if (!newPwd) return send(res, 400, { ok: false, error: '新密码不能为空' });
      if (newPwd.length < 3) return send(res, 400, { ok: false, error: '新密码至少 3 位' });
      const cur = readData();
      const idx = cur.users.findIndex(u => u.username === username);
      if (idx === -1) return send(res, 404, { ok: false, error: '账号不存在' });
      if (cur.users[idx].password !== oldPwd) return send(res, 403, { ok: false, error: '当前密码错误' });
      cur.users[idx].password = newPwd;
      writeData(cur);
      authLog('ADMIN_CHANGE_PASSWORD user=' + username);
      send(res, 200, { ok: true });
    });
    return;
  }

  // ---- admin: delete a user ----
  if (req.method === 'POST' && api === '/api/admin/del-user') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const username = String(b.username || '').trim();
      const cur = readData();
      cur.users = cur.users.filter(u => u.username !== username);
      // 销毁该用户所有登录会话：删除后立即强制下线
      for (const [tk, s] of sessions) { if (s.username === username) sessions.delete(tk); }
      writeData(cur);
      authLog('DEL_USER user=' + username + ' by=' + (req.authSession ? req.authSession.username : '?'));
      send(res, 200, { ok: true });
    });
    return;
  }

  // ---- admin: unbind a specific device or all devices ----
  // device: '1' | '2' | 'all'（默认 all，向后兼容）
  if (req.method === 'POST' && api === '/api/admin/unbind-machine') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const username = String(b.username || '').trim();
      const device = String(b.device || 'all');
      if (['1', '2', 'all'].indexOf(device) === -1) return send(res, 400, { ok: false, error: '无效的解绑目标' });
      const cur = readData();
      const idx = cur.users.findIndex(u => u.username === username);
      if (idx === -1) return send(res, 404, { ok: false, error: '用户不存在' });
      if (cur.users[idx].role === 'admin') return send(res, 403, { ok: false, error: '管理员账号无需解绑' });
      const u = cur.users[idx];
      if (device === '1') {
        delete u.machine1;
        delete u.machine; // 兼容旧字段
        delete u.deviceType1;
        // 设备2 自动升级为设备1，保持槽位整洁
        if (u.machine2) { u.machine1 = u.machine2; delete u.machine2; u.deviceType1 = u.deviceType2; delete u.deviceType2; }
      } else if (device === '2') {
        delete u.machine2;
        delete u.deviceType2;
      } else {
        delete u.machine1; delete u.machine2; delete u.machine;
        delete u.deviceType1; delete u.deviceType2;
      }
      delete u.pendingMachine; delete u.pendingDeviceType; // 解绑后旧待授权申请作废，需重新登录提交
      writeData(cur);
      authLog('UNBIND_MACHINE user=' + username + ' device=' + device + ' by=' + (req.authSession ? req.authSession.username : '?'));
      send(res, 200, { ok: true, user: publicUser(u) });
    });
    return;
  }

  // ---- admin: authorize a pending new device (2nd device slot) ----
  if (req.method === 'POST' && api === '/api/admin/allow-device') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const username = String(b.username || '').trim();
      const cur = readData();
      const idx = cur.users.findIndex(u => u.username === username);
      if (idx === -1) return send(res, 404, { ok: false, error: '用户不存在' });
      if (cur.users[idx].role === 'admin') return send(res, 403, { ok: false, error: '管理员账号无需授权' });
      if (!cur.users[idx].pendingMachine) return send(res, 400, { ok: false, error: '该账号没有待授权的新设备' });
      cur.users[idx].machine2 = cur.users[idx].pendingMachine;
      cur.users[idx].deviceType2 = cur.users[idx].pendingDeviceType || 'desktop';
      delete cur.users[idx].pendingMachine;
      delete cur.users[idx].pendingDeviceType;
      writeData(cur);
      authLog('ALLOW_DEVICE user=' + username + ' by=' + (req.authSession ? req.authSession.username : '?'));
      send(res, 200, { ok: true, user: publicUser(cur.users[idx]) });
    });
    return;
  }

  // ---- user update: password / avatar ----
  if (req.method === 'POST' && api === '/api/user-update') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const username = String(b.username || '').trim();
      if (username !== req.authSession.username) return send(res, 403, { ok: false, error: '只能修改自己的账号' });
      const cur = readData();
      const idx = cur.users.findIndex(u => u.username === username);
      if (idx === -1) return send(res, 404, { ok: false, error: '用户不存在' });
      if (b.password) {
        // 修改密码必须校验当前密码（服务器权威校验）
        if (String(b.oldPassword || '') !== cur.users[idx].password) return send(res, 403, { ok: false, error: '当前密码错误' });
        cur.users[idx].password = String(b.password);
      }
      if (typeof b.avatar === 'string') {
        if (b.avatar.length > 400000) return send(res, 400, { ok: false, error: '头像图片过大，请使用小于 300KB 的图片' });
        cur.users[idx].avatar = b.avatar;
      }
      writeData(cur);
      send(res, 200, { ok: true, user: publicUser(cur.users[idx]) });
    });
    return;
  }

  // ---- submit donation (server append) ----
  if (req.method === 'POST' && api === '/api/donation') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      if (String(b.username || '') !== req.authSession.username) return send(res, 403, { ok: false, error: '请登录自己的账号后操作' });
      const cur = readData();
      const rec = {
        id: Date.now(),
        username: String(b.username || ''),
        gameId: String(b.gameId || ''),
        type: String(b.type || ''),
        amount: String(b.amount || '0'),
        image: String(b.image || ''),
        note: String(b.note || ''),
        status: 'pending',
        createdAt: now()
      };
      cur.donations.push(rec);
      writeData(cur);
      send(res, 200, { ok: true, id: rec.id });
    });
    return;
  }

  // ---- submit power report (server append) ----
  if (req.method === 'POST' && api === '/api/power-report') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      if (String(b.username || '') !== req.authSession.username) return send(res, 403, { ok: false, error: '请登录自己的账号后操作' });
      const cur = readData();
      const rec = {
        id: Date.now(),
        username: String(b.username || ''),
        gameId: String(b.gameId || ''),
        profession: String(b.profession || ''),
        power: String(b.power || '0'),
        hp: String(b.hp || ''),
        atk: String(b.atk || ''),
        note: String(b.note || ''),
        status: 'pending',
        createdAt: now()
      };
      cur.power.push(rec);
      writeData(cur);
      send(res, 200, { ok: true, id: rec.id });
    });
    return;
  }

  // ---- admin: approve/reject donation or power ----
  if (req.method === 'POST' && api === '/api/admin/review') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const kind = b.kind === 'power' ? 'power' : 'donations';
      const cur = readData();
      const arr = cur[kind];
      const idx = arr.findIndex(x => x.id === parseInt(b.id, 10));
      if (idx === -1) return send(res, 404, { ok: false, error: '记录不存在' });
      if (b.status === 'deleted') {
        arr.splice(idx, 1);
      } else {
        arr[idx].status = b.status === 'rejected' ? 'rejected' : 'approved';
        arr[idx].reviewedAt = now();
      }
      writeData(cur);
      send(res, 200, { ok: true });
    });
    return;
  }

  // ---- admin: set custom title/role for a user ----
  if (req.method === 'POST' && api === '/api/admin/set-title') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const username = String(b.username || '').trim();
      const title = String(b.title || '').trim().slice(0, 20);
      const cur = readData();
      const idx = cur.users.findIndex(u => u.username === username);
      if (idx === -1) return send(res, 404, { ok: false, error: '用户不存在' });
      if (title) cur.users[idx].title = title; else delete cur.users[idx].title;
      writeData(cur);
      send(res, 200, { ok: true, user: publicUser(cur.users[idx]) });
    });
    return;
  }

  // ---- admin: save vault (guild treasury) ----
  if (req.method === 'POST' && api === '/api/vault') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const items = b.items && typeof b.items === 'object' ? b.items : {};
      const cur = readData();
      const vault = cur.vault || {};
      for (const k of Object.keys(items)) {
        const n = parseInt(items[k], 10);
        if (!isNaN(n) && n >= 0) vault[k] = n;
      }
      cur.vault = vault;
      writeData(cur);
      send(res, 200, { ok: true, vault: cur.vault });
    });
    return;
  }

  // ---- delete a vault resource ----
  if (req.method === 'POST' && api === '/api/vault-del') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const name = String(b.name || '').trim();
      const cur = readData();
      if (!name) return send(res, 400, { ok: false, error: '资源名称不能为空' });
      if (cur.vault && name in cur.vault) delete cur.vault[name];
      writeData(cur);
      send(res, 200, { ok: true, vault: cur.vault || {} });
    });
    return;
  }

  // ---- upgrade building (tower / magic branches) ----
  var MAGIC_BRANCHES = ['power', 'shield', 'crown', 'defense', 'rhythm', 'staff'];
  if (req.method === 'POST' && api === '/api/building') {
    readBody(req, (b) => {
      if (!b) return send(res, 400, { ok: false, error: 'bad json' });
      const type = String(b.type || '');
      const cur = readData();
      const bd = cur.building || { tower: 1, magic: {}, hall: 1 };
      if (!bd.tower) bd.tower = 1;
      if (!bd.hall) bd.hall = 1;
      if (!bd.magic || typeof bd.magic !== 'object') bd.magic = {};
      let curLv, isTower, isHall = false;
      if (type === 'tower') { curLv = parseInt(bd.tower, 10) || 1; isTower = true; }
      else if (type === 'hall') { curLv = parseInt(bd.hall, 10) || 1; isTower = false; isHall = true; }
      else if (MAGIC_BRANCHES.indexOf(type) !== -1) { if (!bd.magic[type]) bd.magic[type] = 1; curLv = parseInt(bd.magic[type], 10) || 1; isTower = false; }
      else return send(res, 400, { ok: false, error: '无效建筑类型' });
      // 直接修改等级（不扣材料）——仅管理员
      if (b.setLv !== undefined) {
        if (req.authSession.role !== 'admin') return send(res, 403, { ok: false, error: '无管理权限' });
        const lv = parseInt(b.setLv, 10);
        if (isNaN(lv) || lv < 0 || lv > 999) return send(res, 400, { ok: false, error: '等级需在 0-999 之间' });
        if (isTower) bd.tower = lv; else if (isHall) bd.hall = lv; else bd.magic[type] = lv;
        cur.building = bd;
        writeData(cur);
        return send(res, 200, { ok: true, building: cur.building });
      }
      // 升级消耗材料由管理员填写（costs: {材料名: 数量}）
      const costs = b.costs && typeof b.costs === 'object' ? b.costs : {};
      const costEntries = Object.keys(costs).filter(function(k) { return parseInt(costs[k], 10) > 0; });
      if (costEntries.length === 0) return send(res, 400, { ok: false, error: '请填写升级所需材料' });
      const vault = cur.vault || {};
      const missing = {};
      costEntries.forEach(function(k) {
        const need = parseInt(costs[k], 10);
        if ((vault[k] || 0) < need) missing[k] = need - (vault[k] || 0);
      });
      if (Object.keys(missing).length > 0) {
        return send(res, 400, { ok: false, error: '资源不足', need: costs, missing: missing });
      }
      // 扣除材料 + 升级
      costEntries.forEach(function(k) { vault[k] = (vault[k] || 0) - parseInt(costs[k], 10); });
      cur.vault = vault;
      if (isTower) bd.tower = Math.min(999, curLv + 1);
      else if (isHall) bd.hall = Math.min(999, curLv + 1);
      else bd.magic[type] = Math.min(999, curLv + 1);
      cur.building = bd;
      writeData(cur);
      send(res, 200, { ok: true, building: cur.building, vault: cur.vault, costs: costs });
    });
    return;
  }

  send(res, 404, { ok: false, error: 'not found' });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('eden-api listening on 127.0.0.1:' + PORT);
});
