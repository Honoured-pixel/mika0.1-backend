// LYNX relay v0.7
// Host <-> relay <-> browser. The relay never stores anything; it only forwards.
//
// Binary message types (first byte):
//   0x01  host -> viewers   JPEG screen frame
//   0x02  host -> viewers   file download chunk   [0x02][id u32 BE][data]
//   0x03  viewer -> host    file upload chunk     [0x03][id u32 BE][data]
import http from 'node:http';
import crypto from 'node:crypto';
import { WebSocketServer, WebSocket } from 'ws';

const PORT = Number(process.env.PORT || 8080);
const ACCESS_KEY = process.env.LYNX_ACCESS_KEY || '';
if (ACCESS_KEY.length < 24) {
  console.error('Set LYNX_ACCESS_KEY to a random secret at least 24 characters long.');
  process.exit(1);
}

const T_FRAME = 1, T_DOWN = 2, T_UP = 3;
const INPUT_ACTIONS = new Set([
  'mouse_move', 'mouse_down', 'mouse_up', 'wheel', 'key_down', 'key_up', 'key_tap',
  'text', 'release_all', 'set_profile', 'request_admin',
]);
const FILE_OPS = new Set(['list', 'upload_begin', 'upload_end', 'download', 'ack', 'cancel']);
const HOST_TEXT = new Set([
  'host_info', 'file_list', 'file_ready', 'file_ack', 'file_begin', 'file_done', 'file_error', 'notice',
]);

const httpServer = http.createServer((req, res) => {
  if (req.url === '/health') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('LYNX relay online'); return; }
  res.writeHead(404); res.end('Not found');
});
const wss = new WebSocketServer({ noServer: true, maxPayload: 1024 * 1024 });

let host = null;
let lastFrame = null;      // newest JPEG frame (so late/stalled viewers can be refreshed)
let lastHostInfo = null;   // newest host_info JSON string
const viewers = new Set();

const isOpen = ws => !!ws && ws.readyState === WebSocket.OPEN;
const sendJSON = (ws, obj) => { if (isOpen(ws)) ws.send(JSON.stringify(obj)); };
const notifyViewerCount = () => sendJSON(host, { type: 'viewers', count: viewers.size });

function keyMatches(input) {
  if (typeof input !== 'string') return false;
  const a = Buffer.from(input), b = Buffer.from(ACCESS_KEY);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// --- brute-force throttle: 5 bad keys in a minute => that IP is blocked for 5 minutes
const fails = new Map();   // ip -> { n, since }
const blocked = new Map(); // ip -> until
const clientIp = req => (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
function noteFail(ip) {
  const now = Date.now();
  let r = fails.get(ip);
  if (!r || now - r.since > 60000) r = { n: 0, since: now };
  r.n++; fails.set(ip, r);
  if (r.n >= 5) { blocked.set(ip, now + 5 * 60000); fails.delete(ip); }
}
setInterval(() => { const now = Date.now(); for (const [ip, t] of blocked) if (t < now) blocked.delete(ip); }, 60000).unref();

const makeLimiter = max => {
  let start = Date.now(), n = 0;
  return () => { const now = Date.now(); if (now - start >= 1000) { start = now; n = 0; } return ++n <= max; };
};

httpServer.on('upgrade', (req, socket, head) => {
  if (req.url !== '/ws') { socket.destroy(); return; }
  const until = blocked.get(clientIp(req));
  if (until && until > Date.now()) { socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n'); socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});

// --- congestion feedback: tell the host to lower/raise quality when viewers fall behind
let pressure = 0, calm = 0;
setInterval(() => {
  if (!isOpen(host) || viewers.size === 0) { pressure = 0; calm = 0; return; }
  if (pressure >= 3) { sendJSON(host, { type: 'hint', dir: 'down' }); calm = 0; }
  else if (pressure === 0) { if (++calm >= 5) { sendJSON(host, { type: 'hint', dir: 'up' }); calm = 0; } }
  else calm = 0;
  pressure = 0;
}, 2000).unref();

// --- a viewer whose frame was dropped gets the newest frame as soon as it catches up,
//     so a static screen can never stay stuck on an old picture
setInterval(() => {
  if (!lastFrame) return;
  for (const v of viewers) {
    if (v.stale && isOpen(v) && v.bufferedAmount < 100000) { v.stale = false; v.send(lastFrame, { binary: true }); }
  }
}, 250).unref();

// --- app-level heartbeat (browsers cannot see protocol pings) + dead-socket sweep
setInterval(() => { for (const v of viewers) sendJSON(v, { type: 'hb', t: Date.now() }); }, 5000).unref();
setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) { ws.terminate(); continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch { /* ignore */ }
  }
}, 10000).unref();

wss.on('connection', (ws, req) => {
  const ip = clientIp(req);
  let role = null;
  ws.isAlive = true;
  ws.stale = false;
  ws.on('pong', () => { ws.isAlive = true; });
  const inputOk = makeLimiter(400);
  const fileOk = makeLimiter(250);
  const authTimer = setTimeout(() => ws.close(4401, 'Auth timeout'), 8000);

  ws.on('message', (data, isBinary) => {
    ws.isAlive = true;

    // ---- authentication handshake
    if (!role) {
      if (isBinary) { ws.close(4401, 'Authenticate first'); return; }
      let msg; try { msg = JSON.parse(data.toString()); } catch { ws.close(4401, 'Bad auth'); return; }
      if (!keyMatches(msg.key) || !['host', 'viewer'].includes(msg.role)) { noteFail(ip); ws.close(4403, 'Access denied'); return; }
      clearTimeout(authTimer); role = msg.role;
      if (role === 'host') {
        if (isOpen(host)) host.close(4000, 'Host replaced');
        host = ws; lastFrame = null; lastHostInfo = null;
        sendJSON(ws, { type: 'authenticated', role, hostOnline: true });
        for (const v of viewers) sendJSON(v, { type: 'host', online: true });
        notifyViewerCount();
      } else {
        viewers.add(ws);
        sendJSON(ws, { type: 'authenticated', role, hostOnline: isOpen(host) });
        sendJSON(ws, { type: 'host', online: isOpen(host) });
        if (lastHostInfo) ws.send(lastHostInfo);
        if (lastFrame && isOpen(host)) ws.send(lastFrame, { binary: true });
        notifyViewerCount();
      }
      return;
    }

    // ---- host -> viewers
    if (role === 'host') {
      if (isBinary) {
        const kind = data[0];
        if (kind === T_FRAME) {
          lastFrame = data;
          for (const v of viewers) {
            if (!isOpen(v)) continue;
            const b = v.bufferedAmount;
            if (b < 400000) { if (b > 120000) pressure++; v.send(data, { binary: true }); v.stale = false; }
            else { v.stale = true; pressure++; }
          }
        } else if (kind === T_DOWN) {
          for (const v of viewers) if (isOpen(v)) v.send(data, { binary: true });
        }
        return;
      }
      const text = data.toString();
      if (text.length > 524288) return;
      let m; try { m = JSON.parse(text); } catch { return; }
      if (!m || !HOST_TEXT.has(m.type)) return;
      if (m.type === 'host_info') lastHostInfo = text;
      for (const v of viewers) if (isOpen(v)) v.send(text);
      return;
    }

    // ---- viewer -> host
    if (isBinary) { // upload chunk
      if (data.length > 5 && data.length <= 300 * 1024 && data[0] === T_UP && isOpen(host) && host.bufferedAmount < 8 * 1024 * 1024) {
        host.send(data, { binary: true });
      }
      return;
    }
    const text = data.toString();
    if (text.length > 4096) return;
    let m; try { m = JSON.parse(text); } catch { return; }
    if (!m) return;
    if (m.type === 'ping') { sendJSON(ws, { type: 'pong', t: m.t }); return; }
    if (!isOpen(host)) return;
    if (m.type === 'input' && INPUT_ACTIONS.has(m.action)) {
      if (!inputOk()) return;
      if (host.bufferedAmount < 256000) host.send(text);
    } else if (m.type === 'file' && FILE_OPS.has(m.op)) {
      if (!fileOk()) return;
      host.send(text);
    }
  });

  ws.on('close', () => {
    clearTimeout(authTimer);
    if (role === 'host' && host === ws) {
      host = null; lastFrame = null; lastHostInfo = null;
      for (const v of viewers) sendJSON(v, { type: 'host', online: false });
    }
    if (role === 'viewer') {
      viewers.delete(ws);
      if (isOpen(host)) { host.send(JSON.stringify({ type: 'input', action: 'release_all' })); notifyViewerCount(); }
    }
  });
  ws.on('error', () => {});
});

httpServer.listen(PORT, '0.0.0.0', () => console.log(`LYNX relay v0.7 listening on ${PORT}`));
