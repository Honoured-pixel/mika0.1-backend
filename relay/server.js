import http from 'node:http';
import crypto from 'node:crypto';
import { WebSocketServer, WebSocket } from 'ws';

const PORT = Number(process.env.PORT || 8080);
const ACCESS_KEY = process.env.LYNX_ACCESS_KEY || '';
if (ACCESS_KEY.length < 24) {
  console.error('Set LYNX_ACCESS_KEY to a random secret at least 24 characters long.');
  process.exit(1);
}
const httpServer = http.createServer((req, res) => {
  if (req.url === '/health') { res.writeHead(200, {'content-type':'text/plain'}); res.end('LYNX relay online'); return; }
  res.writeHead(404); res.end('Not found');
});
const wss = new WebSocketServer({ noServer: true, maxPayload: 2 * 1024 * 1024 });
let host = null;
const viewers = new Set();
function keyMatches(input) {
  if (typeof input !== 'string') return false;
  const a = Buffer.from(input); const b = Buffer.from(ACCESS_KEY);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
httpServer.on('upgrade', (req, socket, head) => {
  if (req.url !== '/ws') { socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});
wss.on('connection', ws => {
  let role = null;
  const authTimer = setTimeout(() => ws.close(4401, 'Auth timeout'), 8000);
  ws.on('message', (data, isBinary) => {
    if (!role) {
      if (isBinary) { ws.close(4401, 'Authenticate first'); return; }
      let msg; try { msg = JSON.parse(data.toString()); } catch { ws.close(4401, 'Bad auth'); return; }
      if (!keyMatches(msg.key) || !['host','viewer'].includes(msg.role)) { ws.close(4403, 'Access denied'); return; }
      clearTimeout(authTimer); role = msg.role;
      if (role === 'host') {
        if (host && host.readyState === WebSocket.OPEN) host.close(4000, 'Host replaced');
        host = ws;
      } else viewers.add(ws);
      ws.send(JSON.stringify({type:'authenticated', role, hostOnline: !!host && host.readyState === WebSocket.OPEN}));
      if (role === 'host') {
        for (const v of viewers) if (v.readyState === WebSocket.OPEN) v.send(JSON.stringify({type:'host', online:true}));
      } else {
        ws.send(JSON.stringify({type:'host', online: !!host && host.readyState === WebSocket.OPEN}));
      }
      return;
    }
    if (role === 'host' && isBinary) {
      for (const v of viewers) {
        if (v.readyState === WebSocket.OPEN && v.bufferedAmount < 900000) v.send(data, { binary: true });
      }
    }
  });
  ws.on('close', () => {
    clearTimeout(authTimer);
    if (role === 'host' && host === ws) {
      host = null;
      for (const v of viewers) if (v.readyState === WebSocket.OPEN) v.send(JSON.stringify({type:'host', online:false}));
    }
    if (role === 'viewer') viewers.delete(ws);
  });
  ws.on('error', () => {});
});
httpServer.listen(PORT, '0.0.0.0', () => console.log(`LYNX relay listening on ${PORT}`));
