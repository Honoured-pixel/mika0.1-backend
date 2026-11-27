// LYNX relay v0.8 - multi-device routing
import http from 'node:http';
import crypto from 'node:crypto';
import { WebSocketServer, WebSocket } from 'ws';
const PORT = Number(process.env.PORT || 8080);
const ACCESS_KEY = process.env.LYNX_ACCESS_KEY || '';
if (ACCESS_KEY.length < 24) { console.error('Set LYNX_ACCESS_KEY to a secret at least 24 characters long.'); process.exit(1); }
const T_FRAME=1, T_DOWN=2, T_UP=3;
const INPUT_ACTIONS=new Set(['mouse_move','mouse_down','mouse_up','wheel','key_down','key_up','key_tap','text','release_all','set_profile','request_admin']);
const FILE_OPS=new Set(['list','upload_begin','upload_end','download','ack','cancel']);
const HOST_TEXT=new Set(['host_info','file_list','file_ready','file_ack','file_begin','file_done','file_error','notice']);
const httpServer=http.createServer((req,res)=>{if(req.url==='/health'){res.writeHead(200,{'content-type':'text/plain'});res.end('LYNX relay online');return;}res.writeHead(404);res.end('Not found');});
const wss=new WebSocketServer({noServer:true,maxPayload:8*1024*1024});
const hosts=new Map(); // deviceId -> {ws,name,lastFrame,lastHostInfo}
const viewers=new Set();
const isOpen=ws=>!!ws&&ws.readyState===WebSocket.OPEN;
const sendJSON=(ws,obj)=>{if(isOpen(ws))ws.send(JSON.stringify(obj));};
const deviceList=()=>[...hosts.values()].map(h=>({id:h.id,name:h.name,online:isOpen(h.ws)}));
function publishDevices(){const devices=deviceList();for(const v of viewers)sendJSON(v,{type:'devices',devices});}
function selectedHost(v){return v.selectedDeviceId?hosts.get(v.selectedDeviceId):null;}
function sendSelected(v){const h=selectedHost(v);sendJSON(v,{type:'device_selected',deviceId:h?.id||null,online:!!h&&isOpen(h.ws),name:h?.name||null});if(h?.lastHostInfo)sendJSON(v,h.lastHostInfo);if(h?.lastFrame&&isOpen(h.ws))v.send(h.lastFrame,{binary:true});}
function keyMatches(input){if(typeof input!=='string')return false;const a=Buffer.from(input),b=Buffer.from(ACCESS_KEY);return a.length===b.length&&crypto.timingSafeEqual(a,b);}
const fails=new Map(),blocked=new Map();
const clientIp=req=>(req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress||'unknown';
function noteFail(ip){const now=Date.now();let r=fails.get(ip);if(!r||now-r.since>60000)r={n:0,since:now};r.n++;fails.set(ip,r);if(r.n>=5){blocked.set(ip,now+300000);fails.delete(ip);}}
setInterval(()=>{const now=Date.now();for(const[ip,t]of blocked)if(t<now)blocked.delete(ip);},60000).unref();
const makeLimiter=max=>{let start=Date.now(),n=0;return()=>{const now=Date.now();if(now-start>=1000){start=now;n=0;}return ++n<=max;};};
httpServer.on('upgrade',(req,socket,head)=>{if(req.url!='/ws'){socket.destroy();return;}const until=blocked.get(clientIp(req));if(until&&until>Date.now()){socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');socket.destroy();return;}wss.handleUpgrade(req,socket,head,ws=>wss.emit('connection',ws,req));});
setInterval(()=>{for(const v of viewers)sendJSON(v,{type:'hb',t:Date.now()});},5000).unref();
setInterval(()=>{for(const ws of wss.clients){if(ws.isAlive===false){ws.terminate();continue;}ws.isAlive=false;try{ws.ping();}catch{}}},10000).unref();
wss.on('connection',(ws,req)=>{
 const ip=clientIp(req);let role=null,deviceId=null;ws.isAlive=true;ws.stale=false;ws.on('pong',()=>ws.isAlive=true);
 const inputOk=makeLimiter(400),fileOk=makeLimiter(250);const authTimer=setTimeout(()=>ws.close(4401,'Auth timeout'),8000);
 ws.on('message',(data,isBinary)=>{
  ws.isAlive=true;
  if(!role){if(isBinary){ws.close(4401,'Authenticate first');return;}let m;try{m=JSON.parse(data.toString());}catch{ws.close(4401,'Bad auth');return;}if(!keyMatches(m.key)||!['host','viewer'].includes(m.role)){noteFail(ip);ws.close(4403,'Access denied');return;}clearTimeout(authTimer);role=m.role;
   if(role==='host'){
    const raw=typeof m.deviceId==='string'?m.deviceId:'';deviceId=raw.toLowerCase().replace(/[^a-z0-9._-]/g,'').slice(0,80);if(!deviceId)deviceId=crypto.randomUUID();
    const name=(typeof m.deviceName==='string'&&m.deviceName.trim()?m.deviceName.trim():deviceId).slice(0,100);
    const old=hosts.get(deviceId);if(old&&isOpen(old.ws))old.ws.close(4000,'Same device reconnected');
    hosts.set(deviceId,{id:deviceId,name,ws,lastFrame:null,lastHostInfo:null});
    sendJSON(ws,{type:'authenticated',role,deviceId});publishDevices();
    for(const v of viewers)if(v.selectedDeviceId===deviceId){sendJSON(v,{type:'host',online:true});}
   }else{
    viewers.add(ws);const first=deviceList().find(d=>d.online);ws.selectedDeviceId=first?.id||null;
    sendJSON(ws,{type:'authenticated',role,hostOnline:!!first,deviceId:ws.selectedDeviceId});publishDevices();sendSelected(ws);
   }
   return;
  }
  if(role==='host'){
   const h=hosts.get(deviceId);if(!h||h.ws!==ws)return;
   if(isBinary){const kind=data[0];if(kind===T_FRAME){h.lastFrame=data;for(const v of viewers){if(v.selectedDeviceId!==deviceId||!isOpen(v))continue;const b=v.bufferedAmount;if(b<400000){v.send(data,{binary:true});v.stale=false;}else v.stale=true;}}else if(kind===T_DOWN){for(const v of viewers)if(v.selectedDeviceId===deviceId&&isOpen(v))v.send(data,{binary:true});}return;}
   const text=data.toString();if(text.length>524288)return;let m;try{m=JSON.parse(text);}catch{return;}if(!m||!HOST_TEXT.has(m.type))return;if(m.type==='host_info')h.lastHostInfo=text;for(const v of viewers)if(v.selectedDeviceId===deviceId&&isOpen(v))v.send(text);return;
  }
  if(isBinary){const h=selectedHost(ws);if(data.length>5&&data.length<=300*1024&&data[0]===T_UP&&h&&isOpen(h.ws)&&h.ws.bufferedAmount<8*1024*1024)h.ws.send(data,{binary:true});return;}
  const text=data.toString();if(text.length>4096)return;let m;try{m=JSON.parse(text);}catch{return;}if(!m)return;
  if(m.type==='ping'){sendJSON(ws,{type:'pong',t:m.t});return;}
  if(m.type==='select_device'&&typeof m.deviceId==='string'){
   const id=m.deviceId;ws.selectedDeviceId=hosts.has(id)?id:null;sendSelected(ws);sendJSON(ws,{type:'host',online:!!selectedHost(ws)&&isOpen(selectedHost(ws).ws)});return;
  }
  const h=selectedHost(ws);if(!h||!isOpen(h.ws))return;
  if(m.type==='input'&&INPUT_ACTIONS.has(m.action)){if(!inputOk())return;if(h.ws.bufferedAmount<256000)h.ws.send(text);}
  else if(m.type==='file'&&FILE_OPS.has(m.op)){if(!fileOk())return;h.ws.send(text);}
 });
 ws.on('close',()=>{
  clearTimeout(authTimer);
  if(role==='host'){const h=hosts.get(deviceId);if(h&&h.ws===ws){hosts.delete(deviceId);publishDevices();for(const v of viewers)if(v.selectedDeviceId===deviceId){sendJSON(v,{type:'host',online:false});sendJSON(v,{type:'device_selected',deviceId,name:h.name,online:false});}}}
  if(role==='viewer'){viewers.delete(ws);const h=selectedHost(ws);if(h&&isOpen(h.ws))h.ws.send(JSON.stringify({type:'input',action:'release_all'}));}
 });ws.on('error',()=>{});
});
httpServer.listen(PORT,'0.0.0.0',()=>console.log(`LYNX relay v0.8 listening on ${PORT}`));
