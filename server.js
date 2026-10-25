'use strict';
/*
 * CyberFaceit Voice Server — сервер сигналов для голосового чата (WebRTC).
 * Без внешних зависимостей: нужен только Node.js 18+.
 *
 * Что делает:
 *  - принимает WebSocket-подключения на /ws, раскладывает игроков по комнатам (матч / пати);
 *  - пересылает между игроками offer / answer / ice (сам звук идёт напрямую P2P, либо через TURN);
 *  - выдаёт клиентам список ICE-серверов (STUN + TURN с временными ключами);
 *  - проверяет Firebase ID-токен, чтобы никто не мог выдать себя за другого игрока;
 *  - (необязательно) отдаёт сам index.html по адресу /.
 */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const env = process.env;
const PORT = +env.PORT || 8080;
const PROJECT = env.FIREBASE_PROJECT_ID || 'nsnsjsb-15907';
const REQUIRE_AUTH = env.REQUIRE_AUTH !== '0';
const ORIGINS = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const STATIC_FILE = env.STATIC_FILE || path.join(__dirname, 'index.html');
const CERTS_URL = env.CERTS_URL || 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
const STUN = (env.STUN_URLS || 'stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302').split(',').map(s => s.trim()).filter(Boolean);
const TURN_URLS = (env.TURN_URLS || '').split(',').map(s => s.trim()).filter(Boolean);
const TURN_SECRET = env.TURN_SECRET || '';
const TURN_USER = env.TURN_USER || '';
const TURN_PASS = env.TURN_PASS || '';
const TURN_TTL = +env.TURN_TTL || 6 * 3600;
const METERED_DOMAIN = env.METERED_DOMAIN || '';
const METERED_API_KEY = env.METERED_API_KEY || '';
const MAX_ROOM = +env.MAX_ROOM || 10;
const MAX_MSG = 64 * 1024;

const log = (...a) => console.log(new Date().toISOString(), ...a);

/* ---------- Firebase ID token ---------- */
let certs = null, certsExp = 0;
async function getCerts() {
  if (certs && Date.now() < certsExp) return certs;
  const r = await fetch(CERTS_URL);
  if (!r.ok) throw new Error('certs ' + r.status);
  const m = /max-age=(\d+)/.exec(r.headers.get('cache-control') || '');
  certs = await r.json();
  certsExp = Date.now() + (m ? +m[1] * 1000 : 3600e3);
  return certs;
}
const j64 = s => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
async function verifyToken(tok) {
  const parts = String(tok || '').split('.');
  if (parts.length !== 3) throw new Error('bad token');
  const head = j64(parts[0]), pay = j64(parts[1]);
  if (head.alg !== 'RS256') throw new Error('bad alg');
  const pem = (await getCerts())[head.kid];
  if (!pem) throw new Error('unknown kid');
  const v = crypto.createVerify('RSA-SHA256');
  v.update(parts[0] + '.' + parts[1]);
  if (!v.verify(pem, Buffer.from(parts[2], 'base64url'))) throw new Error('bad signature');
  const now = Math.floor(Date.now() / 1000);
  if (!(pay.exp > now)) throw new Error('expired');
  if (pay.iat > now + 300) throw new Error('iat in future');
  if (pay.aud !== PROJECT) throw new Error('bad aud');
  if (pay.iss !== 'https://securetoken.google.com/' + PROJECT) throw new Error('bad iss');
  if (!pay.sub || typeof pay.sub !== 'string') throw new Error('no sub');
  return pay.sub;
}

/* ---------- ICE (STUN + TURN) ---------- */
let meteredCache = null, meteredExp = 0;
async function iceServers(uid) {
  const out = [];
  if (STUN.length) out.push({ urls: STUN });
  if (TURN_URLS.length) {
    if (TURN_SECRET) { // coturn: use-auth-secret (временные ключи)
      const user = (Math.floor(Date.now() / 1000) + TURN_TTL) + ':' + String(uid || 'u').slice(0, 40);
      const credential = crypto.createHmac('sha1', TURN_SECRET).update(user).digest('base64');
      out.push({ urls: TURN_URLS, username: user, credential });
    } else if (TURN_USER) {
      out.push({ urls: TURN_URLS, username: TURN_USER, credential: TURN_PASS });
    }
  }
  if (METERED_DOMAIN && METERED_API_KEY) { // metered.ca — готовый TURN-сервис
    try {
      if (!meteredCache || Date.now() > meteredExp) {
        const r = await fetch('https://' + METERED_DOMAIN + '/api/v1/turn/credentials?apiKey=' + encodeURIComponent(METERED_API_KEY));
        if (r.ok) { meteredCache = await r.json(); meteredExp = Date.now() + 30 * 60e3; }
      }
      if (Array.isArray(meteredCache)) out.push(...meteredCache);
    } catch (e) { log('metered error', e.message); }
  }
  return out;
}

/* ---------- Минимальный WebSocket (RFC 6455) ---------- */
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
class Sock {
  constructor(socket) {
    this.s = socket; this.buf = Buffer.alloc(0); this.frag = []; this.fragLen = 0; this.fragOp = 0;
    this.alive = true; this.closed = false; this.onmessage = null; this.onclose = null;
    socket.setNoDelay(true);
    socket.on('data', d => this._data(d));
    socket.on('close', () => this._end());
    socket.on('error', () => this._end());
  }
  _data(d) {
    this.buf = Buffer.concat([this.buf, d]);
    if (this.buf.length > MAX_MSG * 2) return this.close(1009);
    for (;;) {
      const b = this.buf;
      if (b.length < 2) return;
      const fin = !!(b[0] & 0x80), op = b[0] & 0x0f, masked = !!(b[1] & 0x80);
      let len = b[1] & 0x7f, off = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (b.length < 10) return; const big = b.readBigUInt64BE(2); if (big > BigInt(MAX_MSG)) return this.close(1009); len = Number(big); off = 10; }
      if (!masked) return this.close(1002);
      if (len > MAX_MSG) return this.close(1009);
      if (b.length < off + 4 + len) return;
      const mask = b.subarray(off, off + 4), data = Buffer.from(b.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < data.length; i++) data[i] ^= mask[i & 3];
      this.buf = b.subarray(off + 4 + len);
      this._frame(fin, op, data);
      if (this.closed) return;
    }
  }
  _frame(fin, op, data) {
    if (op === 0x8) { this.close(1000); return; }
    if (op === 0x9) { this._send(0xA, data); return; }
    if (op === 0xA) { this.alive = true; return; }
    if (op === 0x1 || op === 0x2) { this.frag = [data]; this.fragLen = data.length; this.fragOp = op; }
    else if (op === 0x0) {
      if (!this.fragOp) return this.close(1002);
      this.frag.push(data); this.fragLen += data.length;
      if (this.fragLen > MAX_MSG) return this.close(1009);
    } else return this.close(1002);
    if (fin) {
      const msg = Buffer.concat(this.frag); const o = this.fragOp;
      this.frag = []; this.fragLen = 0; this.fragOp = 0;
      if (o === 0x1 && this.onmessage) this.onmessage(msg.toString('utf8'));
    }
  }
  _send(op, payload) {
    if (this.closed || this.s.destroyed) return;
    const n = payload.length; let h;
    if (n < 126) h = Buffer.from([0x80 | op, n]);
    else if (n < 65536) { h = Buffer.alloc(4); h[0] = 0x80 | op; h[1] = 126; h.writeUInt16BE(n, 2); }
    else { h = Buffer.alloc(10); h[0] = 0x80 | op; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); }
    try { this.s.write(Buffer.concat([h, payload])); } catch (e) { /* ignore */ }
  }
  send(obj) { this._send(0x1, Buffer.from(typeof obj === 'string' ? obj : JSON.stringify(obj))); }
  ping() { this._send(0x9, Buffer.alloc(0)); }
  close(code) {
    if (this.closed) return;
    const p = Buffer.alloc(2); p.writeUInt16BE(code || 1000, 0);
    this._send(0x8, p); this.closed = true;
    try { this.s.end(); } catch (e) { /* ignore */ }
    setTimeout(() => { try { this.s.destroy(); } catch (e) { /* ignore */ } }, 1500).unref();
    this._end();
  }
  _end() { if (this._done) return; this._done = true; this.closed = true; if (this.onclose) this.onclose(); }
}

/* ---------- Комнаты ---------- */
const rooms = new Map(); // room -> Map(uid -> {sock, sid})
function leave(c) {
  if (!c.room) return;
  const m = rooms.get(c.room);
  if (m && m.get(c.uid) === c) {
    m.delete(c.uid);
    for (const o of m.values()) o.sock.send({ t: 'left', id: c.uid, sid: c.sid });
    if (!m.size) rooms.delete(c.room);
  }
  c.room = null;
}

function handle(sock) {
  const c = { sock, uid: null, sid: null, room: null, n: 0, win: Date.now() };
  const joinTimer = setTimeout(() => { if (!c.room) sock.close(4001); }, 10000);
  sock.onclose = () => { clearTimeout(joinTimer); leave(c); };
  sock.onmessage = async txt => {
    if (Date.now() - c.win > 10000) { c.win = Date.now(); c.n = 0; }
    if (++c.n > 400) return sock.close(4008);
    let d; try { d = JSON.parse(txt); } catch (e) { return; }
    if (!d || typeof d !== 'object') return;

    if (d.t === 'join') {
      if (c.room || c.joining) return;
      c.joining = true;
      const room = String(d.room || ''), sid = String(d.sid || '');
      if (!/^[\w.:-]{1,80}$/.test(room) || !/^[\w-]{1,32}$/.test(sid)) { c.joining = false; return sock.send({ t: 'err', code: 'bad', msg: 'bad room/sid' }); }
      let uid;
      try {
        if (REQUIRE_AUTH) uid = await verifyToken(d.token);
        else { uid = String(d.uid || ''); if (!/^[\w.-]{1,128}$/.test(uid)) throw new Error('bad uid'); }
      } catch (e) { c.joining = false; sock.send({ t: 'err', code: 'auth', msg: e.message }); return sock.close(4003); }
      if (sock.closed) return;
      let m = rooms.get(room);
      if (!m) { m = new Map(); rooms.set(room, m); }
      const old = m.get(uid);
      if (old) { m.delete(uid); old.room = null; for (const o of m.values()) o.sock.send({ t: 'left', id: uid, sid: old.sid }); old.sock.send({ t: 'err', code: 'replaced', msg: 'joined elsewhere' }); old.sock.close(4000); }
      if (m.size >= MAX_ROOM) { c.joining = false; sock.send({ t: 'err', code: 'full', msg: 'room full' }); return sock.close(4009); }
      const peers = [...m].map(([id, o]) => ({ id, sid: o.sid }));
      c.uid = uid; c.sid = sid; c.room = room; c.joining = false;
      m.set(uid, c);
      let ice = []; try { ice = await iceServers(uid); } catch (e) { /* ignore */ }
      sock.send({ t: 'joined', uid, peers, ice, ts: Date.now() });
      for (const o of m.values()) if (o !== c) o.sock.send({ t: 'peer', id: uid, sid });
      log('join', room, uid, 'peers=' + peers.length);
      return;
    }
    if (!c.room) return;
    if (d.t === 'ping') return sock.send({ t: 'pong' });
    if (d.t === 'leave') return leave(c);
    if (d.t === 'sig') {
      const m = rooms.get(c.room); const to = m && m.get(String(d.to || ''));
      if (!to || (d.toSid && to.sid !== d.toSid)) return;
      if (!['offer', 'answer', 'ice', 'redo'].includes(d.type)) return;
      to.sock.send({ t: 'sig', type: d.type, from: c.uid, sid: c.sid, to: to.uid, toSid: to.sid, data: d.data });
    }
  };
}

/* ---------- HTTP ---------- */
const corsOrigin = req => {
  const o = req.headers.origin;
  if (!o) return null;
  if (!ORIGINS.length) return '*';
  return ORIGINS.includes(o) ? o : null;
};
const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  const co = corsOrigin(req);
  if (co) { res.setHeader('Access-Control-Allow-Origin', co); res.setHeader('Vary', 'Origin'); }
  if (url === '/health') {
    let peers = 0; rooms.forEach(m => { peers += m.size; });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    return res.end(JSON.stringify({ ok: true, rooms: rooms.size, peers, turn: !!(TURN_URLS.length || METERED_DOMAIN) }));
  }
  if (url === '/' || url === '/index.html') {
    fs.readFile(STATIC_FILE, (e, buf) => {
      if (e) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Voice server is running. Put index.html next to server.js to serve the site from here.'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'Permissions-Policy': 'microphone=(self)' });
      res.end(buf);
    });
    return;
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('not found');
});
server.on('upgrade', (req, socket) => {
  const url = req.url.split('?')[0];
  const key = req.headers['sec-websocket-key'];
  const origin = req.headers.origin;
  if (url !== '/ws' || !key || String(req.headers.upgrade).toLowerCase() !== 'websocket') { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); return; }
  if (ORIGINS.length && origin && !ORIGINS.includes(origin)) { socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
  const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  const sock = new Sock(socket);
  handle(sock);
  sock._hb = sock; // keep reference for heartbeat
  conns.add(sock); sock.s.on('close', () => conns.delete(sock));
});
const conns = new Set();
const hb = setInterval(() => {
  for (const s of conns) {
    if (!s.alive) { s.close(4002); conns.delete(s); continue; }
    s.alive = false; s.ping();
  }
}, 20000);
hb.unref();

if (require.main === module) {
  server.listen(PORT, () => {
    log('voice server on :' + PORT, '| auth=' + (REQUIRE_AUTH ? 'firebase:' + PROJECT : 'OFF'), '| turn=' + (TURN_URLS.length ? TURN_URLS[0] : METERED_DOMAIN ? 'metered' : 'none (только STUN!)'));
  });
  const stop = () => { server.close(); process.exit(0); };
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
}
module.exports = { server, verifyToken, iceServers, rooms };
