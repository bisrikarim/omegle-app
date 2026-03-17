const express  = require('express');
const path     = require('path');
const { Server } = require('socket.io');
const { Pool }   = require('pg');
const rateLimit  = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1);
app.use(express.json());

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please slow down.' }
}));

app.use('/api/report', rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  message: { error: 'Too many reports submitted. Please wait.' }
}));

app.use(express.static(path.join(__dirname, 'public')));

// ── PostgreSQL ──
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,
      reported_ip TEXT NOT NULL,
      reporter_ip TEXT,
      reason TEXT DEFAULT 'inappropriate behavior',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS banned_ips (
      id SERIAL PRIMARY KEY,
      ip TEXT UNIQUE NOT NULL,
      reason TEXT DEFAULT 'reported by users',
      banned_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✅ Database tables ready');
}
initDB().catch(err => {
  console.error('❌ DB init error:', err.message);
});

function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.connection?.remoteAddress ||
    'unknown'
  );
}

function getIPFromSocket(socket) {
  return (
    socket.handshake.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    socket.handshake.address ||
    'unknown'
  );
}

async function checkBanned(req, res, next) {
  if (req.path.startsWith('/admin')) return next();
  try {
    const ip = getIP(req);
    const result = await pool.query('SELECT 1 FROM banned_ips WHERE ip = $1', [ip]);
    if (result.rows.length > 0) {
      return res.status(403).send(`<!DOCTYPE html><html><head><title>Banned</title>
        <style>body{background:#0a0a0f;color:#f87171;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:16px;}h1{font-size:2rem;}p{color:#5a5a7a;}</style></head>
        <body><h1>🚫 Access Denied</h1><p>Your IP has been banned for violating our terms of service.</p></body></html>`);
    }
    next();
  } catch (e) { next(); }
}
app.use(checkBanned);

// ── Cloudflare TURN ──
const CF_TURN_TOKEN_ID  = process.env.CF_TURN_TOKEN_ID;
const CF_TURN_API_TOKEN = process.env.CF_TURN_API_TOKEN;

app.get('/api/turn-credentials', async (req, res) => {
  if (!CF_TURN_TOKEN_ID || !CF_TURN_API_TOKEN) {
    return res.json({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
  }
  try {
    const response = await fetch(
      `https://rtc.live.cloudflare.com/v1/turn/keys/${CF_TURN_TOKEN_ID}/credentials/generate-ice-servers`,
      { method: 'POST', headers: { 'Authorization': `Bearer ${CF_TURN_API_TOKEN}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ ttl: 86400 }) }
    );
    res.json(await response.json());
  } catch (e) {
    res.status(500).json({ error: 'Failed to get TURN credentials' });
  }
});

// ── API Report ──
const socketIPMap = new Map();

app.post('/api/report', async (req, res) => {
  try {
    const reporterIP = getIP(req);
    const { reportedSocketId, reason } = req.body;
    const reportedIP = socketIPMap.get(reportedSocketId) || 'unknown';
    if (reportedIP === 'unknown') return res.status(400).json({ error: 'User not found' });
    await pool.query(
      'INSERT INTO reports (reported_ip, reporter_ip, reason) VALUES ($1, $2, $3)',
      [reportedIP, reporterIP, reason || 'inappropriate behavior']
    );
    const countResult = await pool.query(
      `SELECT COUNT(*) FROM reports WHERE reported_ip = $1 AND created_at > NOW() - INTERVAL '24 hours'`,
      [reportedIP]
    );
    if (parseInt(countResult.rows[0].count) >= 3) {
      await pool.query(
        'INSERT INTO banned_ips (ip, reason) VALUES ($1, $2) ON CONFLICT (ip) DO NOTHING',
        [reportedIP, `Auto-banned: ${countResult.rows[0].count} reports in 24h`]
      );
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to submit report' });
  }
});

// ── API Moderation ──
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } });

app.post('/api/moderate', upload.single('image'), async (req, res) => {
  try {
    const { strangerSocketId } = req.body;
    const reporterIP = getIP(req);
    if (!req.file) return res.status(400).json({ error: 'No image' });
    const SE_USER   = process.env.SIGHTENGINE_USER;
    const SE_SECRET = process.env.SIGHTENGINE_SECRET;
    if (!SE_USER || !SE_SECRET) return res.json({ banned: false });
    const boundary = '----FormBoundary' + Math.random().toString(36).slice(2);
    const CRLF = '\r\n';
    const bodyParts = [];
    const addField = (name, value) => {
      bodyParts.push(Buffer.from('--' + boundary + CRLF + 'Content-Disposition: form-data; name="' + name + '"' + CRLF + CRLF + value + CRLF));
    };
    addField('models', 'nudity');
    addField('api_user', SE_USER);
    addField('api_secret', SE_SECRET);
    bodyParts.push(Buffer.from('--' + boundary + CRLF + 'Content-Disposition: form-data; name="media"; filename="frame.jpg"' + CRLF + 'Content-Type: image/jpeg' + CRLF + CRLF));
    bodyParts.push(req.file.buffer);
    bodyParts.push(Buffer.from(CRLF + '--' + boundary + '--' + CRLF));
    const bodyBuffer = Buffer.concat(bodyParts);
    const seRes = await fetch('https://api.sightengine.com/1.0/check.json', {
      method: 'POST', body: bodyBuffer,
      headers: { 'Content-Type': 'multipart/form-data; boundary=' + boundary }
    });
    const seData = await seRes.json();
    const nudity = seData?.nudity || {};
    const score = nudity.raw ?? 0;
    const partialScore = nudity.partial ?? 0;
    if (score > 0.5 || partialScore > 0.55) {
      const reportedIP = socketIPMap.get(strangerSocketId) || 'unknown';
      if (reportedIP !== 'unknown') {
        await pool.query('INSERT INTO reports (reported_ip, reporter_ip, reason) VALUES ($1, $2, $3)', [reportedIP, reporterIP, 'Auto-detected: nudity/sexual content']);
        await pool.query('INSERT INTO banned_ips (ip, reason) VALUES ($1, $2) ON CONFLICT (ip) DO NOTHING', [reportedIP, 'Auto-banned: nudity detected (score: ' + score.toFixed(2) + ')']);
        const s = io.sockets.sockets.get(strangerSocketId);
        if (s) { s.emit('banned'); s.disconnect(true); }
      }
      return res.json({ banned: true, score });
    }
    res.json({ banned: false, score });
  } catch (e) {
    console.error('Moderation error:', e.message);
    res.json({ banned: false });
  }
});

// ── Admin ──
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Son@trach89';

function adminAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin"');
    return res.status(401).send('Authentication required');
  }
  const [user, pass] = Buffer.from(auth.split(' ')[1], 'base64').toString().split(':');
  if (user === 'admin' && pass === ADMIN_PASSWORD) return next();
  res.setHeader('WWW-Authenticate', 'Basic realm="Admin"');
  return res.status(401).send('Invalid credentials');
}

app.get('/admin', adminAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.get('/admin/api/stats', adminAuth, async (req, res) => {
  try {
    const [reports, bans, recent] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM reports'),
      pool.query('SELECT COUNT(*) FROM banned_ips'),
      pool.query(`SELECT COUNT(*) FROM reports WHERE created_at > NOW() - INTERVAL '24 hours'`)
    ]);
    const roomStats = {};
    for (const [room, queue] of waitingRooms.entries()) {
      roomStats[room || 'random'] = queue.length;
    }
    res.json({
      totalReports: reports.rows[0].count,
      totalBans: bans.rows[0].count,
      reportsLast24h: recent.rows[0].count,
      onlineNow: io ? io.sockets.sockets.size : 0,
      roomStats
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/api/reports', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT reported_ip, COUNT(*) as count, MAX(created_at) as last_report, ARRAY_AGG(DISTINCT reason) as reasons FROM reports GROUP BY reported_ip ORDER BY count DESC, last_report DESC`);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/api/bans', adminAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM banned_ips ORDER BY banned_at DESC');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/api/ban', adminAuth, async (req, res) => {
  try {
    const { ip, reason } = req.body;
    await pool.query('INSERT INTO banned_ips (ip, reason) VALUES ($1, $2) ON CONFLICT (ip) DO UPDATE SET reason=$2, banned_at=NOW()', [ip, reason || 'Manually banned by admin']);
    for (const [socketId, socketIP] of socketIPMap.entries()) {
      if (socketIP === ip) {
        const s = io.sockets.sockets.get(socketId);
        if (s) { s.emit('banned'); s.disconnect(true); }
      }
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/api/unban', adminAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM banned_ips WHERE ip = $1', [req.body.ip]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Serveur ──
let server;
if (process.env.NODE_ENV === 'production') {
  server = require('http').createServer(app);
  console.log('🌍 Production mode');
} else {
  const fs = require('fs');
  const { execSync } = require('child_process');
  const CERT_DIR = path.join(__dirname, 'certs');
  const CERT_FILE = path.join(CERT_DIR, 'cert.pem');
  const KEY_FILE  = path.join(CERT_DIR, 'key.pem');
  if (!fs.existsSync(CERT_FILE) || !fs.existsSync(KEY_FILE)) {
    fs.mkdirSync(CERT_DIR, { recursive: true });
    execSync(`openssl req -x509 -newkey rsa:2048 -keyout ${KEY_FILE} -out ${CERT_FILE} -days 365 -nodes -subj "/CN=localhost"`, { stdio: 'inherit' });
  }
  server = require('https').createServer({ key: fs.readFileSync(KEY_FILE), cert: fs.readFileSync(CERT_FILE) }, app);
  const httpRedirect = require('http').createServer((req, res) => {
    res.writeHead(301, { Location: `https://${req.headers.host.split(':')[0]}:3443${req.url}` });
    res.end();
  });
  httpRedirect.listen(3000, '0.0.0.0');
  console.log('🔒 Local mode : HTTPS');
}

const io = new Server(server, { cors: { origin: '*' } });

// ═══════════════════════════════════════════════════════
//  MATCHING — Topic Rooms
// ═══════════════════════════════════════════════════════
const waitingRooms = new Map();
const pairs        = new Map();
const ROOM_TIMEOUT = 12000;
const VALID_ROOMS  = new Set(['gaming', 'music', 'coding', 'movies', 'languages', 'vibing', '']);

function getQueue(room) {
  const key = VALID_ROOMS.has(room) ? room : '';
  if (!waitingRooms.has(key)) waitingRooms.set(key, []);
  return waitingRooms.get(key);
}

function broadcastStats() {
  const totalWaiting = [...waitingRooms.values()].reduce((s, q) => s + q.length, 0);
  io.emit('stats', { online: io.sockets.sockets.size, waiting: totalWaiting, chatting: pairs.size / 2 });
}

function commonInterests(a, b) {
  const setB = new Set(b.map(x => x.toLowerCase().trim()));
  return a.filter(x => setB.has(x.toLowerCase().trim()));
}

function doMatch(entryA, entryB) {
  if (entryA.timer) clearTimeout(entryA.timer);
  if (entryB.timer) clearTimeout(entryB.timer);
  const common = commonInterests(entryA.interests, entryB.interests);
  pairs.set(entryA.socket.id, entryB.socket.id);
  pairs.set(entryB.socket.id, entryA.socket.id);
  entryA.socket.emit('matched', { role: 'A', common, strangerSocketId: entryB.socket.id });
  entryB.socket.emit('matched', { role: 'B', common, strangerSocketId: entryA.socket.id });
  broadcastStats();
}

function removeFromAllQueues(socket) {
  for (const queue of waitingRooms.values()) {
    const idx = queue.findIndex(e => e.socket === socket);
    if (idx !== -1) {
      if (queue[idx].timer) clearTimeout(queue[idx].timer);
      queue.splice(idx, 1);
      return;
    }
  }
}

function tryMatch(socket, interests = [], room = '') {
  removeFromAllQueues(socket);
  const roomKey = VALID_ROOMS.has(room) ? room : '';
  const queue   = getQueue(roomKey);
  const random  = getQueue('');

  if (roomKey !== '') {
    const idx = queue.findIndex(e => commonInterests(interests, e.interests).length > 0);
    if (idx !== -1) { doMatch({ socket, interests, room: roomKey }, queue.splice(idx, 1)[0]); return; }
  }
  if (roomKey !== '' && queue.length > 0) { doMatch({ socket, interests, room: roomKey }, queue.shift()); return; }
  if (roomKey === '' && random.length > 0) { doMatch({ socket, interests, room: '' }, random.shift()); return; }

  const entry = { socket, interests, room: roomKey, timer: null };
  if (roomKey !== '') {
    entry.timer = setTimeout(() => {
      removeFromAllQueues(socket);
      if (random.length > 0) {
        doMatch({ socket, interests, room: '' }, random.shift());
        socket.emit('waiting_fallback');
      } else {
        random.push({ socket, interests, room: '', timer: null });
        socket.emit('waiting_fallback');
        broadcastStats();
      }
    }, ROOM_TIMEOUT);
  }
  queue.push(entry);
  socket.emit('waiting');
  broadcastStats();
}

function disconnect(socket) {
  removeFromAllQueues(socket);
  const partnerId = pairs.get(socket.id);
  if (partnerId) {
    pairs.delete(socket.id);
    pairs.delete(partnerId);
    const ps = io.sockets.sockets.get(partnerId);
    if (ps) ps.emit('partner_left');
  }
  broadcastStats();
}

function forwardToPartner(socket, event, data) {
  const partnerId = pairs.get(socket.id);
  if (partnerId) {
    const ps = io.sockets.sockets.get(partnerId);
    if (ps) ps.emit(event, data);
  }
}

// ═══════════════════════════════════════════════════════
//  KEEP IN TOUCH (KIT)
//  - kitPending : Map<socketId, partnerId>  (one side requested)
//  - kitCodes   : Map<code, { socketAId, socketBId, expiresAt }>
// ═══════════════════════════════════════════════════════
const kitPending = new Map();
const kitCodes   = new Map();
const KIT_EXPIRY = 48 * 60 * 60 * 1000; // 48h

function generateKITCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return kitCodes.has(code) ? generateKITCode() : code;
}

// Clean expired codes every hour
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of kitCodes.entries()) {
    if (now > data.expiresAt) kitCodes.delete(code);
  }
}, 60 * 60 * 1000);

// ── Socket connections ──
io.on('connection', async (socket) => {
  const ip = getIPFromSocket(socket);
  socketIPMap.set(socket.id, ip);

  try {
    const result = await pool.query('SELECT 1 FROM banned_ips WHERE ip = $1', [ip]);
    if (result.rows.length > 0) { socket.emit('banned'); socket.disconnect(true); return; }
  } catch (e) {}

  broadcastStats();

  const socketLimits = {
    message: { count: 0, resetAt: Date.now() + 10000, max: 20 },
    next:    { count: 0, resetAt: Date.now() + 60000, max: 15 },
  };

  function socketAllowed(key) {
    const limit = socketLimits[key];
    if (Date.now() > limit.resetAt) { limit.count = 0; limit.resetAt = Date.now() + (key === 'next' ? 60000 : 10000); }
    if (limit.count >= limit.max) return false;
    limit.count++;
    return true;
  }

  socket.on('find_partner', ({ interests, room } = {}) => tryMatch(socket, interests || [], room || ''));

  socket.on('message', (data) => {
    if (!socketAllowed('message')) return socket.emit('rate_limited', { type: 'message' });
    forwardToPartner(socket, 'message', data);
  });

  socket.on('typing', (v) => forwardToPartner(socket, 'typing', v));

  socket.on('next', ({ room } = {}) => {
    if (!socketAllowed('next')) return socket.emit('rate_limited', { type: 'next' });
    kitPending.delete(socket.id);
    disconnect(socket);
    tryMatch(socket, [], room || '');
  });

  socket.on('stop', () => {
    kitPending.delete(socket.id);
    disconnect(socket);
    socket.emit('stopped');
    broadcastStats();
  });

  socket.on('disconnect', () => {
    kitPending.delete(socket.id);
    disconnect(socket);
    socketIPMap.delete(socket.id);
  });

  socket.on('webrtc_offer',         (data) => forwardToPartner(socket, 'webrtc_offer', data));
  socket.on('webrtc_answer',        (data) => forwardToPartner(socket, 'webrtc_answer', data));
  socket.on('webrtc_ice_candidate', (data) => forwardToPartner(socket, 'webrtc_ice_candidate', data));
  socket.on('webrtc_video_toggle',  (data) => forwardToPartner(socket, 'webrtc_video_toggle', data));
  socket.on('webrtc_audio_toggle',  (data) => forwardToPartner(socket, 'webrtc_audio_toggle', data));
  socket.on('webrtc_screen_share',  (data) => forwardToPartner(socket, 'webrtc_screen_share', data));

  // ── Keep in Touch ──
  socket.on('kit_request', () => {
    const partnerId = pairs.get(socket.id);
    if (!partnerId) return;
    const partnerSocket = io.sockets.sockets.get(partnerId);
    if (!partnerSocket) return;

    if (kitPending.has(partnerId) && kitPending.get(partnerId) === socket.id) {
      // Both agreed → generate code
      kitPending.delete(partnerId);
      kitPending.delete(socket.id);
      const code = generateKITCode();
      kitCodes.set(code, { socketAId: socket.id, socketBId: partnerId, expiresAt: Date.now() + KIT_EXPIRY });
      socket.emit('kit_matched', { code });
      partnerSocket.emit('kit_matched', { code });
    } else {
      // First to request
      kitPending.set(socket.id, partnerId);
      socket.emit('kit_pending');
      partnerSocket.emit('kit_stranger_requested');
    }
  });

  socket.on('kit_cancel', () => {
    kitPending.delete(socket.id);
    forwardToPartner(socket, 'kit_cancelled', {});
  });

  socket.on('kit_reconnect', ({ code } = {}) => {
    if (!code) return socket.emit('kit_error', { message: 'Invalid code.' });
    const upper = code.toUpperCase().trim();
    const entry = kitCodes.get(upper);
    if (!entry) return socket.emit('kit_error', { message: 'Code not found or expired.' });
    if (Date.now() > entry.expiresAt) {
      kitCodes.delete(upper);
      return socket.emit('kit_error', { message: 'This code has expired.' });
    }
    const otherSocketId = entry.socketAId === socket.id ? entry.socketBId : entry.socketAId;
    const otherSocket   = io.sockets.sockets.get(otherSocketId);
    if (!otherSocket) {
      kitCodes.delete(upper);
      return socket.emit('kit_error', { message: 'The other person is no longer online.' });
    }
    kitCodes.delete(upper);
    doMatch(
      { socket, interests: [], room: '', timer: null },
      { socket: otherSocket, interests: [], room: '', timer: null }
    );
    socket.emit('kit_reconnect_ok');
    otherSocket.emit('kit_reconnect_ok');
  });
});

const PORT = process.env.PORT || 3443;
server.listen(PORT, '0.0.0.0', () => console.log(`✅ Server running on port ${PORT}`));