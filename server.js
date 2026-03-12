const express  = require('express');
const path     = require('path');
const { Server } = require('socket.io');
const { Pool }   = require('pg');

const app = express();
app.use(express.json());
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
  console.error('❌ DB connection string starts with:', process.env.DATABASE_URL ? process.env.DATABASE_URL.substring(0, 30) + '...' : 'NOT SET');
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

// ── Middleware ban HTTP ──
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

    // Auto-ban si >= 3 reports en 24h
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
    res.json({ totalReports: reports.rows[0].count, totalBans: bans.rows[0].count, reportsLast24h: recent.rows[0].count, onlineNow: io ? io.sockets.sockets.size : 0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/api/reports', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT reported_ip, COUNT(*) as count, MAX(created_at) as last_report,
             ARRAY_AGG(DISTINCT reason) as reasons
      FROM reports GROUP BY reported_ip ORDER BY count DESC, last_report DESC
    `);
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
    await pool.query(
      'INSERT INTO banned_ips (ip, reason) VALUES ($1, $2) ON CONFLICT (ip) DO UPDATE SET reason=$2, banned_at=NOW()',
      [ip, reason || 'Manually banned by admin']
    );
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

// ── Logique chat ──
const waitingQueue = [];
const pairs = new Map();

function broadcastStats() {
  io.emit('stats', { online: io.sockets.sockets.size, waiting: waitingQueue.length, chatting: pairs.size / 2 });
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

function removeFromQueue(socket) {
  const idx = waitingQueue.findIndex(e => e.socket === socket);
  if (idx !== -1) { if (waitingQueue[idx].timer) clearTimeout(waitingQueue[idx].timer); waitingQueue.splice(idx, 1); }
}

function tryMatch(socket, interests = []) {
  removeFromQueue(socket);
  const commonIdx = waitingQueue.findIndex(e => interests.length > 0 && commonInterests(interests, e.interests).length > 0);
  if (commonIdx !== -1) {
    doMatch({ socket, interests }, waitingQueue.splice(commonIdx, 1)[0]);
  } else if (waitingQueue.length > 0 && interests.length === 0) {
    doMatch({ socket, interests }, waitingQueue.shift());
  } else if (waitingQueue.length > 0 && interests.length > 0) {
    const entry = { socket, interests, timer: null };
    entry.timer = setTimeout(() => {
      const idx = waitingQueue.findIndex(e => e.socket === socket);
      if (idx === -1) return;
      waitingQueue.splice(idx, 1);
      if (waitingQueue.length > 0) { doMatch({ socket, interests }, waitingQueue.shift()); socket.emit('fallback_match'); }
      else { waitingQueue.push({ socket, interests: [], timer: null }); socket.emit('waiting_fallback'); broadcastStats(); }
    }, 10000);
    waitingQueue.push(entry);
    socket.emit('waiting');
    broadcastStats();
  } else {
    const entry = { socket, interests, timer: null };
    if (interests.length > 0) {
      entry.timer = setTimeout(() => {
        const idx = waitingQueue.findIndex(e => e.socket === socket);
        if (idx !== -1) { waitingQueue[idx].interests = []; socket.emit('waiting_fallback'); }
      }, 10000);
    }
    waitingQueue.push(entry);
    socket.emit('waiting');
    broadcastStats();
  }
}

function disconnect(socket) {
  removeFromQueue(socket);
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
  if (partnerId) { const ps = io.sockets.sockets.get(partnerId); if (ps) ps.emit(event, data); }
}

io.on('connection', async (socket) => {
  const ip = getIPFromSocket(socket);
  socketIPMap.set(socket.id, ip);

  try {
    const result = await pool.query('SELECT 1 FROM banned_ips WHERE ip = $1', [ip]);
    if (result.rows.length > 0) { socket.emit('banned'); socket.disconnect(true); return; }
  } catch (e) {}

  broadcastStats();
  socket.on('find_partner', ({ interests } = {}) => tryMatch(socket, interests || []));
  socket.on('message',  (data)     => forwardToPartner(socket, 'message', data));
  socket.on('typing',   (isTyping) => forwardToPartner(socket, 'typing', isTyping));
  socket.on('next',     () => { disconnect(socket); tryMatch(socket, []); });
  socket.on('stop',     () => { disconnect(socket); socket.emit('stopped'); broadcastStats(); });
  socket.on('disconnect', () => { disconnect(socket); socketIPMap.delete(socket.id); });
  socket.on('webrtc_offer',         (data) => forwardToPartner(socket, 'webrtc_offer', data));
  socket.on('webrtc_answer',        (data) => forwardToPartner(socket, 'webrtc_answer', data));
  socket.on('webrtc_ice_candidate', (data) => forwardToPartner(socket, 'webrtc_ice_candidate', data));
  socket.on('webrtc_video_toggle',  (data) => forwardToPartner(socket, 'webrtc_video_toggle', data));
  socket.on('webrtc_audio_toggle',  (data) => forwardToPartner(socket, 'webrtc_audio_toggle', data));
});

const PORT = process.env.PORT || 3443;
server.listen(PORT, '0.0.0.0', () => console.log(`✅ Server running on port ${PORT}`));