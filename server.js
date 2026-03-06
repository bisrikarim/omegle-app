const express  = require('express');
const path     = require('path');
const { Server } = require('socket.io');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

let server;

// ── Local : HTTPS avec certificat auto-signé
// ── Production (Railway) : HTTP simple (Railway gère HTTPS)
if (process.env.NODE_ENV === 'production') {
  const http = require('http');
  server = http.createServer(app);
  console.log('🌍 Production mode : HTTP (HTTPS handled by Railway)');
} else {
  const fs  = require('fs');
  const { execSync } = require('child_process');
  const https = require('https');
  const http  = require('http');

  const CERT_DIR  = path.join(__dirname, 'certs');
  const CERT_FILE = path.join(CERT_DIR, 'cert.pem');
  const KEY_FILE  = path.join(CERT_DIR, 'key.pem');

  if (!fs.existsSync(CERT_FILE) || !fs.existsSync(KEY_FILE)) {
    fs.mkdirSync(CERT_DIR, { recursive: true });
    console.log('🔐 Generating self-signed certificate...');
    execSync(
      `openssl req -x509 -newkey rsa:2048 -keyout ${KEY_FILE} -out ${CERT_FILE}` +
      ` -days 365 -nodes -subj "/CN=localhost"`,
      { stdio: 'inherit' }
    );
  }

  const sslOptions = {
    key:  fs.readFileSync(KEY_FILE),
    cert: fs.readFileSync(CERT_FILE),
  };

  server = https.createServer(sslOptions, app);

  // Redirect HTTP -> HTTPS en local
  const httpRedirect = http.createServer((req, res) => {
    res.writeHead(301, { Location: `https://${req.headers.host.split(':')[0]}:3443${req.url}` });
    res.end();
  });
  httpRedirect.listen(3000, '0.0.0.0', () => {
    console.log('↪  HTTP redirect on http://0.0.0.0:3000 -> HTTPS');
  });

  console.log('🔒 Local mode : HTTPS');
}

const io = new Server(server, { cors: { origin: '*' } });

// ════════════════════════════════════════
//  LOGIQUE MÉTIER
// ════════════════════════════════════════
const waitingQueue = [];
const pairs = new Map();

function getOnlineCount() { return io.sockets.sockets.size; }

function broadcastStats() {
  io.emit('stats', {
    online: getOnlineCount(),
    waiting: waitingQueue.length,
    chatting: pairs.size / 2
  });
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
  entryA.socket.emit('matched', { role: 'A', common });
  entryB.socket.emit('matched', { role: 'B', common });
  broadcastStats();
}

function removeFromQueue(socket) {
  const idx = waitingQueue.findIndex(e => e.socket === socket);
  if (idx !== -1) {
    const entry = waitingQueue[idx];
    if (entry.timer) clearTimeout(entry.timer);
    waitingQueue.splice(idx, 1);
  }
}

function tryMatch(socket, interests = []) {
  removeFromQueue(socket);
  const commonIdx = waitingQueue.findIndex(e =>
    interests.length > 0 && commonInterests(interests, e.interests).length > 0
  );
  if (commonIdx !== -1) {
    const partner = waitingQueue.splice(commonIdx, 1)[0];
    doMatch({ socket, interests }, partner);
  } else if (waitingQueue.length > 0 && interests.length === 0) {
    const partner = waitingQueue.shift();
    doMatch({ socket, interests }, partner);
  } else if (waitingQueue.length > 0 && interests.length > 0) {
    const entry = { socket, interests, timer: null };
    entry.timer = setTimeout(() => {
      const idx = waitingQueue.findIndex(e => e.socket === socket);
      if (idx === -1) return;
      waitingQueue.splice(idx, 1);
      if (waitingQueue.length > 0) {
        const partner = waitingQueue.shift();
        doMatch({ socket, interests }, partner);
        socket.emit('fallback_match');
      } else {
        waitingQueue.push({ socket, interests: [], timer: null });
        socket.emit('waiting_fallback');
        broadcastStats();
      }
    }, 10000);
    waitingQueue.push(entry);
    socket.emit('waiting');
    broadcastStats();
  } else {
    const entry = { socket, interests, timer: null };
    if (interests.length > 0) {
      entry.timer = setTimeout(() => {
        const idx = waitingQueue.findIndex(e => e.socket === socket);
        if (idx === -1) return;
        waitingQueue[idx].interests = [];
        socket.emit('waiting_fallback');
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
    const partnerSocket = io.sockets.sockets.get(partnerId);
    if (partnerSocket) partnerSocket.emit('partner_left');
  }
  broadcastStats();
}

function forwardToPartner(socket, event, data) {
  const partnerId = pairs.get(socket.id);
  if (partnerId) {
    const partnerSocket = io.sockets.sockets.get(partnerId);
    if (partnerSocket) partnerSocket.emit(event, data);
  }
}

io.on('connection', (socket) => {
  broadcastStats();
  socket.on('find_partner', ({ interests } = {}) => tryMatch(socket, interests || []));
  socket.on('message',  (data)     => forwardToPartner(socket, 'message', data));
  socket.on('typing',   (isTyping) => forwardToPartner(socket, 'typing', isTyping));
  socket.on('next',  () => { disconnect(socket); tryMatch(socket, []); });
  socket.on('stop',  () => { disconnect(socket); socket.emit('stopped'); broadcastStats(); });
  socket.on('disconnect', () => disconnect(socket));
  socket.on('webrtc_offer',         (data) => forwardToPartner(socket, 'webrtc_offer', data));
  socket.on('webrtc_answer',        (data) => forwardToPartner(socket, 'webrtc_answer', data));
  socket.on('webrtc_ice_candidate', (data) => forwardToPartner(socket, 'webrtc_ice_candidate', data));
  socket.on('webrtc_video_toggle',  (data) => forwardToPartner(socket, 'webrtc_video_toggle', data));
  socket.on('webrtc_audio_toggle',  (data) => forwardToPartner(socket, 'webrtc_audio_toggle', data));
});

// ── Démarrage ──
const PORT = process.env.PORT || 3443;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
});