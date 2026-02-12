// relay-server.js
// Simple WebSocket relay for cross-device/cross-browser P2P sync

import { WebSocketServer } from 'ws';
import http from 'http';
import https from 'https';
import fs from 'fs';
import crypto from 'crypto';
import { URL } from 'url';

const PORT = process.env.PORT || 8080;
const server = http.createServer();
const wss = new WebSocketServer({ server });

const clients = new Map();   // peerId -> WebSocket
const rooms = new Map();     // roomId -> Set of peerIds

// ─── Persistence ────────────────────────────────────────────────────────────
// FIX: voteRegistry and sessions were in-memory only — reset on every server
// restart, allowing users to vote again and losing all login sessions.
// Now persisted to JSON files so they survive restarts.

const DATA_DIR = new URL('./data', import.meta.url).pathname;
const VOTE_FILE = `${DATA_DIR}/votes.json`;
const SESSION_FILE = `${DATA_DIR}/sessions.json`;
const RECEIPT_LOG_FILE = `${DATA_DIR}/storage.txt`;

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadJson(file, fallback) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) { console.error(`Failed to load ${file}:`, e); }
  return fallback;
}

function saveJson(file, data) {
  try { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }
  catch (e) { console.error(`Failed to save ${file}:`, e); }
}

// Load persisted vote registry (Set stored as Array in JSON)
const voteRegistryData = loadJson(VOTE_FILE, []);
const voteRegistry = new Set(voteRegistryData);

// Load persisted sessions (Map stored as Object in JSON)
// FIX: Also enforce session expiry — sessions older than 7 days are dropped
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const rawSessions = loadJson(SESSION_FILE, {});
const sessions = new Map();
const now = Date.now();
for (const [id, entry] of Object.entries(rawSessions)) {
  if (entry && entry.expiresAt && entry.expiresAt > now) {
    sessions.set(id, entry);
  }
}
// Persist cleaned sessions immediately
saveJson(SESSION_FILE, Object.fromEntries(sessions));

function persistVotes() {
  saveJson(VOTE_FILE, Array.from(voteRegistry));
}

function persistSessions() {
  saveJson(SESSION_FILE, Object.fromEntries(sessions));
}

// ─── Auth helpers ────────────────────────────────────────────────────────────

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';

console.log('Google OAuth config:', {
  clientIdConfigured: !!process.env.GOOGLE_CLIENT_ID,
  clientIdPreview: process.env.GOOGLE_CLIENT_ID ? String(process.env.GOOGLE_CLIENT_ID).slice(0, 12) + '...' : null,
  clientSecretConfigured: !!process.env.GOOGLE_CLIENT_SECRET,
});

// Minimal in-memory OAuth state (short-lived, ok to lose on restart)
const oauthStates = new Map();

function generateRandomId(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

function setSessionCookie(res, user) {
  const sessionId = generateRandomId(16);
  const expiresAt = Date.now() + SESSION_TTL_MS;
  sessions.set(sessionId, { ...user, expiresAt });
  persistSessions();
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  // SameSite=None;Secure required for cross-origin cookie on Render
  const cookie = `sessionId=${sessionId}; HttpOnly; Path=/; SameSite=None; Secure; Max-Age=${maxAge}`;
  res.setHeader('Set-Cookie', cookie);
  // Return sessionId so callers can also embed it in the redirect URL
  // (fallback for browsers that block third-party cookies)
  return sessionId;
}

function getSessionFromRequest(req) {
  const cookieHeader = req.headers['cookie'];
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(';').map((c) => c.trim());
  const sessionPart = parts.find((p) => p.startsWith('sessionId='));
  if (!sessionPart) return null;
  const sessionId = sessionPart.split('=')[1];
  if (!sessionId) return null;
  const entry = sessions.get(sessionId);
  if (!entry) return null;
  // FIX: Check expiry
  if (entry.expiresAt && entry.expiresAt < Date.now()) {
    sessions.delete(sessionId);
    persistSessions();
    return null;
  }
  const { expiresAt, ...user } = entry;
  return user;
}

function postForm(urlString, data) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const body = new URLSearchParams(data).toString();
    const options = {
      method: 'POST', hostname: url.hostname, path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    };
    const req = https.request(options, (res) => {
      let chunks = '';
      res.on('data', (d) => { chunks += d.toString(); });
      res.on('end', () => {
        try { resolve(JSON.parse(chunks || '{}')); }
        catch (error) { reject(error); }
      });
    });
    req.on('error', (err) => reject(err));
    req.write(body);
    req.end();
  });
}

function getJson(urlString, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const options = {
      method: 'GET', hostname: url.hostname, path: url.pathname + url.search, headers,
    };
    const req = https.request(options, (res) => {
      let chunks = '';
      res.on('data', (d) => { chunks += d.toString(); });
      res.on('end', () => {
        try { resolve(JSON.parse(chunks || '{}')); }
        catch (error) { reject(error); }
      });
    });
    req.on('error', (err) => reject(err));
    req.end();
  });
}

function decodeJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
  } catch (error) { console.error('Failed to decode JWT:', error); return null; }
}

// ─── HTTP routes ──────────────────────────────────────────────────────────────

server.on('request', (req, res) => {
  // Wildcard CORS — allow any origin for Render deployment
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
  if (!req.url) { res.writeHead(400); res.end('Bad request'); return; }

  const url = new URL(req.url, `http://localhost:${PORT}`);

  // ── Google OAuth ──────────────────────────────────────────────────────────

  if (req.method === 'GET' && url.pathname === '/auth/google/start') {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const redirectUri = `${process.env.SERVER_ORIGIN || `http://localhost:${PORT}`}/auth/google/callback`;
    if (!clientId) { res.writeHead(500); res.end('Google OAuth not configured'); return; }
    const state = generateRandomId(16);
    oauthStates.set(state, 'google');
    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('access_type', 'offline');
    res.writeHead(302, { Location: authUrl.toString() });
    res.end();
    return;
  }

  if (req.method === 'GET' && url.pathname === '/auth/google/callback') {
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    if (!code || !state || oauthStates.get(state) !== 'google') {
      res.writeHead(400); res.end('Invalid OAuth state'); return;
    }
    oauthStates.delete(state);
    const redirectUri = `${process.env.SERVER_ORIGIN || `http://localhost:${PORT}`}/auth/google/callback`;
    postForm('https://oauth2.googleapis.com/token', {
      code, client_id: process.env.GOOGLE_CLIENT_ID || '',
      client_secret: process.env.GOOGLE_CLIENT_SECRET || '',
      redirect_uri: redirectUri, grant_type: 'authorization_code',
    }).then((tokenResponse) => {
      const idToken = tokenResponse.id_token;
      if (idToken) {
        const claims = decodeJwt(idToken);
        if (!claims) throw new Error('Failed to decode id_token');
        const user = {
          provider: 'google', sub: claims.sub, email: claims.email,
          name: claims.name || claims.email, picture: claims.picture || null,
        };
        const sid = setSessionCookie(res, user);
        res.writeHead(302, { Location: `${FRONTEND_ORIGIN}/auth/callback?sessionId=${sid}` });
        res.end();
        return;
      }
      const accessToken = tokenResponse.access_token;
      if (!accessToken) throw new Error('No id_token or access_token from Google');
      return getJson('https://openidconnect.googleapis.com/v1/userinfo', {
        Authorization: `Bearer ${accessToken}`,
      }).then((profile) => {
        if (!profile?.sub) throw new Error('No userinfo from Google');
        const user = {
          provider: 'google', sub: profile.sub, email: profile.email,
          name: profile.name || profile.email, picture: profile.picture || null,
        };
        const sid = setSessionCookie(res, user);
        res.writeHead(302, { Location: `${FRONTEND_ORIGIN}/auth/callback?sessionId=${sid}` });
        res.end();
      });
    }).catch((error) => {
      console.error('Google OAuth error:', error);
      res.writeHead(500); res.end('Google OAuth failed');
    });
    return;
  }

  // ── Microsoft OAuth ───────────────────────────────────────────────────────

  if (req.method === 'GET' && url.pathname === '/auth/microsoft/start') {
    const clientId = process.env.MS_CLIENT_ID;
    const tenant = process.env.MS_TENANT || 'common';
    const redirectUri = `${process.env.SERVER_ORIGIN || `http://localhost:${PORT}`}/auth/microsoft/callback`;
    if (!clientId) { res.writeHead(500); res.end('Microsoft OAuth not configured'); return; }
    const state = generateRandomId(16);
    oauthStates.set(state, 'microsoft');
    const authUrl = new URL(`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`);
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_mode', 'query');
    authUrl.searchParams.set('scope', process.env.MS_SCOPES || 'openid profile email');
    authUrl.searchParams.set('state', state);
    res.writeHead(302, { Location: authUrl.toString() });
    res.end();
    return;
  }

  if (req.method === 'GET' && url.pathname === '/auth/microsoft/callback') {
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    if (!code || !state || oauthStates.get(state) !== 'microsoft') {
      res.writeHead(400); res.end('Invalid OAuth state'); return;
    }
    oauthStates.delete(state);
    const tenant = process.env.MS_TENANT || 'common';
    const redirectUri = `${process.env.SERVER_ORIGIN || `http://localhost:${PORT}`}/auth/microsoft/callback`;
    postForm(`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`, {
      client_id: process.env.MS_CLIENT_ID || '',
      client_secret: process.env.MS_CLIENT_SECRET || '',
      scope: process.env.MS_SCOPES || 'openid profile email',
      code, redirect_uri: redirectUri, grant_type: 'authorization_code',
    }).then((tokenResponse) => {
      const idToken = tokenResponse.id_token;
      const claims = idToken ? decodeJwt(idToken) : null;
      if (!claims) throw new Error('No id_token from Microsoft');
      const user = {
        provider: 'microsoft', sub: claims.sub || claims.oid,
        email: claims.email || claims.preferred_username,
        name: claims.name || claims.preferred_username,
      };
      const sid = setSessionCookie(res, user);
      res.writeHead(302, { Location: `${FRONTEND_ORIGIN}/auth/callback?sessionId=${sid}` });
      res.end();
    }).catch((error) => {
      console.error('Microsoft OAuth error:', error);
      res.writeHead(500); res.end('Microsoft OAuth failed');
    });
    return;
  }

  // ── Session / Me ──────────────────────────────────────────────────────────

  if (req.method === 'GET' && url.pathname === '/api/me') {
    // Accept sessionId from cookie, Authorization header, or query param
    // (query param / header used when wildcard CORS blocks cookies)
    let user = getSessionFromRequest(req);
    if (!user) {
      const authHeader = req.headers['authorization'] || '';
      const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
      const sid = bearerMatch?.[1] || url.searchParams.get('sessionId') || null;
      if (sid) {
        const entry = sessions.get(sid);
        if (entry && (!entry.expiresAt || entry.expiresAt > Date.now())) {
          const { expiresAt, ...u } = entry;
          user = u;
        }
      }
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ user: user || null }));
    return;
  }

  if (req.method === 'POST' && url.pathname === '/auth/logout') {
    const cookieHeader = req.headers['cookie'];
    if (cookieHeader) {
      const parts = cookieHeader.split(';').map((c) => c.trim());
      const sessionPart = parts.find((p) => p.startsWith('sessionId='));
      if (sessionPart) {
        const sessionId = sessionPart.split('=')[1];
        if (sessionId) {
          sessions.delete(sessionId);
          persistSessions();
        }
      }
    }
    res.setHeader('Set-Cookie', 'sessionId=; HttpOnly; Path=/; SameSite=None; Secure; Max-Age=0');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // ── Vote protection ───────────────────────────────────────────────────────

  if (req.method === 'POST' && url.pathname === '/api/vote-authorize') {
    let body = '';
    req.on('data', (chunk) => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const pollId = String(data.pollId || '');
        const deviceId = String(data.deviceId || '');
        if (!pollId || !deviceId) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ allowed: false, reason: 'missing pollId or deviceId' }));
          return;
        }
        const key = `${pollId}:${deviceId}`;
        const alreadyVoted = voteRegistry.has(key);
        if (!alreadyVoted) {
          voteRegistry.add(key);
          persistVotes(); // FIX: persist immediately so restarts don't allow re-voting
        }
        const logEntry = { type: 'vote-authorize', pollId, deviceId, allowed: !alreadyVoted, timestamp: Date.now() };
        fs.appendFile(RECEIPT_LOG_FILE, JSON.stringify(logEntry) + '\n', () => {});
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ allowed: !alreadyVoted, reason: alreadyVoted ? 'already voted' : undefined }));
      } catch (error) {
        console.error('Error in /api/vote-authorize:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ allowed: true }));
      }
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/receipts') {
    let body = '';
    req.on('data', (chunk) => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const logEntry = { type: 'receipt', payload: data, timestamp: Date.now() };
        fs.appendFile(RECEIPT_LOG_FILE, JSON.stringify(logEntry) + '\n', (err) => {
          if (err) console.error('Failed to write receipt log:', err);
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (error) {
        console.error('Error in /api/receipts:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false }));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

// ─── WebSocket ────────────────────────────────────────────────────────────────

wss.on('connection', (ws, req) => {
  let peerId = null;
  console.log('🔌 New connection from', req.socket.remoteAddress);

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString());
      switch (data.type) {
        case 'register':
          peerId = data.peerId;
          clients.set(peerId, ws);
          console.log(`✅ Peer registered: ${peerId} (Total: ${clients.size})`);
          broadcast({ type: 'peer-list', peers: Array.from(clients.keys()) });
          break;
        case 'join-room':
          const roomId = data.roomId || 'default';
          if (!rooms.has(roomId)) rooms.set(roomId, new Set());
          rooms.get(roomId).add(peerId);
          console.log(`🚪 ${peerId} joined room: ${roomId}`);
          break;
        case 'broadcast':
          console.log(`📡 Broadcasting ${data.data?.type || 'message'} from ${peerId}`);
          broadcastToOthers(peerId, data.data);
          break;
        case 'direct':
          const targetWs = clients.get(data.targetPeer);
          if (targetWs?.readyState === 1) targetWs.send(JSON.stringify(data.data));
          break;
        case 'new-poll':
        case 'new-block':
        case 'request-sync':
        case 'sync-response':
          console.log(`📡 Broadcasting ${data.type} from ${peerId}`);
          broadcastToOthers(peerId, data);
          break;
        default:
          console.log('Unknown message type:', data.type);
      }
    } catch (error) { console.error('Error handling message:', error); }
  });

  ws.on('close', () => {
    if (peerId) {
      clients.delete(peerId);
      rooms.forEach((peers, roomId) => {
        peers.delete(peerId);
        if (peers.size === 0) rooms.delete(roomId);
      });
      console.log(`❌ Peer disconnected: ${peerId} (Total: ${clients.size})`);
      broadcast({ type: 'peer-left', peerId });
    }
  });

  ws.on('error', (error) => { console.error('WebSocket error:', error); });

  ws.send(JSON.stringify({ type: 'welcome', message: 'Connected to P2P relay', timestamp: Date.now() }));
});

function broadcast(message) {
  clients.forEach((ws) => {
    if (ws.readyState === 1) ws.send(JSON.stringify(message));
  });
}

function broadcastToOthers(excludePeerId, message) {
  clients.forEach((ws, pid) => {
    if (pid !== excludePeerId && ws.readyState === 1) ws.send(JSON.stringify(message));
  });
}

server.listen(PORT, () => {
  console.log(`🚀 P2P Relay Server running on ws://localhost:${PORT}`);
  console.log(`📦 Persisted votes loaded: ${voteRegistry.size}`);
  console.log(`🔑 Persisted sessions loaded: ${sessions.size}`);
});

// ─── Periodic session cleanup ─────────────────────────────────────────────────
// Prune expired sessions every hour to prevent unbounded growth
setInterval(() => {
  const now = Date.now();
  let pruned = 0;
  for (const [id, entry] of sessions) {
    if (entry.expiresAt && entry.expiresAt < now) { sessions.delete(id); pruned++; }
  }
  if (pruned > 0) { console.log(`🧹 Pruned ${pruned} expired sessions`); persistSessions(); }
}, 60 * 60 * 1000);

process.on('SIGINT', () => {
  console.log('\n👋 Shutting down...');
  persistVotes();
  persistSessions();
  wss.clients.forEach((ws) => ws.close());
  server.close(() => { console.log('✅ Server closed'); process.exit(0); });
});
