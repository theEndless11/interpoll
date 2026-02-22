import { WebSocketServer } from 'ws';
import http from 'http';
import https from 'https';
import fs from 'fs';
import crypto from 'crypto';
import { URL } from 'url';
import mysql from 'mysql2/promise';

const PORT = process.env.PORT || 8080;
const DOMAIN = process.env.DOMAIN || 'https://endless.sbs';
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'https://endless.sbs';

const server = http.createServer();
const wss = new WebSocketServer({ server });
const clients = new Map();
const rooms = new Map();
const voteRegistry = new Set();
const oauthStates = new Map();
const sessions = new Map();

// ─── Persistence ──────────────────────────────────────────────────────────────
const DATA_DIR = new URL('./data', import.meta.url).pathname;
const RECEIPT_LOG_FILE = `${DATA_DIR}/storage.txt`;
const MESSAGE_CACHE_FILE = `${DATA_DIR}/message-cache.json`;

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const MAX_CACHED_MESSAGES = 500;
let messageCache = [];
try {
  if (fs.existsSync(MESSAGE_CACHE_FILE)) {
    messageCache = JSON.parse(fs.readFileSync(MESSAGE_CACHE_FILE, 'utf8'));
  }
} catch { messageCache = []; }

function cacheMessage(msg) {
  if (!msg?.type) return;
  const cacheable = ['new-poll', 'new-block', 'sync-response', 'new-event'];
  if (!cacheable.includes(msg.type || msg.data?.type)) return;
  messageCache.push({ ...msg, _cachedAt: Date.now() });
  while (messageCache.length > MAX_CACHED_MESSAGES) messageCache.shift();
}

function saveMessageCache() {
  try { fs.writeFileSync(MESSAGE_CACHE_FILE, JSON.stringify(messageCache)); }
  catch (err) { console.error('Failed to save message cache:', err.message); }
}
setInterval(saveMessageCache, 30_000);

// ─── MySQL ────────────────────────────────────────────────────────────────────
let db = null;

async function initMySQL() {
  if (!process.env.MYSQL_HOST) return;
  try {
    db = await mysql.createPool({
      host: process.env.MYSQL_HOST,
      user: process.env.MYSQL_USER,
      password: process.env.MYSQL_PASSWORD,
      database: process.env.MYSQL_DATABASE,
      port: process.env.MYSQL_PORT ? parseInt(process.env.MYSQL_PORT) : 3306,
      waitForConnections: true,
      connectionLimit: 5,
      ssl: { rejectUnauthorized: false },
    });
    console.log('✅ MySQL connected');
  } catch (err) {
    console.error('❌ MySQL failed:', err.message);
    db = null;
  }
}
await initMySQL();

async function queryMySQL(sql, params) {
  if (!db) return null;
  let conn;
  try {
    conn = await db.getConnection();
    const [rows] = await conn.execute(sql, params);
    return rows;
  } catch (err) {
    console.error('❌ MySQL query error:', err.message);
    return null;
  } finally {
    if (conn) conn.release();
  }
}

// ─── SSR Cache ────────────────────────────────────────────────────────────────
const ssrCache = new Map();
const SSR_CACHE_TTL = 3_600_000;

// ─── SSR Data Fetching ────────────────────────────────────────────────────────
async function fetchPostFromDB(postId) {
  const escaped = postId.replace(/[%_\\]/g, '\\$&');
  const rows = await queryMySQL(
    `SELECT soul, data FROM gun_nodes WHERE soul LIKE ? ESCAPE ? OR soul = ? LIMIT 10`,
    [`v2/%/posts/${escaped}`, '\\', `v2/posts/${postId}`]
  );
  if (!rows) return null;
  for (const row of rows) {
    try {
      const d = JSON.parse(row.data);
      if (d?.title) return {
        id: d.id || postId, authorName: d.authorName || 'Anonymous',
        title: d.title, content: d.content || '',
        imageIPFS: d.imageIPFS || '', createdAt: d.createdAt || Date.now(),
      };
    } catch { /* skip */ }
  }
  return null;
}

async function fetchPollFromDB(pollId) {
  const escaped = pollId.replace(/[%_\\]/g, '\\$&');
  const rows = await queryMySQL(
    `SELECT soul, data FROM gun_nodes WHERE soul LIKE ? ESCAPE ? OR soul = ? LIMIT 10`,
    [`v2/%/polls/${escaped}`, '\\', `v2/polls/${pollId}`]
  );
  if (!rows) return null;
  for (const row of rows) {
    try {
      const d = JSON.parse(row.data);
      if (d?.question) return {
        id: d.id || pollId, authorName: d.authorName || 'Anonymous',
        question: d.question, description: d.description || '',
        totalVotes: d.totalVotes || 0, createdAt: d.createdAt || Date.now(),
      };
    } catch { /* skip */ }
  }
  return null;
}

// ─── SSR Helpers ──────────────────────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function buildHtmlShell(head, initScript = '') {
  const ASSET_JS = process.env.ASSET_JS || '/assets2/index.js';
  const ASSET_CSS = process.env.ASSET_CSS || '/assets2/index.css';
  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    ${head}
    <link rel="stylesheet" crossorigin href="${DOMAIN}${ASSET_CSS}">
  </head>
  <body>
    <div id="app"></div>
    ${initScript}
    <script type="module" crossorigin src="${DOMAIN}${ASSET_JS}"></script>
  </body>
</html>`;
}

function generatePostHTML(post) {
  const desc = escapeHtml(post.content.slice(0, 160));
  const title = escapeHtml(post.title);
  const imageUrl = post.imageIPFS ? `https://ipfs.io/ipfs/${post.imageIPFS}` : `${DOMAIN}/og-default.png`;
  const postUrl = `${DOMAIN}/post/${post.id}`;
  return buildHtmlShell(`
    <title>${title} - Interpoll</title>
    <meta name="description" content="${desc}" />
    <meta property="og:type" content="article" />
    <meta property="og:title" content="${title}" />
    <meta property="og:description" content="${desc}" />
    <meta property="og:image" content="${imageUrl}" />
    <meta property="og:url" content="${postUrl}" />
    <meta property="og:site_name" content="Interpoll" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${title}" />
    <meta name="twitter:description" content="${desc}" />
    <meta name="twitter:image" content="${imageUrl}" />
    <link rel="canonical" href="${postUrl}" />
    <script type="application/ld+json">{"@context":"https://schema.org","@type":"BlogPosting","headline":"${title}","description":"${desc}","image":"${imageUrl}","author":{"@type":"Person","name":"${escapeHtml(post.authorName)}"},"datePublished":"${new Date(post.createdAt).toISOString()}"}</script>`,
    `<script>window.__INITIAL_POST_ID__="${escapeHtml(post.id)}";</script>`
  );
}

function generatePollHTML(poll) {
  const desc = escapeHtml((poll.description || `Vote on: ${poll.question}`).slice(0, 160));
  const question = escapeHtml(poll.question);
  const pollUrl = `${DOMAIN}/vote/${poll.id}`;
  return buildHtmlShell(`
    <title>${question} - Interpoll</title>
    <meta name="description" content="${desc}" />
    <meta property="og:type" content="website" />
    <meta property="og:title" content="${question}" />
    <meta property="og:description" content="${desc}" />
    <meta property="og:url" content="${pollUrl}" />
    <meta property="og:site_name" content="Interpoll" />
    <meta name="twitter:card" content="summary" />
    <meta name="twitter:title" content="${question}" />
    <meta name="twitter:description" content="${desc}" />
    <link rel="canonical" href="${pollUrl}" />
    <script type="application/ld+json">{"@context":"https://schema.org","@type":"CreativeWork","name":"${question}","description":"${desc}","author":{"@type":"Person","name":"${escapeHtml(poll.authorName)}"},"datePublished":"${new Date(poll.createdAt).toISOString()}"}</script>`,
    `<script>window.__INITIAL_POLL_ID__="${escapeHtml(poll.id)}";</script>`
  );
}

async function generateSitemap() {
  try {
    const rows = await queryMySQL(
      `SELECT soul, data FROM gun_nodes WHERE soul LIKE 'v2/communities/%/posts/post-%' OR soul LIKE 'v2/polls/poll-%'`,
      []
    );
    const posts = [], polls = [], seen = new Set();
    for (const row of rows || []) {
      try {
        const d = JSON.parse(row.data);
        if (!d?.id || seen.has(d.id)) continue;
        seen.add(d.id);
        if (row.soul.includes('/posts/')) posts.push({ id: d.id, createdAt: d.createdAt || Date.now() });
        else if (d.question) polls.push({ id: d.id, createdAt: d.createdAt || Date.now() });
      } catch { /* skip */ }
    }
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
    xml += `  <url><loc>${DOMAIN}/</loc><changefreq>hourly</changefreq></url>\n`;
    for (const p of posts)
      xml += `  <url><loc>${DOMAIN}/post/${p.id}</loc><lastmod>${new Date(p.createdAt).toISOString().split('T')[0]}</lastmod><changefreq>weekly</changefreq></url>\n`;
    for (const p of polls)
      xml += `  <url><loc>${DOMAIN}/vote/${p.id}</loc><lastmod>${new Date(p.createdAt).toISOString().split('T')[0]}</lastmod><changefreq>weekly</changefreq></url>\n`;
    return xml + '</urlset>';
  } catch {
    return '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>';
  }
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function generateRandomId(bytes = 16) { return crypto.randomBytes(bytes).toString('hex'); }

function setSessionCookie(res, user) {
  const sessionId = generateRandomId(16);
  sessions.set(sessionId, user);
  res.setHeader('Set-Cookie', `sessionId=${sessionId}; HttpOnly; Path=/; SameSite=None; Secure; Max-Age=604800`);
  return sessionId;
}

function getSessionFromRequest(req) {
  const cookie = req.headers['cookie'] || '';
  const sid = cookie.split(';').map(c => c.trim()).find(p => p.startsWith('sessionId='))?.split('=')[1];
  return sid ? sessions.get(sid) || null : null;
}

function postForm(urlString, data) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const body = new URLSearchParams(data).toString();
    const req = https.request({
      method: 'POST', hostname: url.hostname, path: url.pathname + url.search,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      let chunks = '';
      res.on('data', d => chunks += d.toString());
      res.on('end', () => { try { resolve(JSON.parse(chunks || '{}')); } catch (e) { reject(e); } });
    });
    req.on('error', reject); req.write(body); req.end();
  });
}

function getJson(urlString, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const req = https.request({ method: 'GET', hostname: url.hostname, path: url.pathname + url.search, headers }, (res) => {
      let chunks = '';
      res.on('data', d => chunks += d.toString());
      res.on('end', () => { try { resolve(JSON.parse(chunks || '{}')); } catch (e) { reject(e); } });
    });
    req.on('error', reject); req.end();
  });
}

function decodeJwt(token) {
  try {
    const payload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
  } catch { return null; }
}

// ─── HTTP Routes ──────────────────────────────────────────────────────────────
server.on('request', async (req, res) => {
  const origin = req.headers.origin || FRONTEND_ORIGIN;
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
  if (!req.url) { res.writeHead(400); res.end('Bad request'); return; }

  const url = new URL(req.url, `http://localhost:${PORT}`);

  // ── SSR: Post ─────────────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname.startsWith('/post/')) {
    const postId = url.pathname.split('/')[2];
    if (!postId) { res.writeHead(404); res.end('Not found'); return; }
    const cached = ssrCache.get(`post:${postId}`);
    if (cached && Date.now() - cached.ts < SSR_CACHE_TTL) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.end(cached.html); return;
    }
    const post = await fetchPostFromDB(postId);
    if (!post) { res.writeHead(404); res.end('Post not found'); return; }
    const html = generatePostHTML(post);
    ssrCache.set(`post:${postId}`, { html, ts: Date.now() });
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600, s-maxage=86400');
    res.end(html); return;
  }

  // ── SSR: Poll ─────────────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname.startsWith('/vote/')) {
    const pollId = url.pathname.split('/')[2];
    if (!pollId) { res.writeHead(404); res.end('Not found'); return; }
    const cached = ssrCache.get(`poll:${pollId}`);
    if (cached && Date.now() - cached.ts < SSR_CACHE_TTL) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.end(cached.html); return;
    }
    const poll = await fetchPollFromDB(pollId);
    if (!poll) { res.writeHead(404); res.end('Poll not found'); return; }
    const html = generatePollHTML(poll);
    ssrCache.set(`poll:${pollId}`, { html, ts: Date.now() });
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600, s-maxage=86400');
    res.end(html); return;
  }

  // ── Sitemap & Robots ──────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname === '/sitemap.xml') {
    res.setHeader('Content-Type', 'application/xml');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.end(await generateSitemap()); return;
  }

  if (req.method === 'GET' && url.pathname === '/robots.txt') {
    res.setHeader('Content-Type', 'text/plain');
    res.end(`User-agent: *\nAllow: /\nDisallow: /auth/\nDisallow: /api/\nSitemap: ${DOMAIN}/sitemap.xml\n`);
    return;
  }

  // ── Health ────────────────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', uptime: process.uptime(), clients: clients.size, cachedMessages: messageCache.length, mysql: !!db }));
    return;
  }

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
    res.end(); return;
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
        const user = { provider: 'google', sub: claims.sub, email: claims.email, name: claims.name || claims.email, picture: claims.picture || null };
        const sid = setSessionCookie(res, user);
        res.writeHead(302, { Location: `${FRONTEND_ORIGIN}/auth/callback?sessionId=${sid}` });
        res.end(); return;
      }
      return getJson('https://openidconnect.googleapis.com/v1/userinfo', { Authorization: `Bearer ${tokenResponse.access_token}` })
        .then((profile) => {
          const user = { provider: 'google', sub: profile.sub, email: profile.email, name: profile.name || profile.email, picture: profile.picture || null };
          const sid = setSessionCookie(res, user);
          res.writeHead(302, { Location: `${FRONTEND_ORIGIN}/auth/callback?sessionId=${sid}` });
          res.end();
        });
    }).catch((err) => { console.error('Google OAuth error:', err); res.writeHead(500); res.end('Google OAuth failed'); });
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
    res.end(); return;
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
      client_id: process.env.MS_CLIENT_ID || '', client_secret: process.env.MS_CLIENT_SECRET || '',
      scope: process.env.MS_SCOPES || 'openid profile email',
      code, redirect_uri: redirectUri, grant_type: 'authorization_code',
    }).then((tokenResponse) => {
      const claims = tokenResponse.id_token ? decodeJwt(tokenResponse.id_token) : null;
      if (!claims) throw new Error('No id_token from Microsoft');
      const user = { provider: 'microsoft', sub: claims.sub || claims.oid, email: claims.email || claims.preferred_username, name: claims.name || claims.preferred_username };
      const sid = setSessionCookie(res, user);
      res.writeHead(302, { Location: `${FRONTEND_ORIGIN}/auth/callback?sessionId=${sid}` });
      res.end();
    }).catch((err) => { console.error('Microsoft OAuth error:', err); res.writeHead(500); res.end('Microsoft OAuth failed'); });
    return;
  }

  // ── Session ───────────────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname === '/api/me') {
    let user = getSessionFromRequest(req);
    if (!user) {
      const sid = req.headers['authorization']?.match(/^Bearer\s+(.+)$/i)?.[1] || url.searchParams.get('sessionId');
      if (sid) user = sessions.get(sid) || null;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ user: user || null })); return;
  }

  if (req.method === 'POST' && url.pathname === '/auth/logout') {
    const cookie = req.headers['cookie'] || '';
    const sid = cookie.split(';').map(c => c.trim()).find(p => p.startsWith('sessionId='))?.split('=')[1];
    if (sid) sessions.delete(sid);
    res.setHeader('Set-Cookie', 'sessionId=; HttpOnly; Path=/; SameSite=None; Secure; Max-Age=0');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true })); return;
  }

  // ── Vote protection ───────────────────────────────────────────────────────
  if (req.method === 'POST' && url.pathname === '/api/vote-authorize') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      try {
        const { pollId, deviceId } = JSON.parse(body || '{}');
        if (!pollId || !deviceId) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ allowed: false, reason: 'missing pollId or deviceId' })); return;
        }
        const key = `${pollId}:${deviceId}`;
        const alreadyVoted = voteRegistry.has(key);
        if (!alreadyVoted) voteRegistry.add(key);
        fs.appendFile(RECEIPT_LOG_FILE, JSON.stringify({ type: 'vote-authorize', pollId, deviceId, allowed: !alreadyVoted, timestamp: Date.now() }) + '\n', () => {});
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ allowed: !alreadyVoted, reason: alreadyVoted ? 'already voted' : undefined }));
      } catch (err) {
        console.error('Error in /api/vote-authorize:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ allowed: true }));
      }
    }); return;
  }

  if (req.method === 'POST' && url.pathname === '/api/receipts') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      try {
        fs.appendFile(RECEIPT_LOG_FILE, JSON.stringify({ type: 'receipt', payload: JSON.parse(body || '{}'), timestamp: Date.now() }) + '\n', () => {});
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false }));
      }
    }); return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

// ─── WebSocket ────────────────────────────────────────────────────────────────
const PING_INTERVAL = 20_000;
const pingTimer = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) { ws.terminate(); return; }
    ws.isAlive = false;
    ws.ping();
  });
}, PING_INTERVAL);

wss.on('close', () => clearInterval(pingTimer));

wss.on('connection', (ws) => {
  let peerId = null;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString());
      switch (data.type) {
        case 'register':
          peerId = data.peerId;
          clients.set(peerId, ws);
          broadcast({ type: 'peer-list', peers: Array.from(clients.keys()) });
          for (const msg of messageCache) {
            try { ws.send(JSON.stringify(msg)); } catch { /* ignore */ }
          }
          break;
        case 'join-room': {
          const roomId = data.roomId || 'default';
          if (!rooms.has(roomId)) rooms.set(roomId, new Set());
          rooms.get(roomId).add(peerId);
          break;
        }
        case 'broadcast':
          broadcastToOthers(peerId, data.data);
          cacheMessage(data.data);
          break;
        case 'direct': {
          const targetWs = clients.get(data.targetPeer);
          if (targetWs?.readyState === 1) targetWs.send(JSON.stringify(data.data));
          break;
        }
        case 'new-poll':
        case 'new-block':
        case 'request-sync':
        case 'sync-response':
          broadcastToOthers(peerId, data);
          cacheMessage(data);
          break;
        case 'ping':
          if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'pong' }));
          break;
      }
    } catch (err) { console.error('WS error:', err); }
  });

  ws.on('close', () => {
    if (peerId) {
      clients.delete(peerId);
      rooms.forEach((peers, roomId) => {
        peers.delete(peerId);
        if (peers.size === 0) rooms.delete(roomId);
      });
      broadcast({ type: 'peer-left', peerId });
    }
  });

  ws.on('error', err => console.error('WebSocket error:', err));
  ws.send(JSON.stringify({ type: 'welcome', message: 'Connected to P2P relay', timestamp: Date.now() }));
});

function broadcast(msg) {
  clients.forEach(ws => { if (ws.readyState === 1) ws.send(JSON.stringify(msg)); });
}
function broadcastToOthers(excludeId, msg) {
  clients.forEach((ws, pid) => { if (pid !== excludeId && ws.readyState === 1) ws.send(JSON.stringify(msg)); });
}

// ─── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`Relay on :${PORT} | MySQL: ${db ? '✅' : '❌'} | Cache: ${messageCache.length} msgs`);
});

process.on('SIGINT', () => {
  saveMessageCache();
  clearInterval(pingTimer);
  wss.clients.forEach(ws => ws.close());
  server.close(() => process.exit(0));
});
