// relay-server.js
// Enhanced WebSocket relay with SSR/SEO, persistence, and native WS keepalive

import { WebSocketServer } from 'ws';
import http from 'http';
import https from 'https';
import fs from 'fs';
import crypto from 'crypto';
import { URL } from 'url';
import Gun from 'gun';

const PORT = process.env.PORT || 8080;
const DOMAIN = process.env.DOMAIN || 'http://localhost:5173';
const server = http.createServer();
const wss = new WebSocketServer({ server });

const clients = new Map();  // peerId -> WebSocket
const rooms = new Map();    // roomId -> Set of peerIds

// ─── Persistence ──────────────────────────────────────────────────────────────
const DATA_DIR = new URL('./data', import.meta.url).pathname;
const VOTE_FILE = `${DATA_DIR}/votes.json`;
const SESSION_FILE = `${DATA_DIR}/sessions.json`;
const RECEIPT_LOG_FILE = `${DATA_DIR}/storage.txt`;
const MESSAGE_CACHE_FILE = `${DATA_DIR}/message-cache.json`;

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

// Vote registry — persisted so restarts don't allow re-voting
const voteRegistry = new Set(loadJson(VOTE_FILE, []));

// Sessions — persisted with TTL enforcement
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const sessions = new Map();
const _now = Date.now();
for (const [id, entry] of Object.entries(loadJson(SESSION_FILE, {}))) {
  if (entry?.expiresAt && entry.expiresAt > _now) sessions.set(id, entry);
}
saveJson(SESSION_FILE, Object.fromEntries(sessions)); // flush expired on boot

function persistVotes() { saveJson(VOTE_FILE, Array.from(voteRegistry)); }
function persistSessions() { saveJson(SESSION_FILE, Object.fromEntries(sessions)); }

// Message cache — replayed to newly connected peers
const MAX_CACHED_MESSAGES = 500;
let messageCache = loadJson(MESSAGE_CACHE_FILE, []);
console.log(`✅ Loaded ${messageCache.length} cached messages from disk`);

function cacheMessage(msg) {
  if (!msg?.type) return;
  const cacheable = ['new-poll', 'new-block', 'sync-response', 'new-event'];
  const type = msg.type || msg.data?.type;
  if (!cacheable.includes(type)) return;
  messageCache.push({ ...msg, _cachedAt: Date.now() });
  while (messageCache.length > MAX_CACHED_MESSAGES) messageCache.shift();
}

function saveMessageCache() {
  try { fs.writeFileSync(MESSAGE_CACHE_FILE, JSON.stringify(messageCache)); }
  catch (err) { console.error('Failed to save message cache:', err.message); }
}

setInterval(saveMessageCache, 30_000);

// ─── SEO Cache ────────────────────────────────────────────────────────────────
const seoCache = new Map();
const SEO_CACHE_TTL = 3_600_000; // 1 hour

// ─── GunDB for SSR ────────────────────────────────────────────────────────────
const gunServer = http.createServer();
const gun = Gun({
  peers: [process.env.GUN_URL || 'http://localhost:8765/gun'],
  web: gunServer,
  radisk: false,
  localStorage: false,
});

// ─── Auth ─────────────────────────────────────────────────────────────────────
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
const oauthStates = new Map();

console.log('Google OAuth config:', {
  clientIdConfigured: !!process.env.GOOGLE_CLIENT_ID,
  clientIdPreview: process.env.GOOGLE_CLIENT_ID ? String(process.env.GOOGLE_CLIENT_ID).slice(0, 12) + '...' : null,
  clientSecretConfigured: !!process.env.GOOGLE_CLIENT_SECRET,
});

function generateRandomId(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

function setSessionCookie(res, user) {
  const sessionId = generateRandomId(16);
  const expiresAt = Date.now() + SESSION_TTL_MS;
  sessions.set(sessionId, { ...user, expiresAt });
  persistSessions();
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  const cookie = `sessionId=${sessionId}; HttpOnly; Path=/; SameSite=None; Secure; Max-Age=${maxAge}`;
  res.setHeader('Set-Cookie', cookie);
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
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
    };
    const req = https.request(options, (res) => {
      let chunks = '';
      res.on('data', (d) => { chunks += d.toString(); });
      res.on('end', () => { try { resolve(JSON.parse(chunks || '{}')); } catch (e) { reject(e); } });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function getJson(urlString, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const options = { method: 'GET', hostname: url.hostname, path: url.pathname + url.search, headers };
    const req = https.request(options, (res) => {
      let chunks = '';
      res.on('data', (d) => { chunks += d.toString(); });
      res.on('end', () => { try { resolve(JSON.parse(chunks || '{}')); } catch (e) { reject(e); } });
    });
    req.on('error', reject);
    req.end();
  });
}

function decodeJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
  } catch (e) { console.error('Failed to decode JWT:', e); return null; }
}

// ─── SSR Helpers ──────────────────────────────────────────────────────────────

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

async function fetchPostFromGun(postId) {
  return new Promise((resolve) => {
    let resolved = false;
    gun.get('posts').get(postId).once((data) => {
      if (resolved) return;
      resolved = true;
      if (!data?.id || !data?.title) { resolve(null); return; }
      resolve({
        id: data.id, communityId: data.communityId || '',
        authorName: data.authorName || 'Anonymous', title: data.title,
        content: data.content || '', imageIPFS: data.imageIPFS || '',
        createdAt: data.createdAt || Date.now(),
        upvotes: data.upvotes || 0, downvotes: data.downvotes || 0,
      });
    });
    setTimeout(() => { if (!resolved) { resolved = true; resolve(null); } }, 3000);
  });
}

async function fetchPollOptionsFromGun(pollId) {
  return new Promise((resolve) => {
    let resolved = false;
    gun.get('polls').get(pollId).get('options').once((data) => {
      if (resolved) return;
      resolved = true;
      if (!data || typeof data !== 'object') { resolve(null); return; }
      const keys = Object.keys(data).filter((k) => !k.startsWith('_')).sort((a, b) => Number(a) - Number(b));
      resolve(keys.map((k) => ({ id: data[k]?.id ?? '', text: data[k]?.text ?? '', votes: data[k]?.votes ?? 0 })));
    });
    setTimeout(() => { if (!resolved) { resolved = true; resolve(null); } }, 2000);
  });
}

async function fetchPollFromGun(pollId) {
  return new Promise((resolve) => {
    let resolved = false;
    gun.get('polls').get(pollId).once(async (data) => {
      if (resolved) return;
      resolved = true;
      if (!data?.id || !data?.question) { resolve(null); return; }
      const options = await fetchPollOptionsFromGun(pollId);
      resolve({
        id: data.id, communityId: data.communityId || '',
        authorName: data.authorName || 'Anonymous', question: data.question,
        description: data.description || '', options: options || [],
        totalVotes: data.totalVotes || 0,
        createdAt: data.createdAt || Date.now(), expiresAt: data.expiresAt || Date.now(),
      });
    });
    setTimeout(() => { if (!resolved) { resolved = true; resolve(null); } }, 3000);
  });
}

function generatePostHTML(post) {
  const description = post.content.slice(0, 160);
  const imageUrl = post.imageIPFS || '/default-og.png';
  const postUrl = `${DOMAIN}/post/${post.id}`;
  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${escapeHtml(post.title)} - Interpoll</title>
    <meta name="description" content="${escapeHtml(description)}" />
    <meta property="og:type" content="article" />
    <meta property="og:title" content="${escapeHtml(post.title)}" />
    <meta property="og:description" content="${escapeHtml(description)}" />
    <meta property="og:image" content="${imageUrl}" />
    <meta property="og:url" content="${postUrl}" />
    <meta property="og:site_name" content="Interpoll" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${escapeHtml(post.title)}" />
    <meta name="twitter:description" content="${escapeHtml(description)}" />
    <meta name="twitter:image" content="${imageUrl}" />
    <link rel="canonical" href="${postUrl}" />
    <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "BlogPosting",
      "headline": "${escapeHtml(post.title)}",
      "description": "${escapeHtml(description)}",
      "image": "${imageUrl}",
      "author": { "@type": "Person", "name": "${escapeHtml(post.authorName)}" },
      "datePublished": "${new Date(post.createdAt).toISOString()}",
      "dateModified": "${new Date(post.createdAt).toISOString()}"
    }
    </script>
  </head>
  <body>
    <div id="app"></div>
    <script>window.__INITIAL_POST_ID__ = "${escapeHtml(post.id)}";</script>
    <script type="module" src="/src/main.ts"></script>
  </body>
</html>`;
}

function generatePollHTML(poll) {
  const description = poll.description.slice(0, 160) || `Vote on: ${poll.question}`;
  const pollUrl = `${DOMAIN}/vote/${poll.id}`;
  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${escapeHtml(poll.question)} - Interpoll</title>
    <meta name="description" content="${escapeHtml(description)}" />
    <meta property="og:type" content="website" />
    <meta property="og:title" content="${escapeHtml(poll.question)}" />
    <meta property="og:description" content="${escapeHtml(description)}" />
    <meta property="og:url" content="${pollUrl}" />
    <meta property="og:site_name" content="Interpoll" />
    <meta name="twitter:card" content="summary" />
    <meta name="twitter:title" content="${escapeHtml(poll.question)}" />
    <meta name="twitter:description" content="${escapeHtml(description)}" />
    <link rel="canonical" href="${pollUrl}" />
    <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "CreativeWork",
      "name": "${escapeHtml(poll.question)}",
      "description": "${escapeHtml(description)}",
      "author": { "@type": "Person", "name": "${escapeHtml(poll.authorName)}" },
      "datePublished": "${new Date(poll.createdAt).toISOString()}"
    }
    </script>
  </head>
  <body>
    <div id="app"></div>
    <script>window.__INITIAL_POLL_ID__ = "${escapeHtml(poll.id)}";</script>
    <script type="module" src="/src/main.ts"></script>
  </body>
</html>`;
}

async function generateSitemap() {
  try {
    const collect = (node) => new Promise((resolve) => {
      const items = [];
      node.map().once((data, key) => {
        if (data?.id && !key.startsWith('_')) items.push({ id: data.id, createdAt: data.createdAt || Date.now() });
      });
      setTimeout(() => resolve(items), 1000);
    });
    const [posts, polls] = await Promise.all([collect(gun.get('posts')), collect(gun.get('polls'))]);
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
    xml += `  <url><loc>${DOMAIN}/</loc><changefreq>hourly</changefreq></url>\n`;
    for (const p of posts)
      xml += `  <url><loc>${DOMAIN}/post/${p.id}</loc><lastmod>${new Date(p.createdAt).toISOString().split('T')[0]}</lastmod><changefreq>weekly</changefreq></url>\n`;
    for (const p of polls)
      xml += `  <url><loc>${DOMAIN}/vote/${p.id}</loc><lastmod>${new Date(p.createdAt).toISOString().split('T')[0]}</lastmod><changefreq>weekly</changefreq></url>\n`;
    xml += '</urlset>';
    return xml;
  } catch (error) {
    console.error('Error generating sitemap:', error);
    return '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>';
  }
}

function generateRobotsTxt() {
  return `User-agent: *\nAllow: /\nDisallow: /auth/\nDisallow: /api/\nCrawl-delay: 1\n\nSitemap: ${DOMAIN}/sitemap.xml\n`;
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

  // ── SSR: Post page ────────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname.startsWith('/post/')) {
    const postId = url.pathname.split('/')[2];
    if (!postId) { res.writeHead(404); res.end('Not found'); return; }
    const cacheKey = `post:${postId}`;
    const cached = seoCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < SEO_CACHE_TTL) {
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.end(cached.html); return;
    }
    const post = await fetchPostFromGun(postId);
    if (!post) { res.writeHead(404); res.end('Post not found'); return; }
    const html = generatePostHTML(post);
    seoCache.set(cacheKey, { html, timestamp: Date.now() });
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600, s-maxage=86400');
    res.end(html); return;
  }

  // ── SSR: Poll page ────────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname.startsWith('/vote/')) {
    const pollId = url.pathname.split('/')[2];
    if (!pollId) { res.writeHead(404); res.end('Not found'); return; }
    const cacheKey = `poll:${pollId}`;
    const cached = seoCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < SEO_CACHE_TTL) {
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.end(cached.html); return;
    }
    const poll = await fetchPollFromGun(pollId);
    if (!poll) { res.writeHead(404); res.end('Poll not found'); return; }
    const html = generatePollHTML(poll);
    seoCache.set(cacheKey, { html, timestamp: Date.now() });
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600, s-maxage=86400');
    res.end(html); return;
  }

  // ── Sitemap & Robots ──────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname === '/sitemap.xml') {
    const sitemap = await generateSitemap();
    res.setHeader('Content-Type', 'application/xml');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.end(sitemap); return;
  }

  if (req.method === 'GET' && url.pathname === '/robots.txt') {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.end(generateRobotsTxt()); return;
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
      const accessToken = tokenResponse.access_token;
      if (!accessToken) throw new Error('No id_token or access_token from Google');
      return getJson('https://openidconnect.googleapis.com/v1/userinfo', { Authorization: `Bearer ${accessToken}` })
        .then((profile) => {
          if (!profile?.sub) throw new Error('No userinfo from Google');
          const user = { provider: 'google', sub: profile.sub, email: profile.email, name: profile.name || profile.email, picture: profile.picture || null };
          const sid = setSessionCookie(res, user);
          res.writeHead(302, { Location: `${FRONTEND_ORIGIN}/auth/callback?sessionId=${sid}` });
          res.end();
        });
    }).catch((error) => {
      console.error('Google OAuth error:', error);
      res.writeHead(500); res.end('Google OAuth failed');
    }); return;
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
      const idToken = tokenResponse.id_token;
      const claims = idToken ? decodeJwt(idToken) : null;
      if (!claims) throw new Error('No id_token from Microsoft');
      const user = { provider: 'microsoft', sub: claims.sub || claims.oid, email: claims.email || claims.preferred_username, name: claims.name || claims.preferred_username };
      const sid = setSessionCookie(res, user);
      res.writeHead(302, { Location: `${FRONTEND_ORIGIN}/auth/callback?sessionId=${sid}` });
      res.end();
    }).catch((error) => {
      console.error('Microsoft OAuth error:', error);
      res.writeHead(500); res.end('Microsoft OAuth failed');
    }); return;
  }

  // ── Session / Me ──────────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname === '/api/me') {
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
    res.end(JSON.stringify({ user: user || null })); return;
  }

  if (req.method === 'POST' && url.pathname === '/auth/logout') {
    const cookieHeader = req.headers['cookie'];
    if (cookieHeader) {
      const sid = cookieHeader.split(';').map((c) => c.trim()).find((p) => p.startsWith('sessionId='))?.split('=')[1];
      if (sid) { sessions.delete(sid); persistSessions(); }
    }
    res.setHeader('Set-Cookie', 'sessionId=; HttpOnly; Path=/; SameSite=None; Secure; Max-Age=0');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true })); return;
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
          res.end(JSON.stringify({ allowed: false, reason: 'missing pollId or deviceId' })); return;
        }
        const key = `${pollId}:${deviceId}`;
        const alreadyVoted = voteRegistry.has(key);
        if (!alreadyVoted) { voteRegistry.add(key); persistVotes(); }
        fs.appendFile(RECEIPT_LOG_FILE, JSON.stringify({ type: 'vote-authorize', pollId, deviceId, allowed: !alreadyVoted, timestamp: Date.now() }) + '\n', () => {});
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ allowed: !alreadyVoted, reason: alreadyVoted ? 'already voted' : undefined }));
      } catch (error) {
        console.error('Error in /api/vote-authorize:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ allowed: true }));
      }
    }); return;
  }

  if (req.method === 'POST' && url.pathname === '/api/receipts') {
    let body = '';
    req.on('data', (chunk) => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        fs.appendFile(RECEIPT_LOG_FILE, JSON.stringify({ type: 'receipt', payload: data, timestamp: Date.now() }) + '\n', (err) => {
          if (err) console.error('Failed to write receipt log:', err);
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (error) {
        console.error('Error in /api/receipts:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false }));
      }
    }); return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

// ─── WebSocket + Native Keepalive ────────────────────────────────────────────
// Native ping every 20s prevents proxies (Render, Railway, Cloudflare) from
// killing idle connections. Clients that don't pong are terminated.

const PING_INTERVAL = 20_000;
const pingTimer = setInterval(() => {
  wss.clients.forEach((ws) => {
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
          console.log(`✅ Peer registered: ${peerId} (total: ${clients.size})`);
          broadcast({ type: 'peer-list', peers: Array.from(clients.keys()) });
          // Replay cached messages so new peer catches up without full sync
          for (const msg of messageCache) {
            try { ws.send(JSON.stringify(msg)); } catch { /* ignore */ }
          }
          break;

        case 'join-room': {
          const roomId = data.roomId || 'default';
          if (!rooms.has(roomId)) rooms.set(roomId, new Set());
          rooms.get(roomId).add(peerId);
          break; // no log — fires on every reconnect
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
          // JSON-level ping — reply so client knows server is alive
          if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'pong' }));
          break;

        default:
          // Silently ignore unknown types — no log spam
          break;
      }
    } catch (error) { console.error('WS message error:', error); }
  });

  ws.on('close', () => {
    if (peerId) {
      clients.delete(peerId);
      rooms.forEach((peers, roomId) => {
        peers.delete(peerId);
        if (peers.size === 0) rooms.delete(roomId);
      });
      console.log(`❌ Peer disconnected: ${peerId} (total: ${clients.size})`);
      broadcast({ type: 'peer-left', peerId });
    }
  });

  ws.on('error', (error) => { console.error('WebSocket error:', error); });

  ws.send(JSON.stringify({ type: 'welcome', message: 'Connected to P2P relay', timestamp: Date.now() }));
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function broadcast(message) {
  clients.forEach((ws) => { if (ws.readyState === 1) ws.send(JSON.stringify(message)); });
}

function broadcastToOthers(excludePeerId, message) {
  clients.forEach((ws, pid) => { if (pid !== excludePeerId && ws.readyState === 1) ws.send(JSON.stringify(message)); });
}

// ─── Periodic session cleanup ─────────────────────────────────────────────────

setInterval(() => {
  const now = Date.now();
  let pruned = 0;
  for (const [id, entry] of sessions) {
    if (entry.expiresAt && entry.expiresAt < now) { sessions.delete(id); pruned++; }
  }
  if (pruned > 0) { console.log(`🧹 Pruned ${pruned} expired sessions`); persistSessions(); }
}, 60 * 60 * 1000);

// ─── Start ────────────────────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log('');
  console.log('╔════════════════════════════════════════════╗');
  console.log('║   🚀 Enhanced Relay Server with SSR/SEO   ║');
  console.log('╚════════════════════════════════════════════╝');
  console.log('');
  console.log(`🌐 WebSocket : ws://localhost:${PORT}`);
  console.log(`📡 Domain    : ${DOMAIN}`);
  console.log(`🔍 Sitemap   : ${DOMAIN}/sitemap.xml`);
  console.log(`🤖 Robots    : ${DOMAIN}/robots.txt`);
  console.log(`📦 Votes     : ${voteRegistry.size} persisted`);
  console.log(`🔑 Sessions  : ${sessions.size} persisted`);
  console.log(`💬 Msg cache : ${messageCache.length} messages`);
  console.log('');
  console.log('Press Ctrl+C to stop');
  console.log('');
});

process.on('SIGINT', () => {
  console.log('\n👋 Shutting down...');
  persistVotes();
  persistSessions();
  saveMessageCache();
  clearInterval(pingTimer);
  wss.clients.forEach((ws) => ws.close());
  server.close(() => { console.log('✅ Server closed'); process.exit(0); });
});
