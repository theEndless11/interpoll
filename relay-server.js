//backend/relay-server-enhanced.js
// Enhanced with: 1-to-1 P2P chat, Full-text search, Improved auth security

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
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

const server = http.createServer();
const wss = new WebSocketServer({ server });
const clients = new Map();
const rooms = new Map();
const voteRegistry = new Set();
const oauthStates = new Map();
const sessions = new Map();
const activeChatSessions = new Map();

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
  const cacheable = ['new-poll', 'new-block', 'sync-response', 'new-event', 'new-post'];
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
      connectionLimit: 10,
      ssl: { rejectUnauthorized: false },
    });

    // Create search index tables
    await db.execute(`
      CREATE TABLE IF NOT EXISTS search_index (
        id VARCHAR(100) PRIMARY KEY,
        type ENUM('post', 'poll') NOT NULL,
        title TEXT,
        content TEXT,
        author VARCHAR(200),
        community VARCHAR(100),
        created_at BIGINT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FULLTEXT idx_title_content (title, content),
        INDEX idx_author (author),
        INDEX idx_community (community),
        INDEX idx_created (created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Chat messages table (encrypted)
    await db.execute(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id VARCHAR(100) PRIMARY KEY,
        room_id VARCHAR(200) NOT NULL,
        sender_id VARCHAR(100) NOT NULL,
        recipient_id VARCHAR(100) NOT NULL,
        encrypted_content TEXT NOT NULL,
        timestamp BIGINT NOT NULL,
        read_at BIGINT DEFAULT NULL,
        INDEX idx_room (room_id),
        INDEX idx_sender (sender_id),
        INDEX idx_recipient (recipient_id),
        INDEX idx_timestamp (timestamp)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // User profiles
    await db.execute(`
      CREATE TABLE IF NOT EXISTS user_profiles (
        user_id VARCHAR(100) PRIMARY KEY,
        username VARCHAR(100) UNIQUE,
        display_name VARCHAR(200),
        avatar_url TEXT,
        public_key TEXT,
        last_seen BIGINT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_username (username)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Session security
    await db.execute(`
      CREATE TABLE IF NOT EXISTS sessions (
        session_id VARCHAR(64) PRIMARY KEY,
        user_id VARCHAR(100) NOT NULL,
        ip_address VARCHAR(45),
        user_agent TEXT,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        last_activity BIGINT NOT NULL,
        INDEX idx_user (user_id),
        INDEX idx_expires (expires_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    console.log('✅ MySQL connected with enhanced tables');
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

// ─── Search Functions ─────────────────────────────────────────────────────────
async function indexContent(type, id, data) {
  if (!db) return;
  try {
    const title = type === 'post' ? data.title : data.question;
    const content = type === 'post' ? data.content : data.description;
    await db.execute(
      `INSERT INTO search_index (id, type, title, content, author, community, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         title = VALUES(title),
         content = VALUES(content),
         author = VALUES(author),
         updated_at = NOW()`,
      [id, type, title, content || '', data.authorName || 'Anonymous', data.communitySlug || '', data.createdAt || Date.now()]
    );
  } catch (err) {
    console.error('❌ Indexing error:', err.message);
  }
}

async function searchContent(query, filters = {}) {
  if (!db) return { results: [], total: 0 };
  try {
    const limit = Math.min(parseInt(filters.limit || '20'), 100);
    const offset = parseInt(filters.offset || '0');
    
    let sql = `
      SELECT id, type, title, content, author, community, created_at,
             MATCH(title, content) AGAINST(? IN NATURAL LANGUAGE MODE) as relevance
      FROM search_index
      WHERE MATCH(title, content) AGAINST(? IN NATURAL LANGUAGE MODE)
    `;
    const params = [query, query];

    if (filters.type) {
      sql += ` AND type = ?`;
      params.push(filters.type);
    }
    if (filters.community) {
      sql += ` AND community = ?`;
      params.push(filters.community);
    }

    sql += ` ORDER BY relevance DESC, created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const results = await queryMySQL(sql, params);
    
    const countSql = `
      SELECT COUNT(*) as total FROM search_index
      WHERE MATCH(title, content) AGAINST(? IN NATURAL LANGUAGE MODE)
      ${filters.type ? 'AND type = ?' : ''}
      ${filters.community ? 'AND community = ?' : ''}
    `;
    const countParams = [query];
    if (filters.type) countParams.push(filters.type);
    if (filters.community) countParams.push(filters.community);
    
    const countResult = await queryMySQL(countSql, countParams);
    const total = countResult?.[0]?.total || 0;

    return { results: results || [], total };
  } catch (err) {
    console.error('❌ Search error:', err.message);
    return { results: [], total: 0 };
  }
}

// ─── Enhanced Auth & Security ─────────────────────────────────────────────────
function generateSecureToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function createJWT(payload, expiresIn = '7d') {
  const header = { alg: 'HS256', typ: 'JWT' };
  const exp = Date.now() + (expiresIn === '7d' ? 7 * 24 * 60 * 60 * 1000 : 60 * 60 * 1000);
  const claims = { ...payload, exp, iat: Date.now() };
  
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64url');
  
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyJWT(token) {
  try {
    const [header, payload, signature] = token.split('.');
    const validSignature = crypto.createHmac('sha256', JWT_SECRET)
      .update(`${header}.${payload}`)
      .digest('base64url');
    
    if (signature !== validSignature) return null;
    
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (claims.exp < Date.now()) return null;
    
    return claims;
  } catch {
    return null;
  }
}

async function setSecureSession(res, req, user) {
  const sessionId = generateSecureToken(32);
  const expiresAt = Date.now() + (7 * 24 * 60 * 60 * 1000);
  
  const sessionData = {
    user,
    ip: req.socket.remoteAddress,
    userAgent: req.headers['user-agent'],
    createdAt: Date.now(),
  };
  
  sessions.set(sessionId, sessionData);
  
  if (db) {
    await db.execute(
      `INSERT INTO sessions (session_id, user_id, ip_address, user_agent, created_at, expires_at, last_activity)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [sessionId, user.sub, sessionData.ip, sessionData.userAgent, Date.now(), expiresAt, Date.now()]
    );
  }
  
  const jwt = createJWT({ sub: user.sub, email: user.email });
  
  res.setHeader('Set-Cookie', [
    `sessionId=${sessionId}; HttpOnly; Path=/; SameSite=None; Secure; Max-Age=604800`,
    `jwt=${jwt}; Path=/; SameSite=None; Secure; Max-Age=604800`
  ]);
  
  return { sessionId, jwt };
}

async function getSecureSession(req) {
  const cookie = req.headers['cookie'] || '';
  const sid = cookie.split(';').find(c => c.trim().startsWith('sessionId='))?.split('=')[1];
  const jwt = cookie.split(';').find(c => c.trim().startsWith('jwt='))?.split('=')[1];
  
  if (jwt) {
    const claims = verifyJWT(jwt);
    if (claims && sid) {
      const sessionData = sessions.get(sid);
      if (sessionData) {
        if (db) {
          await db.execute(`UPDATE sessions SET last_activity = ? WHERE session_id = ?`, [Date.now(), sid]);
        }
        return sessionData.user;
      }
    }
  }
  
  if (sid) {
    const sessionData = sessions.get(sid);
    if (sessionData) return sessionData.user;
  }
  
  return null;
}

// ─── P2P Chat Functions ───────────────────────────────────────────────────────
function getChatRoomId(user1, user2) {
  return [user1, user2].sort().join(':');
}

async function storeChatMessage(roomId, senderId, recipientId, encryptedContent) {
  if (!db) return;
  try {
    const messageId = `msg-${Date.now()}-${generateSecureToken(8)}`;
    await db.execute(
      `INSERT INTO chat_messages (id, room_id, sender_id, recipient_id, encrypted_content, timestamp)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [messageId, roomId, senderId, recipientId, encryptedContent, Date.now()]
    );
    return messageId;
  } catch (err) {
    console.error('❌ Chat storage error:', err.message);
  }
}

async function getChatHistory(roomId, limit = 50) {
  if (!db) return [];
  try {
    const messages = await queryMySQL(
      `SELECT id, sender_id, recipient_id, encrypted_content, timestamp, read_at
       FROM chat_messages
       WHERE room_id = ?
       ORDER BY timestamp DESC
       LIMIT ?`,
      [roomId, limit]
    );
    return (messages || []).reverse();
  } catch (err) {
    console.error('❌ Chat history error:', err.message);
    return [];
  }
}

async function markMessagesAsRead(roomId, userId) {
  if (!db) return;
  try {
    await db.execute(
      `UPDATE chat_messages
       SET read_at = ?
       WHERE room_id = ? AND recipient_id = ? AND read_at IS NULL`,
      [Date.now(), roomId, userId]
    );
  } catch (err) {
    console.error('❌ Mark read error:', err.message);
  }
}

// ─── OAuth helpers ────────────────────────────────────────────────────────────
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

// ─── SSR Functions ────────────────────────────────────────────────────────────
const ssrCache = new Map();
const SSR_CACHE_TTL = 3_600_000;

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
    <meta name="twitter:card" content="summary_large_image" />
    <link rel="canonical" href="${postUrl}" />`,
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
    <link rel="canonical" href="${pollUrl}" />`,
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
      xml += `  <url><loc>${DOMAIN}/post/${p.id}</loc><lastmod>${new Date(p.createdAt).toISOString().split('T')[0]}</lastmod></url>\n`;
    for (const p of polls)
      xml += `  <url><loc>${DOMAIN}/vote/${p.id}</loc><lastmod>${new Date(p.createdAt).toISOString().split('T')[0]}</lastmod></url>\n`;
    return xml + '</urlset>';
  } catch {
    return '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>';
  }
}

// ─── HTTP Routes ──────────────────────────────────────────────────────────────
server.on('request', async (req, res) => {
  const origin = req.headers.origin || FRONTEND_ORIGIN;
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
  if (!req.url) { res.writeHead(400); res.end('Bad request'); return; }

  const url = new URL(req.url, `http://localhost:${PORT}`);

  // ── SSR Routes ────────────────────────────────────────────────────────────
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

  // ── Search API ────────────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname === '/api/search') {
    const query = url.searchParams.get('q');
    if (!query || query.length < 2) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Query must be at least 2 characters' }));
      return;
    }
    
    const filters = {
      type: url.searchParams.get('type'),
      community: url.searchParams.get('community'),
      limit: url.searchParams.get('limit'),
      offset: url.searchParams.get('offset'),
    };
    
    const results = await searchContent(query, filters);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(results));
    return;
  }

  // ── Index content ─────────────────────────────────────────────────────────
  if (req.method === 'POST' && url.pathname === '/api/index') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', async () => {
      try {
        const { type, id, data } = JSON.parse(body || '{}');
        if (!type || !id || !data) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing required fields' }));
          return;
        }
        await indexContent(type, id, data);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (err) {
        console.error('Index error:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Indexing failed' }));
      }
    });
    return;
  }

  // ── Chat History ──────────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname === '/api/chat/history') {
    const user = await getSecureSession(req);
    if (!user) { res.writeHead(401); res.end('Unauthorized'); return; }
    
    const otherUserId = url.searchParams.get('userId');
    if (!otherUserId) { res.writeHead(400); res.end('Missing userId'); return; }
    
    const roomId = getChatRoomId(user.sub, otherUserId);
    const messages = await getChatHistory(roomId, 100);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ messages }));
    return;
  }

  // ── Mark messages as read ─────────────────────────────────────────────────
  if (req.method === 'POST' && url.pathname === '/api/chat/mark-read') {
    const user = await getSecureSession(req);
    if (!user) { res.writeHead(401); res.end('Unauthorized'); return; }
    
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', async () => {
      try {
        const { otherUserId } = JSON.parse(body || '{}');
        const roomId = getChatRoomId(user.sub, otherUserId);
        await markMessagesAsRead(roomId, user.sub);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(500); res.end('Error');
      }
    });
    return;
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
    res.end(JSON.stringify({ 
      status: 'ok', 
      uptime: process.uptime(), 
      clients: clients.size, 
      activeChatRooms: activeChatSessions.size,
      cachedMessages: messageCache.length, 
      mysql: !!db 
    }));
    return;
  }

  // ── Google OAuth ──────────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname === '/auth/google/start') {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const redirectUri = `${process.env.SERVER_ORIGIN || `http://localhost:${PORT}`}/auth/google/callback`;
    if (!clientId) { res.writeHead(500); res.end('Google OAuth not configured'); return; }
    const state = generateSecureToken(16);
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
    }).then(async (tokenResponse) => {
      const idToken = tokenResponse.id_token;
      if (idToken) {
        const claims = decodeJwt(idToken);
        if (!claims) throw new Error('Failed to decode id_token');
        const user = { provider: 'google', sub: claims.sub, email: claims.email, name: claims.name || claims.email, picture: claims.picture || null };
        const { sessionId } = await setSecureSession(res, req, user);
        res.writeHead(302, { Location: `${FRONTEND_ORIGIN}/auth/callback?sessionId=${sessionId}` });
        res.end(); return;
      }
      return getJson('https://openidconnect.googleapis.com/v1/userinfo', { Authorization: `Bearer ${tokenResponse.access_token}` })
        .then(async (profile) => {
          const user = { provider: 'google', sub: profile.sub, email: profile.email, name: profile.name || profile.email, picture: profile.picture || null };
          const { sessionId } = await setSecureSession(res, req, user);
          res.writeHead(302, { Location: `${FRONTEND_ORIGIN}/auth/callback?sessionId=${sessionId}` });
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
    const state = generateSecureToken(16);
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
    }).then(async (tokenResponse) => {
      const claims = tokenResponse.id_token ? decodeJwt(tokenResponse.id_token) : null;
      if (!claims) throw new Error('No id_token from Microsoft');
      const user = { provider: 'microsoft', sub: claims.sub || claims.oid, email: claims.email || claims.preferred_username, name: claims.name || claims.preferred_username };
      const { sessionId } = await setSecureSession(res, req, user);
      res.writeHead(302, { Location: `${FRONTEND_ORIGIN}/auth/callback?sessionId=${sessionId}` });
      res.end();
    }).catch((err) => { console.error('Microsoft OAuth error:', err); res.writeHead(500); res.end('Microsoft OAuth failed'); });
    return;
  }

  // ── Session ───────────────────────────────────────────────────────────────
  if (req.method === 'GET' && url.pathname === '/api/me') {
    const user = await getSecureSession(req);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ user: user || null })); return;
  }

  if (req.method === 'POST' && url.pathname === '/auth/logout') {
    const cookie = req.headers['cookie'] || '';
    const sid = cookie.split(';').find(c => c.trim().startsWith('sessionId='))?.split('=')[1];
    if (sid) {
      sessions.delete(sid);
      if (db) {
        await db.execute(`DELETE FROM sessions WHERE session_id = ?`, [sid]);
      }
    }
    res.setHeader('Set-Cookie', [
      'sessionId=; HttpOnly; Path=/; SameSite=None; Secure; Max-Age=0',
      'jwt=; Path=/; SameSite=None; Secure; Max-Age=0'
    ]);
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

wss.on('connection', (ws, req) => {
  let peerId = null;
  let userId = null;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message.toString());
      
      switch (data.type) {
        case 'register':
          peerId = data.peerId;
          userId = data.userId;
          clients.set(peerId, { ws, userId, peerId });
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

        // ── P2P Chat ──────────────────────────────────────────────────────────
        case 'chat-start': {
          const recipientId = data.recipientId;
          const roomId = getChatRoomId(userId, recipientId);
          activeChatSessions.set(roomId, { users: [userId, recipientId], createdAt: Date.now() });
          
          const recipientClient = Array.from(clients.values()).find(c => c.userId === recipientId);
          if (recipientClient?.ws.readyState === 1) {
            recipientClient.ws.send(JSON.stringify({
              type: 'chat-invite',
              from: userId,
              roomId,
            }));
          }
          break;
        }

        case 'chat-message': {
          const { recipientId, encryptedForRecipient, messageId, timestamp } = data;
          const roomId = getChatRoomId(userId, recipientId);
          
          const storedId = await storeChatMessage(roomId, userId, recipientId, encryptedForRecipient);
          
          const recipientClient = Array.from(clients.values()).find(c => c.userId === recipientId);
          if (recipientClient?.ws.readyState === 1) {
            recipientClient.ws.send(JSON.stringify({
  type: 'chat-message',
  from: userId,
  messageId: storedId || messageId,
  encryptedForRecipient,
  timestamp: timestamp || Date.now(),
}));
          }
          
          ws.send(JSON.stringify({
            type: 'chat-delivered',
            messageId: storedId || messageId,
            recipientId,
          }));
          break;
        }

        case 'chat-typing': {
          const { recipientId, isTyping } = data;
          const recipientClient = Array.from(clients.values()).find(c => c.userId === recipientId);
          if (recipientClient?.ws.readyState === 1) {
            recipientClient.ws.send(JSON.stringify({
              type: 'chat-typing',
              from: userId,
              isTyping,
            }));
          }
          break;
        }

        case 'chat-read': {
          const { recipientId } = data;
          const roomId = getChatRoomId(userId, recipientId);
          await markMessagesAsRead(roomId, userId);
          
          const senderClient = Array.from(clients.values()).find(c => c.userId === recipientId);
          if (senderClient?.ws.readyState === 1) {
            senderClient.ws.send(JSON.stringify({
              type: 'chat-read-receipt',
              from: userId,
            }));
          }
          break;
        }

        case 'broadcast':
          broadcastToOthers(peerId, data.data);
          cacheMessage(data.data);
          break;

        case 'direct': {
          const targetWs = clients.get(data.targetPeer)?.ws;
          if (targetWs?.readyState === 1) targetWs.send(JSON.stringify(data.data));
          break;
        }

        case 'new-poll':
        case 'new-block':
        case 'request-sync':
        case 'sync-response':
          broadcastToOthers(peerId, data);
          cacheMessage(data);
          
          if (data.type === 'new-poll' && data.poll) {
            await indexContent('poll', data.poll.id, data.poll);
          }
          break;

        case 'new-post':
          broadcastToOthers(peerId, data);
          cacheMessage(data);
          
          if (data.post) {
            await indexContent('post', data.post.id, data.post);
          }
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
      
      activeChatSessions.forEach((session, roomId) => {
        if (session.users.includes(userId)) {
          activeChatSessions.delete(roomId);
        }
      });
    }
  });

  ws.on('error', err => console.error('WebSocket error:', err));
  ws.send(JSON.stringify({ type: 'welcome', message: 'Connected to P2P relay', timestamp: Date.now() }));
});

function broadcast(msg) {
  clients.forEach(({ ws }) => { if (ws.readyState === 1) ws.send(JSON.stringify(msg)); });
}

function broadcastToOthers(excludeId, msg) {
  clients.forEach(({ ws, peerId }) => { 
    if (peerId !== excludeId && ws.readyState === 1) ws.send(JSON.stringify(msg)); 
  });
}

// ─── Cleanup old sessions ─────────────────────────────────────────────────────
setInterval(async () => {
  if (!db) return;
  try {
    await db.execute(`DELETE FROM sessions WHERE expires_at < ?`, [Date.now()]);
  } catch (err) {
    console.error('Session cleanup error:', err.message);
  }
}, 3600_000);

// ─── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`🚀 Enhanced Relay on :${PORT}`);
  console.log(`   MySQL: ${db ? '✅' : '❌'}`);
  console.log(`   Features: P2P Chat ✅ | Search ✅ | Enhanced Auth ✅`);
  console.log(`   Cache: ${messageCache.length} messages`);
});

process.on('SIGINT', () => {
  saveMessageCache();
  clearInterval(pingTimer);
  wss.clients.forEach(ws => ws.close());
  server.close(() => process.exit(0));
});

