'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const TG_TOKEN = process.env.TG_BOT_TOKEN || '';
const TG_CHATS = (process.env.TG_CHAT_ID || '').split(',').map((s) => s.trim()).filter(Boolean);
const TG_API = process.env.TG_API_BASE || 'https://api.telegram.org';
const ADMIN = process.env.ADMIN_TOKEN || '';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const ORIGINS = (process.env.ALLOWED_ORIGIN || '').split(',').map((x) => x.trim()).filter(Boolean);
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUB = path.join(__dirname, 'docs');
const MAX_REVIEWS = 5000;
const SESSION_MS = 12 * 3600e3;

fs.mkdirSync(DATA, { recursive: true });
const reviewsFile = path.join(DATA, 'reviews.json');
const siteFile = path.join(DATA, 'site.json');
const ordersLog = path.join(DATA, 'orders.jsonl');

function writeAtomic(file, obj) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj));
  fs.renameSync(tmp, file);
}
function readJsonFile(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return fallback(); throw e; }
}

let reviews = readJsonFile(reviewsFile, () => []);
let site = readJsonFile(siteFile, () => ({ ...JSON.parse(fs.readFileSync(path.join(__dirname, 'default-site.json'), 'utf8')), rev: 1 }));
if (!fs.existsSync(siteFile)) writeAtomic(siteFile, site);

const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) { hits.set(key, arr); return true; }
  arr.push(now); hits.set(key, arr); return false;
}
const sessions = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, a] of hits) if (!a.length || now - a[a.length - 1] > 3600e3) hits.delete(k);
  for (const [k, exp] of sessions) if (exp < now) sessions.delete(k);
}, 600e3).unref();

function clientIp(req) {
  if (TRUST_PROXY) {
    const xf = req.headers['x-forwarded-for'];
    if (xf) return String(xf).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const clean = (v, max) => (typeof v === 'string' ? v.replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, ' ').trim().slice(0, max) : '');
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const money = (kop) => (kop / 100).toFixed(2).replace('.', ',');

function isAdmin(req) {
  if (!ADMIN) return false;
  const h = req.headers['x-admin-token'];
  if (h && safeEq(h, ADMIN)) return true;
  const m = /(?:^|;\s*)ad_sess=([a-f0-9]{48})/.exec(req.headers.cookie || '') || /^Bearer ([a-f0-9]{48})$/.exec(req.headers.authorization || '');
  const exp = m && sessions.get(m[1]);
  return Boolean(exp && exp > Date.now());
}
function requireAdmin(req, res) {
  if (isAdmin(req)) return true;
  send(res, 401, { error: 'Требуется вход администратора' });
  return false;
}

function send(res, code, obj, headers) {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(JSON.stringify(obj));
}
function readJson(req, limit = 16384) {
  return new Promise((resolve, reject) => {
    if (!/^application\/json/i.test(req.headers['content-type'] || '')) return reject(Object.assign(new Error('Нужен JSON'), { status: 415 }));
    const chunks = []; let size = 0; let over = false;
    req.on('data', (d) => { size += d.length; if (size > limit) over = true; else chunks.push(d); });
    req.on('end', () => {
      if (over) return reject(Object.assign(new Error('Слишком большой запрос'), { status: 413 }));
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(Object.assign(new Error('Некорректный JSON'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}

function validateSite(b) {
  const bad = (m) => Object.assign(new Error(m), { status: 400 });
  if (!b || typeof b !== 'object') throw bad('Некорректные данные');
  const str = (v, max, min = 0, label = 'поле') => { const s = clean(v, max); if (s.length < min) throw bad('Пустое ' + label); return s; };
  const out = {
    brand: str(b.brand, 40, 1, 'название сайта'), tag: str(b.tag, 60), heroTitle: str(b.heroTitle, 80, 1, 'заголовок'),
    lead: str(b.lead, 240), footer: str(b.footer, 120),
  };
  if (!Array.isArray(b.why) || b.why.length > 8) throw bad('Блок «Почему мы» заполнен неверно');
  out.why = b.why.map((w) => ({ num: str(w && w.num, 8), title: str(w && w.title, 40, 1, 'заголовок блока'), text: str(w && w.text, 160) }));
  if (!Array.isArray(b.places) || b.places.length > 30) throw bad('Список адресов заполнен неверно');
  out.places = b.places.map((p) => ({ name: str(p && p.name, 80, 1, 'адрес'), hours: str(p && p.hours, 30) }));
  if (!Array.isArray(b.menu) || b.menu.length > 200) throw bad('Меню заполнено неверно');
  const ids = new Set();
  out.menu = b.menu.map((m) => {
    if (!m || typeof m.id !== 'string' || !/^[a-z0-9-]{1,40}$/.test(m.id) || ids.has(m.id)) throw bad('Некорректный id позиции меню');
    ids.add(m.id);
    if (!Number.isInteger(m.p) || m.p < 0 || m.p > 1000000) throw bad('Некорректная цена у позиции «' + clean(m.n, 40) + '»');
    return { id: m.id, c: str(m.c, 30, 1, 'название категории'), e: clean(m.e, 8), n: str(m.n, 60, 1, 'название позиции'), d: str(m.d, 200), p: m.p, on: m.on !== false };
  });
  return out;
}
const publicSite = () => ({ ...site, menu: site.menu.filter((m) => m.on) });

async function telegramSend(text) {
  let okCount = 0;
  await Promise.all(TG_CHATS.map(async (chat) => {
    try {
      const r = await fetch(`${TG_API}/bot${TG_TOKEN}/sendMessage`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ chat_id: chat, text, parse_mode: 'HTML', disable_web_page_preview: true }),
        signal: AbortSignal.timeout(10000),
      });
      const j = await r.json().catch(() => ({}));
      if (r.ok && j.ok) okCount++; else console.error('Telegram error', r.status, j.description || '');
    } catch (e) { console.error('Telegram request failed:', e.message); }
  }));
  return okCount;
}

async function handleOrder(req, res) {
  if (limited('o:' + clientIp(req), 5, 600e3)) return send(res, 429, { error: 'Слишком много заказов, попробуйте позже' });
  const b = await readJson(req);
  const name = clean(b.name, 60), phone = clean(b.phone, 25), address = clean(b.address, 200), comment = clean(b.comment, 300);
  if (!name) return send(res, 400, { error: 'Укажите имя' });
  if (!/^\+?[\d\s()\-]{7,20}$/.test(phone)) return send(res, 400, { error: 'Некорректный телефон' });
  if (address.length < 3) return send(res, 400, { error: 'Укажите адрес' });
  if (!Array.isArray(b.items) || b.items.length < 1 || b.items.length > 30) return send(res, 400, { error: 'Корзина пуста' });
  const byId = new Map(site.menu.filter((m) => m.on).map((m) => [m.id, m]));
  const lines = []; let total = 0; const seen = new Set();
  for (const it of b.items) {
    const m = it && byId.get(it.id);
    const qty = it && Number.isInteger(it.qty) ? it.qty : 0;
    if (!m || qty < 1 || qty > 20 || seen.has(it.id)) return send(res, 400, { error: 'Позиция недоступна, обновите страницу' });
    seen.add(it.id); total += m.p * qty;
    lines.push({ id: m.id, n: m.n, qty, sum: m.p * qty });
  }
  if (!TG_TOKEN || !TG_CHATS.length) return send(res, 503, { error: 'Приём заказов временно недоступен' });
  const orderNo = Date.now().toString(36).slice(-5).toUpperCase();
  const text = [
    `🌯 <b>Заказ №${orderNo}</b>`, `Имя: ${esc(name)}`, `Телефон: ${esc(phone)}`, `Адрес: ${esc(address)}`,
    comment ? `Комментарий: ${esc(comment)}` : null, '',
    ...lines.map((l) => `• ${esc(l.n)} × ${l.qty} = ${money(l.sum)}`), '', `<b>Итого: ${money(total)} BYN</b>`,
  ].filter((x) => x !== null).join('\n');
  const delivered = (await telegramSend(text)) > 0;
  fs.appendFileSync(ordersLog, JSON.stringify({ orderNo, ts: Date.now(), name, phone, address, comment, lines, total, delivered }) + '\n');
  if (!delivered) return send(res, 502, { error: 'Не удалось передать заказ, позвоните нам' });
  send(res, 200, { ok: true, orderNo, total });
}

async function handleReviewPost(req, res) {
  if (limited('r:' + clientIp(req), 3, 600e3)) return send(res, 429, { error: 'Слишком много отзывов, попробуйте позже' });
  const b = await readJson(req);
  const name = clean(b.name, 40), text = clean(b.text, 600), rating = b.rating;
  if (!name) return send(res, 400, { error: 'Укажите имя' });
  if (text.length < 3) return send(res, 400, { error: 'Напишите хотя бы пару слов' });
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) return send(res, 400, { error: 'Оценка от 1 до 5' });
  const r = { id: crypto.randomBytes(6).toString('hex'), name, rating, text, ts: Date.now() };
  reviews.unshift(r);
  if (reviews.length > MAX_REVIEWS) reviews.length = MAX_REVIEWS;
  writeAtomic(reviewsFile, reviews);
  send(res, 201, r);
}
function handleReviewGet(url, res) {
  const offset = Math.max(0, parseInt(url.searchParams.get('offset'), 10) || 0);
  const limit = Math.min(20, Math.max(1, parseInt(url.searchParams.get('limit'), 10) || 10));
  const avg = reviews.length ? reviews.reduce((s, r) => s + r.rating, 0) / reviews.length : 0;
  send(res, 200, { total: reviews.length, avg: Math.round(avg * 10) / 10, items: reviews.slice(offset, offset + limit) });
}
function handleReviewDelete(req, res, id) {
  if (!requireAdmin(req, res)) return;
  const i = reviews.findIndex((r) => r.id === id);
  if (i < 0) return send(res, 404, { error: 'Не найден' });
  reviews.splice(i, 1); writeAtomic(reviewsFile, reviews); send(res, 200, { ok: true });
}

async function handleLogin(req, res) {
  if (limited('l:' + clientIp(req), 5, 600e3)) return send(res, 429, { error: 'Слишком много попыток, подождите' });
  const b = await readJson(req);
  if (!ADMIN) return send(res, 403, { error: 'Админ-панель не настроена (ADMIN_TOKEN)' });
  if (typeof b.password !== 'string' || !safeEq(b.password, ADMIN)) return send(res, 403, { error: 'Неверный пароль' });
  const sid = crypto.randomBytes(24).toString('hex');
  sessions.set(sid, Date.now() + SESSION_MS);
  const secure = req.headers['x-forwarded-proto'] === 'https' && TRUST_PROXY ? '; Secure' : '';
  send(res, 200, { ok: true, token: sid }, { 'set-cookie': `ad_sess=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${secure}` });
}
function handleLogout(req, res) {
  const m = /(?:^|;\s*)ad_sess=([a-f0-9]{48})/.exec(req.headers.cookie || '') || /^Bearer ([a-f0-9]{48})$/.exec(req.headers.authorization || '');
  if (m) sessions.delete(m[1]);
  send(res, 200, { ok: true }, { 'set-cookie': 'ad_sess=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
}
async function handleSitePut(req, res) {
  if (!requireAdmin(req, res)) return;
  const cleaned = validateSite(await readJson(req, 262144));
  site = { ...cleaned, rev: site.rev + 1 };
  writeAtomic(siteFile, site);
  send(res, 200, { ok: true, rev: site.rev });
}
function handleSiteGet(req, url, res) {
  const admin = isAdmin(req);
  if (Number(url.searchParams.get('rev')) === site.rev) return send(res, 200, { unchanged: true, rev: site.rev, admin });
  send(res, 200, { ...(admin ? site : publicSite()), admin });
}

const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
function serveStatic(url, res) {
  let p;
  try { p = decodeURIComponent(url.pathname); } catch { res.writeHead(400); return res.end(); }
  if (p === '/') p = '/index.html';
  const file = path.join(PUB, p);
  if (!file.startsWith(PUB + path.sep)) { res.writeHead(404); return res.end(); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }); return res.end('Not found'); }
    res.writeHead(200, { 'content-type': types[path.extname(file)] || 'application/octet-stream', 'x-content-type-options': 'nosniff', 'cache-control': 'no-cache' });
    res.end(buf);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname, m = req.method;
    const origin = req.headers.origin;
    if (origin && ORIGINS.includes(origin)) {
      res.setHeader('access-control-allow-origin', origin);
      res.setHeader('vary', 'Origin');
      res.setHeader('access-control-allow-headers', 'content-type, authorization');
      res.setHeader('access-control-allow-methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader('access-control-max-age', '600');
    }
    if (m === 'OPTIONS') { res.writeHead(204); return res.end(); }
    if (p === '/api/site' && m === 'GET') return handleSiteGet(req, url, res);
    if (p === '/api/site' && m === 'PUT') return await handleSitePut(req, res);
    if (p === '/api/admin/login' && m === 'POST') return await handleLogin(req, res);
    if (p === '/api/admin/logout' && m === 'POST') return handleLogout(req, res);
    if (p === '/api/reviews' && m === 'GET') return handleReviewGet(url, res);
    if (p === '/api/reviews' && m === 'POST') return await handleReviewPost(req, res);
    if (p.startsWith('/api/reviews/') && m === 'DELETE') return handleReviewDelete(req, res, p.slice(13));
    if (p === '/api/order' && m === 'POST') return await handleOrder(req, res);
    if (p.startsWith('/api/')) return send(res, 404, { error: 'Not found' });
    if (m !== 'GET' && m !== 'HEAD') { res.writeHead(405); return res.end(); }
    serveStatic(url, res);
  } catch (e) {
    if (!res.headersSent) send(res, e.status || 500, { error: e.status ? e.message : 'Ошибка сервера' });
    if (!e.status) console.error(e);
  }
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`Ander Doner: http://localhost:${PORT}`);
    if (!TG_TOKEN || !TG_CHATS.length) console.warn('ВНИМАНИЕ: TG_BOT_TOKEN/TG_CHAT_ID не заданы, заказы принимаются не будут.');
    if (!ADMIN) console.warn('ВНИМАНИЕ: ADMIN_TOKEN не задан, админ-панель отключена.');
  });
}
module.exports = server;
