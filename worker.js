// VLESS over WebSocket - Cloudflare Worker (v12: + per-user expiry/quota, QR codes, multi-source clean-IP status)
// - KV-stored config, multi-UUID, subscription, admin panel (advanced UI)
// - Automatic ProxyIP: direct first, then relay candidates resolved via DoH (TXT/A/AAAA)
// - UDP DNS over DoH, Blob-safe WebSocket frames
//
// Bindings / variables:
//   KV        (KV namespace binding, required)
//   ADMIN     (variable/secret, required)  -> password for /admin
//   PROXY_IP  (optional)                   -> extra relay entries (comma/newline separated)
//
// Routes:
//   /admin        -> admin panel
//   /sub/<token>  -> base64 subscription (all users x all addresses)

import { connect } from 'cloudflare:sockets';

const CONFIG_KEY = 'config';
const CACHE_TTL = 60 * 1000;
const MAX_USERS = 20;
const MAX_LIST = 50;
const BYTES_PER_GB = 1024 * 1024 * 1024;
const MAX_QUOTA_GB = 100000;

const DEFAULT_AUTO_DOMAIN = 'proxyip.cmliussss.net'; // same source edgetunnel uses (per-colo: <colo>.<domain>)
const DOH = 'https://cloudflare-dns.com/dns-query';
const DEFAULT_CLEAN_IP_URLS = [
  'https://addressesapi.090227.xyz/CloudFlareYes',
  'https://ip.164746.xyz/ipTop10.html',
];
const CLEAN_IP_TIMEOUT = 4000;
const CLEAN_IP_CACHE_TTL = 10 * 60 * 1000;
const MAX_CLEAN_IP_URLS = 6;
const GEOIP_URL = 'http://ip-api.com/batch?fields=query,countryCode,status';
const GEOIP_BATCH_MAX = 100;
const GEOIP_TIMEOUT = 4000;
const GEOIP_CACHE_TTL = 24 * 60 * 60 * 1000;
const MAX_COUNTRIES = 10;
const MAX_AUTO_ADDRS = 10;
const DIRECT_TIMEOUT = 3000;
const PROXY_TIMEOUT = 4000;
const MAX_PROXY_TRIES = 4;
const PROXY_CACHE_TTL = 5 * 60 * 1000;
const DIRECT_FAIL_TTL = 5 * 60 * 1000;

let cache = { value: null, at: 0 };

export default {
  async fetch(request, env, ctx) {
    try {
      if (!env.KV) {
        return new Response('KV binding named "KV" is not set', { status: 500 });
      }

      if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
        const cfg = await getConfig(env);
        return handleWebSocket(request, env, cfg, ctx);
      }

      const url = new URL(request.url);

      if (url.pathname.startsWith('/sub/')) {
        return await handleSub(request, env, url);
      }
      if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) {
        return await handleAdmin(request, env, url);
      }

      return new Response('OK', { status: 200 });
    } catch (err) {
      return new Response('Error: ' + (err && err.message ? err.message : err), { status: 500 });
    }
  },
};

/* ================================ Config (KV) ================================ */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ENTRY_RE = /^(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.\-]+)(:\d{1,5})?$/;
const DOMAIN_RE = /^[a-zA-Z0-9][a-zA-Z0-9.\-]{1,251}[a-zA-Z0-9]$/;
const URL_RE = /^https:\/\/[a-zA-Z0-9][a-zA-Z0-9.\-]{1,251}[a-zA-Z0-9](?::\d{1,5})?(?:\/[^\s]*)?$/;
const COUNTRY_RE = /^[A-Z]{2}$/;

function randomToken() {
  const b = crypto.getRandomValues(new Uint8Array(24));
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

async function getConfig(env, force = false) {
  if (!force && cache.value && Date.now() - cache.at < CACHE_TTL) return cache.value;

  let cfg = null;
  try {
    cfg = await env.KV.get(CONFIG_KEY, 'json');
  } catch (_) {}

  let dirty = false;
  if (!cfg || typeof cfg !== 'object') { cfg = {}; dirty = true; }

  // Migrate from v1 ({ uuid })
  if (!Array.isArray(cfg.users)) {
    cfg.users = [];
    if (UUID_RE.test(cfg.uuid || '')) cfg.users.push({ uuid: cfg.uuid.toLowerCase(), name: 'default' });
    delete cfg.uuid;
    dirty = true;
  }
  if (!cfg.users.length) { cfg.users.push({ uuid: crypto.randomUUID(), name: 'default' }); dirty = true; }
  for (const u of cfg.users) {
    if (u.expiresAt !== null && !Number.isFinite(u.expiresAt)) { u.expiresAt = null; dirty = true; }
    if (u.quotaBytes !== null && !Number.isFinite(u.quotaBytes)) { u.quotaBytes = null; dirty = true; }
    if (!Number.isFinite(u.usedBytes)) { u.usedBytes = 0; dirty = true; }
  }
  if (!cfg.subToken) { cfg.subToken = randomToken(); dirty = true; }

  // Migrate from v2-v4 ({ proxyIp })
  if (!cfg.proxyMode) {
    if (typeof cfg.proxyIp === 'string' && cfg.proxyIp.trim()) {
      cfg.proxyMode = 'custom';
      cfg.proxyList = cfg.proxyIp.trim();
    } else {
      cfg.proxyMode = 'auto';
    }
    delete cfg.proxyIp;
    dirty = true;
  }
  if (typeof cfg.proxyList !== 'string') { cfg.proxyList = ''; dirty = true; }
  if (!cfg.autoDomain) { cfg.autoDomain = DEFAULT_AUTO_DOMAIN; dirty = true; }
  if (typeof cfg.autoPerColo !== 'boolean') { cfg.autoPerColo = true; dirty = true; }
  if (typeof cfg.addrs !== 'string') { cfg.addrs = ''; dirty = true; }
  if (typeof cfg.cleanIpEnabled !== 'boolean') { cfg.cleanIpEnabled = false; dirty = true; }
  if (typeof cfg.cleanIpUrls !== 'string') { cfg.cleanIpUrls = DEFAULT_CLEAN_IP_URLS.join('\n'); dirty = true; }
  if (typeof cfg.countryFilter !== 'string') { cfg.countryFilter = ''; dirty = true; }
  if (cfg.addrMode !== 'auto' && cfg.addrMode !== 'manual') { cfg.addrMode = 'manual'; dirty = true; }
  if (!Number.isInteger(cfg.addrCount) || cfg.addrCount < 1 || cfg.addrCount > MAX_AUTO_ADDRS) { cfg.addrCount = 3; dirty = true; }

  if (dirty) await env.KV.put(CONFIG_KEY, JSON.stringify(cfg));
  cache = { value: cfg, at: Date.now() };
  return cfg;
}

async function saveConfig(env, cfg) {
  await env.KV.put(CONFIG_KEY, JSON.stringify(cfg));
  cache = { value: cfg, at: Date.now() };
}

function splitList(text) {
  return String(text || '').split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean);
}

function cleanList(text, max) {
  const items = splitList(text);
  if (items.length > max) throw new Error(`حداکثر ${max} مورد مجاز است`);
  for (const it of items) if (!ENTRY_RE.test(it)) throw new Error('مقدار نامعتبر: ' + it);
  return items;
}

function cleanUrlList(text, max) {
  const items = splitList(text);
  if (items.length > max) throw new Error(`حداکثر ${max} آدرس مجاز است`);
  for (const it of items) if (!URL_RE.test(it)) throw new Error('آدرس نامعتبر (باید با https شروع شود): ' + it);
  return items;
}

function parseCountryList(text, max) {
  const items = String(text || '')
    .split(/[\s,;]+/)
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);
  const uniq = [...new Set(items)];
  if (uniq.length > max) throw new Error(`حداکثر ${max} کد کشور مجاز است`);
  for (const c of uniq) if (!COUNTRY_RE.test(c)) throw new Error('کد کشور نامعتبر (باید دو حرفی باشد): ' + c);
  return uniq;
}

function dedupeAddrs(list) {
  const seen = new Set();
  const out = [];
  for (const [a, p] of list) {
    const k = a + ':' + p;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push([a, p]);
  }
  return out;
}

// Address(es) the CLIENT connects to (goes into the vless:// link as host:port), as opposed
// to the ProxyIP relay the Worker itself uses to reach blocked destinations. In 'auto' mode
// this reuses the same public clean-IP sources and country filter as the ProxyIP tab, since
// both need the same kind of thing: a currently-reachable Cloudflare edge IP.
async function getConnectAddrs(cfg, host) {
  const manual = splitList(cfg.addrs).map((s) => {
    const [a, p] = splitHostPort(s);
    return [a, p || 443];
  });

  if (cfg.addrMode !== 'auto') return manual.length ? manual : [[host, 443]];

  let auto = [];
  try {
    const urls = splitList(cfg.cleanIpUrls);
    const raw = await fetchCleanIps(urls.length ? urls : DEFAULT_CLEAN_IP_URLS);
    let countries = [];
    try { countries = parseCountryList(cfg.countryFilter, MAX_COUNTRIES); } catch (_) {}
    const filtered = countries.length ? await filterByCountry(raw, countries).catch(() => raw) : raw;
    auto = filtered.slice(0, cfg.addrCount).map(([ip, port]) => [ip, port || 443]);
  } catch (_) {}

  const combined = dedupeAddrs([...manual, ...auto]);
  return combined.length ? combined : [[host, 443]];
}

function vlessLink(u, host, addr, port) {
  const label = encodeURIComponent(addr === host ? u.name : `${u.name}-${addr}`);
  return (
    `vless://${u.uuid}@${addr}:${port}?encryption=none&security=tls&sni=${host}` +
    `&fp=chrome&type=ws&host=${host}&path=%2F%3Fed%3D2048#${label}`
  );
}

/* ============================== Subscription =============================== */

async function handleSub(request, env, url) {
  const cfg = await getConfig(env);
  const token = url.pathname.slice('/sub/'.length);
  if (!safeEqual(token, cfg.subToken)) return new Response('Not found', { status: 404 });

  const addrs = await getConnectAddrs(cfg, url.host);
  const lines = [];
  for (const u of cfg.users) for (const [a, p] of addrs) lines.push(vlessLink(u, url.host, a, p));
  return new Response(btoa(lines.join('\n')), {
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

/* ============================ Proxy IP resolution ============================ */

const proxyCache = new Map(); // key -> { list, at }
const directFail = new Map(); // host -> expiresAt

function splitHostPort(s) {
  s = String(s).trim();
  let m = s.match(/^(\[[^\]]+\])(?::(\d+))?$/);
  if (m) return [m[1], m[2] ? parseInt(m[2], 10) : null];
  m = s.match(/^([^:]+)(?::(\d+))?$/);
  if (m) return [m[1], m[2] ? parseInt(m[2], 10) : null];
  return [s, null];
}

function isIpLiteral(a) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(a) || a.startsWith('[');
}

function buildProxyEntries(cfg, env, colo) {
  if (cfg.proxyMode === 'off') return [];
  const out = [...splitList(cfg.proxyList)];
  if (env.PROXY_IP) out.push(...splitList(env.PROXY_IP));
  if (cfg.proxyMode === 'auto') {
    const d = cfg.autoDomain || DEFAULT_AUTO_DOMAIN;
    if (cfg.autoPerColo && colo) out.push(`${String(colo).toLowerCase()}.${d}`);
    out.push(d);
  }
  return [...new Set(out)];
}

async function doh(name, type) {
  const r = await fetch(`${DOH}?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { accept: 'application/dns-json' },
    signal: AbortSignal.timeout(3000),
  });
  if (!r.ok) return [];
  const j = await r.json();
  return Array.isArray(j.Answer) ? j.Answer : [];
}

function parseTxt(data) {
  return String(data)
    .replace(/"/g, ' ')
    .replace(/\\010/g, ',')
    .split(/[\s,]+/)
    .filter(Boolean);
}

function shuffle(a) {
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// entry -> [[addr, port|null], ...]
async function resolveEntry(entry) {
  const [addr, port] = splitHostPort(entry);
  if (isIpLiteral(addr)) return [[addr, port]];

  const [txt, a] = await Promise.all([doh(addr, 'TXT').catch(() => []), doh(addr, 'A').catch(() => [])]);

  const out = [];
  for (const r of txt) {
    if (r.type !== 16) continue;
    for (const s of parseTxt(r.data)) out.push(splitHostPort(s));
  }
  if (out.length) return shuffle(out);

  for (const r of a) if (r.type === 1) out.push([r.data, port]);
  if (out.length) return shuffle(out);

  const aaaa = await doh(addr, 'AAAA').catch(() => []);
  for (const r of aaaa) if (r.type === 28) out.push([`[${r.data}]`, port]);
  return shuffle(out);
}

// Pull IPv4 (optionally :port) tokens out of whatever a public "clean IP" source
// returns (plain text, HTML, JSON, CSV) - format varies by source and changes over time,
// so this stays deliberately forgiving rather than parsing a specific schema.
function extractIps(text, defaultPort, max) {
  const re = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d{1,5}))?/g;
  const seen = new Set();
  const out = [];
  let m;
  while ((m = re.exec(text)) && out.length < max) {
    if ([m[1], m[2], m[3], m[4]].some((o) => Number(o) > 255)) continue;
    const ip = `${m[1]}.${m[2]}.${m[3]}.${m[4]}`;
    if (seen.has(ip)) continue;
    seen.add(ip);
    const port = m[5] ? parseInt(m[5], 10) : defaultPort;
    out.push([ip, port > 0 && port < 65536 ? port : defaultPort]);
  }
  return out;
}

const cleanIpCache = new Map(); // urls-key -> { list, at }
const sourceStats = new Map(); // url -> { ok, count, ms, error, at } (last fetch attempt, per isolate)

function recordSourceStat(url, stat) {
  if (sourceStats.size > 50) sourceStats.clear();
  sourceStats.set(url, { ...stat, at: Date.now() });
}

// Forces a fresh fetch of every configured source and reports how each one did.
async function checkCleanSources(urls) {
  const list = await fetchCleanIps(urls, true);
  return {
    total: list.length,
    sources: urls.map((u) => ({ url: u, ...(sourceStats.get(u) || { ok: false, count: 0, ms: 0, error: 'بدون نتیجه' }) })),
  };
}

// Fetches the admin's configured public "clean IP" list URLs and extracts candidate
// IPs from each. These are third-party lists outside our control, so every fetch is
// timeboxed and a failing/unreachable source is skipped rather than failing the batch.
async function fetchCleanIps(urls, force = false) {
  if (!urls.length) return [];
  const key = urls.join('|');
  const c = cleanIpCache.get(key);
  if (!force && c && Date.now() - c.at < CLEAN_IP_CACHE_TTL) return c.list;

  const results = await Promise.allSettled(
    urls.map(async (u) => {
      const t0 = Date.now();
      try {
        const r = await fetch(u, { signal: AbortSignal.timeout(CLEAN_IP_TIMEOUT), headers: { accept: 'text/plain,*/*' } });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const text = await r.text();
        const found = extractIps(text, 443, 30);
        recordSourceStat(u, { ok: found.length > 0, count: found.length, ms: Date.now() - t0, error: found.length ? '' : 'هیچ آی‌پی‌ای در پاسخ پیدا نشد' });
        return found;
      } catch (e) {
        recordSourceStat(u, { ok: false, count: 0, ms: Date.now() - t0, error: String((e && e.message) || e).slice(0, 80) });
        throw e;
      }
    })
  );

  const seen = new Set();
  const list = [];
  for (const r of results) {
    if (r.status !== 'fulfilled') continue;
    for (const [ip, port] of r.value) {
      const k = ip + ':' + port;
      if (seen.has(k)) continue;
      seen.add(k);
      list.push([ip, port]);
    }
  }
  if (cleanIpCache.size > 20) cleanIpCache.clear();
  cleanIpCache.set(key, { list, at: list.length ? Date.now() : Date.now() - CLEAN_IP_CACHE_TTL + 30 * 1000 });
  return list;
}

const geoCache = new Map(); // ip -> { cc, at }

function stripBrackets(ip) {
  return ip.startsWith('[') && ip.endsWith(']') ? ip.slice(1, -1) : ip;
}

// Looks up the country of each IP via ip-api.com's free batch endpoint (no key, ~45 req/min,
// up to 100 IPs per call) and caches results for a day. Best-effort: an IP whose country
// could not be determined (lookup failed, rate-limited, IP reserved, etc.) is treated as
// non-matching rather than blocking the whole batch.
async function lookupCountries(ips) {
  const now = Date.now();
  const need = ips.filter((ip) => {
    const c = geoCache.get(ip);
    return !c || now - c.at >= GEOIP_CACHE_TTL;
  });

  for (let i = 0; i < need.length; i += GEOIP_BATCH_MAX) {
    const batch = need.slice(i, i + GEOIP_BATCH_MAX);
    try {
      const r = await fetch(GEOIP_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(batch.map(stripBrackets)),
        signal: AbortSignal.timeout(GEOIP_TIMEOUT),
      });
      if (!r.ok) continue;
      const rows = await r.json();
      if (!Array.isArray(rows)) continue;
      rows.forEach((row, idx) => {
        const ip = batch[idx];
        const cc = row && row.status === 'success' && row.countryCode ? row.countryCode : null;
        geoCache.set(ip, { cc, at: now });
      });
    } catch (_) {
      // leave these IPs unresolved for this call; they'll be treated as non-matching below
    }
  }
  if (geoCache.size > 5000) geoCache.clear();
}

async function filterByCountry(list, countries) {
  if (!countries.length) return list;
  const ips = [...new Set(list.map(([ip]) => ip))];
  await lookupCountries(ips);
  return list.filter(([ip]) => {
    const c = geoCache.get(ip);
    return c && c.cc && countries.includes(c.cc);
  });
}

async function getProxies(cfg, env, colo, force = false) {
  const entries = buildProxyEntries(cfg, env, colo);
  const cleanUrls = cfg.proxyMode !== 'off' && cfg.cleanIpEnabled ? splitList(cfg.cleanIpUrls) : [];
  let countries = [];
  if (cfg.proxyMode !== 'off') {
    try { countries = parseCountryList(cfg.countryFilter, MAX_COUNTRIES); } catch (_) {}
  }
  if (!entries.length && !cleanUrls.length) return { entries, cleanUrls, countries, list: [] };

  const key = entries.join('|') + '||' + cleanUrls.join('|') + '||' + countries.join(',');
  const c = proxyCache.get(key);
  if (!force && c && Date.now() - c.at < PROXY_CACHE_TTL) return { entries, cleanUrls, countries, list: c.list };

  const [groups, cleanList] = await Promise.all([
    Promise.all(entries.map((e) => resolveEntry(e).catch(() => []))),
    cleanUrls.length ? fetchCleanIps(cleanUrls, force).catch(() => []) : Promise.resolve([]),
  ]);

  const seen = new Set();
  const raw = [];
  const push = (a, p) => {
    const k = `${a}:${p || ''}`;
    if (seen.has(k)) return;
    seen.add(k);
    raw.push([a, p]);
  };
  for (const g of groups) for (const [a, p] of g) push(a, p);
  for (const [a, p] of cleanList) push(a, p);

  const list = countries.length ? await filterByCountry(raw, countries).catch(() => raw) : raw;

  if (proxyCache.size > 50) proxyCache.clear();
  // Empty results are re-tried after 30s instead of the full TTL
  proxyCache.set(key, { list, at: list.length ? Date.now() : Date.now() - PROXY_CACHE_TTL + 30 * 1000 });
  return { entries, cleanUrls, countries, list };
}

function isDirectBlocked(host) {
  const t = directFail.get(host);
  if (!t) return false;
  if (t < Date.now()) { directFail.delete(host); return false; }
  return true;
}

function markDirectFail(host) {
  if (directFail.size > 2000) directFail.clear();
  directFail.set(host, Date.now() + DIRECT_FAIL_TTL);
}

function withTimeout(p, ms, msg = 'timeout') {
  let t;
  return Promise.race([
    p,
    new Promise((_, rej) => { t = setTimeout(() => rej(new Error(msg)), ms); }),
  ]).finally(() => clearTimeout(t));
}

/* ================================ Admin panel ================================ */

const SEC_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy':
    "default-src 'none'; script-src 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
};

function html(body, status = 200) {
  return new Response(body, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', ...SEC_HEADERS } });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

async function handleAdmin(request, env, url) {
  if (!env.ADMIN) return new Response('ADMIN variable is not set', { status: 500 });

  const token = await sha256(String(env.ADMIN));
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const authed = safeEqual(cookies.auth || '', token);
  const path = url.pathname;

  if (request.method === 'POST' && path === '/admin/login') {
    const form = await request.formData();
    const pass = String(form.get('password') || '');
    if (safeEqual(await sha256(pass), token)) {
      return new Response(null, {
        status: 302,
        headers: {
          Location: '/admin',
          'Set-Cookie': `auth=${token}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`,
        },
      });
    }
    await new Promise((r) => setTimeout(r, 600));
    return html(loginPage('رمز اشتباه است'), 401);
  }

  if (path.startsWith('/admin/api/')) {
    if (!authed) return json({ error: 'unauthorized' }, 401);
    return await handleApi(request, env, url, path.slice('/admin/api/'.length));
  }

  if (!authed) return html(loginPage(''));
  return html(panelPage());
}

async function handleApi(request, env, url, action) {
  const colo = (request.cf && request.cf.colo) || '';

  if (request.method === 'GET' && action === 'state') {
    return json(await publicState(await getConfig(env, true), url, colo));
  }
  if (request.method !== 'POST') return json({ error: 'method not allowed' }, 405);

  // CSRF hardening (cookie is SameSite=Strict as well)
  const origin = request.headers.get('Origin');
  if (origin && origin !== url.origin) return json({ error: 'forbidden origin' }, 403);
  if (!(request.headers.get('content-type') || '').includes('application/json')) {
    return json({ error: 'content-type must be application/json' }, 415);
  }

  let body = {};
  try { body = await request.json(); } catch (_) {}
  if (!body || typeof body !== 'object') body = {};

  if (action === 'logout') {
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': 'auth=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
      },
    });
  }

  const cfg = await getConfig(env, true);

  try {
    switch (action) {
      case 'user/add': {
        if (cfg.users.length >= MAX_USERS) throw new Error(`حداکثر ${MAX_USERS} کاربر`);
        const name = String(body.name || '').trim().slice(0, 32) || 'user';
        cfg.users.push({ uuid: crypto.randomUUID(), name });
        break;
      }
      case 'user/delete': {
        if (cfg.users.length <= 1) throw new Error('حداقل یک کاربر لازم است');
        const uuid = String(body.uuid || '').toLowerCase();
        cfg.users = cfg.users.filter((u) => u.uuid !== uuid);
        break;
      }
      case 'user/rename': {
        const uuid = String(body.uuid || '').toLowerCase();
        const name = String(body.name || '').trim().slice(0, 32);
        if (!name) throw new Error('نام خالی است');
        const u = cfg.users.find((x) => x.uuid === uuid);
        if (!u) throw new Error('کاربر پیدا نشد');
        u.name = name;
        break;
      }
      case 'user/set-limits': {
        const uuid = String(body.uuid || '').toLowerCase();
        const u = cfg.users.find((x) => x.uuid === uuid);
        if (!u) throw new Error('کاربر پیدا نشد');

        const dateStr = String(body.expiresAt || '').trim();
        if (!dateStr) {
          u.expiresAt = null;
        } else {
          const t = Date.parse(dateStr + 'T23:59:59');
          if (!Number.isFinite(t)) throw new Error('تاریخ نامعتبر است');
          u.expiresAt = t;
        }

        const gbStr = String(body.quotaGB || '').trim();
        if (!gbStr) {
          u.quotaBytes = null;
        } else {
          const gb = Number(gbStr);
          if (!Number.isFinite(gb) || gb <= 0 || gb > MAX_QUOTA_GB) throw new Error('حجم نامعتبر است');
          u.quotaBytes = Math.round(gb * BYTES_PER_GB);
        }
        break;
      }
      case 'user/reset-usage': {
        const uuid = String(body.uuid || '').toLowerCase();
        const u = cfg.users.find((x) => x.uuid === uuid);
        if (!u) throw new Error('کاربر پیدا نشد');
        u.usedBytes = 0;
        break;
      }
      case 'proxy/save': {
        const mode = String(body.proxyMode || '');
        if (!['auto', 'custom', 'off'].includes(mode)) throw new Error('حالت نامعتبر');
        const domain = String(body.autoDomain || DEFAULT_AUTO_DOMAIN).trim().toLowerCase();
        if (!DOMAIN_RE.test(domain)) throw new Error('دامنه‌ی منبع خودکار نامعتبر است');
        cfg.proxyMode = mode;
        cfg.proxyList = cleanList(body.proxyList, MAX_LIST).join('\n');
        cfg.autoDomain = domain;
        cfg.autoPerColo = !!body.autoPerColo;
        cfg.cleanIpEnabled = !!body.cleanIpEnabled;
        cfg.cleanIpUrls = cleanUrlList(body.cleanIpUrls, MAX_CLEAN_IP_URLS).join('\n');
        cfg.countryFilter = parseCountryList(body.countryFilter, MAX_COUNTRIES).join(',');
        break;
      }
      case 'addr/save': {
        cfg.addrs = cleanList(body.addrs, 20).join('\n');
        const mode = String(body.addrMode || '');
        if (!['manual', 'auto'].includes(mode)) throw new Error('حالت نامعتبر');
        const count = parseInt(body.addrCount, 10);
        if (!Number.isInteger(count) || count < 1 || count > MAX_AUTO_ADDRS) {
          throw new Error(`تعداد باید بین ۱ تا ${MAX_AUTO_ADDRS} باشد`);
        }
        cfg.addrMode = mode;
        cfg.addrCount = count;
        break;
      }
      case 'sub/regen': {
        cfg.subToken = randomToken();
        break;
      }
      case 'test': {
        const host = String(body.host || 'chatgpt.com').trim().toLowerCase();
        if (!/^[a-z0-9][a-z0-9.\-]{0,251}[a-z0-9]$/.test(host)) throw new Error('آدرس سایت نامعتبر است');
        return json(await runTest(cfg, env, colo, host));
      }
      case 'sources/check': {
        const urls = splitList(cfg.cleanIpUrls);
        if (!urls.length) throw new Error('هیچ آدرس منبعی تنظیم نشده است');
        return json(await checkCleanSources(urls));
      }
      default:
        return json({ error: 'not found' }, 404);
    }
  } catch (e) {
    return json({ error: e && e.message ? e.message : String(e) }, 400);
  }

  await saveConfig(env, cfg);
  return json({ ok: true, state: await publicState(cfg, url, colo) });
}

async function publicState(cfg, url, colo) {
  const host = url.host;
  const addrs = await getConnectAddrs(cfg, host);
  return {
    host,
    colo,
    maxUsers: MAX_USERS,
    subUrl: `https://${host}/sub/${cfg.subToken}`,
    proxyMode: cfg.proxyMode,
    proxyList: cfg.proxyList,
    autoDomain: cfg.autoDomain,
    autoDomainDefault: DEFAULT_AUTO_DOMAIN,
    autoPerColo: cfg.autoPerColo,
    cleanIpEnabled: cfg.cleanIpEnabled,
    cleanIpUrls: cfg.cleanIpUrls,
    cleanIpUrlsDefault: DEFAULT_CLEAN_IP_URLS.join('\n'),
    maxCleanIpUrls: MAX_CLEAN_IP_URLS,
    countryFilter: cfg.countryFilter,
    maxCountries: MAX_COUNTRIES,
    addrs: cfg.addrs,
    addrMode: cfg.addrMode,
    addrCount: cfg.addrCount,
    maxAutoAddrs: MAX_AUTO_ADDRS,
    users: cfg.users.map((u) => ({
      uuid: u.uuid,
      name: u.name,
      expiresAt: u.expiresAt || null,
      quotaBytes: u.quotaBytes || null,
      usedBytes: u.usedBytes || 0,
      status: checkUserStatus(u),
      links: addrs.map(([a, p]) => ({ label: a === host ? 'پیش‌فرض' : a, url: vlessLink(u, host, a, p) })),
    })),
  };
}

/* ---------------------------- Connectivity test tool ---------------------------- */

// Connects to addr:port, does TLS with SNI = host, sends a GET and checks for an HTTP response.
async function httpProbe(addr, port, host) {
  const t0 = Date.now();
  let sock;
  try {
    sock = connect({ hostname: addr, port }, { secureTransport: 'starttls' });
    await withTimeout(sock.opened, 3000, 'connect timeout');
    const tls = sock.startTls({ expectedServerHostname: host });
    const w = tls.writable.getWriter();
    const req = `GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
    await withTimeout(w.write(new TextEncoder().encode(req)), 4000, 'write timeout');
    const r = tls.readable.getReader();
    const { value } = await withTimeout(r.read(), 4000, 'no response');
    const head = new TextDecoder().decode(value || new Uint8Array(0)).split('\r\n')[0];
    return { ok: /^HTTP\/\d/.test(head), status: head.slice(0, 40), ms: Date.now() - t0 };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e).slice(0, 120), ms: Date.now() - t0 };
  } finally {
    try { sock && sock.close(); } catch (_) {}
  }
}

async function runTest(cfg, env, colo, host) {
  const { entries, countries, list } = await getProxies(cfg, env, colo, true);
  const [direct, ...cands] = await Promise.all([
    httpProbe(host, 443, host),
    ...list.slice(0, 6).map(([a, p]) =>
      httpProbe(a, p || 443, host).then((r) => ({ addr: a, port: p || 443, cc: (geoCache.get(a) || {}).cc || null, ...r }))
    ),
  ]);
  return { host, colo, entries, countries, resolved: list.length, direct, candidates: cands };
}

/* ---------------------------------- Pages ---------------------------------- */

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const STYLE = `
:root{
  --canvas:#eef0f4;--canvas-2:#e6e9ee;--surface:#ffffff;--ink:#151b26;--muted:#66707d;--line:#dde1e7;
  --accent:#0d7d6f;--accent-2:#0a5f9e;--accent-ink:#ffffff;--soft:#e2f3ef;
  --ok:#1a8354;--bad:#c23b34;--warn:#b3790c;
  --mono:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;
  --sans:Vazirmatn,IRANSans,"Segoe UI",Tahoma,Arial,sans-serif;
  --r-lg:16px;--r-md:10px;--r-sm:7px;
}
@media (prefers-color-scheme:dark){:root{
  --canvas:#0c1417;--canvas-2:#0a1114;--surface:#151f24;--ink:#e9eef1;--muted:#93a1ab;--line:#25333a;
  --accent:#3fc2ad;--accent-2:#5ab6e8;--accent-ink:#04211c;--soft:#132a27;
  --ok:#5fd39a;--bad:#f0847c;--warn:#e3ac53;
}}
*{box-sizing:border-box}
body{margin:0;background:linear-gradient(180deg,var(--canvas-2),var(--canvas) 140px);color:var(--ink);font-family:var(--sans);font-size:15px;line-height:1.7;-webkit-font-smoothing:antialiased}
.wrap{max-width:860px;margin:0 auto;padding:18px 16px 40px}
header.top{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:6px 0 18px}
header.top h1{font-size:19px;margin:0;font-weight:800;letter-spacing:-.01em;display:flex;align-items:center;gap:8px}
header.top h1::before{content:"";width:9px;height:9px;border-radius:50%;background:linear-gradient(135deg,var(--accent),var(--accent-2));display:inline-block;box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 18%,transparent)}
.tabs{display:flex;gap:4px;overflow-x:auto;margin-bottom:18px;padding:4px;background:var(--surface);border:1px solid var(--line);border-radius:999px;box-shadow:0 1px 2px rgba(0,0,0,.03)}
.tab{background:none;border:0;color:var(--muted);padding:8px 15px;cursor:pointer;font:inherit;font-size:13.5px;border-radius:999px;white-space:nowrap;transition:background .15s,color .15s}
.tab.on{color:var(--accent-ink);background:linear-gradient(135deg,var(--accent),var(--accent-2));font-weight:700}
.tab:not(.on):hover{background:var(--soft);color:var(--ink)}
.tab:focus-visible,.btn:focus-visible,input:focus-visible,textarea:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r-lg);padding:18px;margin-bottom:14px;box-shadow:0 1px 2px rgba(15,23,32,.04),0 6px 20px -8px rgba(15,23,32,.08)}
.card h3{margin:0 0 12px;font-size:16px;font-weight:700;letter-spacing:-.01em}
.card h4{margin:16px 0 6px;font-size:13.5px;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.03em}
.route{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.node{background:var(--surface);border:1px solid var(--line);border-radius:var(--r-md);padding:8px 13px;min-width:92px}
.node small{display:block;color:var(--muted);font-size:11.5px}
.node.hot{border-color:var(--accent);background:var(--soft);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 12%,transparent)}
.arrow{color:var(--muted);font-size:13px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.stat{background:var(--surface);border:1px solid var(--line);border-inline-start:3px solid var(--accent);border-radius:var(--r-md);padding:11px 14px}
.stat span{display:block;color:var(--muted);font-size:12.5px}
.stat b{font-size:17px;word-break:break-all;font-weight:700}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11.5px;font-weight:700}
.badge.ok{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}
.badge.warn{background:color-mix(in srgb,var(--warn) 16%,transparent);color:var(--warn)}
.badge.bad{background:color-mix(in srgb,var(--bad) 16%,transparent);color:var(--bad)}
.bar{background:var(--canvas);border:1px solid var(--line);border-radius:6px;overflow:hidden;height:7px;margin:6px 0}
.bar > div{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent-2))}
.bar.bad > div{background:var(--bad)}
input[type=text],input:not([type]),textarea{width:100%;background:var(--canvas);color:var(--ink);border:1px solid var(--line);border-radius:var(--r-sm);padding:10px 11px;font:inherit;margin:4px 0 10px;transition:border-color .15s}
input:hover,textarea:hover{border-color:color-mix(in srgb,var(--accent) 40%,var(--line))}
textarea{font-family:var(--mono);font-size:13px;direction:ltr;resize:vertical}
.ltr{direction:ltr;text-align:left;font-family:var(--mono);font-size:13px}
input.ltr{font-family:var(--mono)}
.field{display:inline-block;min-width:150px;margin-inline-end:8px;vertical-align:top}
.field label{display:block;font-size:11.5px;color:var(--muted);margin-bottom:2px}
.field input{margin:0}
code.blk{display:block;background:var(--canvas);border:1px solid var(--line);border-radius:var(--r-sm);padding:9px 11px;margin:6px 0;word-break:break-all;direction:ltr;text-align:left;font-family:var(--mono);font-size:12.5px}
.btn{background:linear-gradient(135deg,var(--accent),var(--accent-2));color:var(--accent-ink);border:0;border-radius:var(--r-sm);padding:9px 16px;cursor:pointer;font:inherit;font-weight:600;transition:filter .12s,transform .05s,box-shadow .15s;box-shadow:0 1px 2px rgba(0,0,0,.08)}
.btn:hover{filter:brightness(1.07);box-shadow:0 4px 12px -4px color-mix(in srgb,var(--accent) 50%,transparent)}
.btn:active{transform:translateY(1px)}
.btn.sm{padding:5px 11px;font-size:13px}
.btn.ghost{background:transparent;color:var(--ink);border:1px solid var(--line);box-shadow:none;font-weight:500}
.btn.ghost:hover{background:var(--soft);filter:none;box-shadow:none}
.btn.danger{background:transparent;color:var(--bad);border:1px solid var(--bad);box-shadow:none;font-weight:500}
.btn.danger:hover{background:color-mix(in srgb,var(--bad) 10%,transparent);filter:none;box-shadow:none}
.btn[disabled]{opacity:.55;cursor:wait;box-shadow:none}
.row{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}
.opt{display:flex;gap:10px;align-items:flex-start;padding:9px 0;cursor:pointer}
.opt input{margin-top:6px}
.note{color:var(--muted);font-size:13px;margin:8px 0 0}
.warn{border-inline-start:3px solid var(--warn);padding-inline-start:10px;color:var(--ink);background:color-mix(in srgb,var(--warn) 6%,transparent);border-radius:0 var(--r-sm) var(--r-sm) 0;padding:8px 10px}
.qrbox{background:#fff;border:1px solid var(--line);border-radius:var(--r-md);padding:12px;margin:8px 0;display:inline-block;color:#333}
.qrbox[hidden]{display:none}
.qrbox svg{display:block;margin:0 auto;max-width:100%;height:auto}
.user{border-top:1px solid var(--line);padding:14px 0}
.user:first-of-type{border-top:0}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:start;padding:8px 6px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.02em}
tbody tr:hover{background:var(--soft)}
.ok{color:var(--ok)}.bad{color:var(--bad)}
.verdict{padding:11px 14px;border-radius:var(--r-md);background:var(--soft);margin:10px 0;font-size:14px}
#toast{position:fixed;inset-inline:0;bottom:20px;display:flex;justify-content:center;pointer-events:none;z-index:50}
#toast div{background:var(--ink);color:var(--canvas);padding:9px 18px;border-radius:999px;font-size:13.5px;box-shadow:0 6px 20px -6px rgba(0,0,0,.35)}
#toast div.bad{background:var(--bad);color:#fff}
.login{max-width:360px;margin:16vh auto 0;text-align:center}
.login .mark{width:44px;height:44px;margin:0 auto 14px;border-radius:14px;background:linear-gradient(135deg,var(--accent),var(--accent-2));box-shadow:0 8px 24px -8px color-mix(in srgb,var(--accent) 60%,transparent)}
.login h3{margin:0 0 16px;font-size:18px}
.login form{text-align:start}
@media (prefers-reduced-motion:no-preference){.tab,.btn,input,textarea{transition-duration:.15s}}
`;

function loginPage(msg) {
  return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>ورود</title><style>${STYLE}</style></head>
<body><div class="wrap"><div class="card login"><div class="mark"></div><h3>ورود به پنل</h3>
${msg ? `<p class="badge bad">${esc(msg)}</p>` : ''}
<form method="POST" action="/admin/login">
<input type="password" name="password" placeholder="رمز عبور" autocomplete="current-password" autofocus required>
<button class="btn" type="submit">ورود</button></form></div></div></body></html>`;
}

function panelPage() {
  return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>پنل مدیریت</title><style>${STYLE}</style></head>
<body><div class="wrap" id="app"><p class="note">در حال بارگذاری…</p></div><div id="toast"></div>
<script>(${clientMain.toString()})();</script></body></html>`;
}

// Runs in the browser (serialised into the page via toString)
function clientMain() {
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let S = null, tab = 'overview', testRes = null, testing = false, testHost = 'chatgpt.com';
  let srcRes = null, srcChecking = false;

  async function api(path, body) {
    const opt = body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) };
    const r = await fetch('/admin/api/' + path, opt);
    if (r.status === 401) { location.reload(); throw new Error('نشست منقضی شد'); }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || 'خطا ' + r.status);
    return j;
  }

  let toastTimer = null;
  function toast(msg, bad) {
    const el = $('#toast');
    el.innerHTML = '<div class="' + (bad ? 'bad' : '') + '">' + esc(msg) + '</div>';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.innerHTML = ''; }, 2600);
  }

  async function doAct(path, body, okMsg) {
    try {
      const j = await api(path, body);
      if (j.state) S = j.state;
      toast(okMsg || 'انجام شد');
      render();
    } catch (e) { toast(e.message, true); }
  }

  function copy(t) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(t).then(() => toast('کپی شد'), () => window.prompt('کپی کنید:', t));
    } else { window.prompt('کپی کنید:', t); }
  }

  const modeLabel = { auto: 'خودکار', custom: 'فقط لیست دستی', off: 'غیرفعال' };

  function routeStrip() {
    const relay = S.proxyMode === 'off' ? 'بدون رله' : 'رله‌ی ProxyIP';
    return '<div class="route" aria-label="مسیر ترافیک">' +
      '<div class="node"><small>دستگاه شما</small>کلاینت</div><span class="arrow">←</span>' +
      '<div class="node hot"><small>دیتاسنتر ' + esc(S.colo || '؟') + '</small>Worker</div><span class="arrow">←</span>' +
      '<div class="node"><small>اول</small>مستقیم</div><span class="arrow">/</span>' +
      '<div class="node"><small>اگر نشد</small>' + esc(relay) + '</div><span class="arrow">←</span>' +
      '<div class="node"><small>مقصد</small>سایت</div></div>';
  }

  // QR codes: the well-tested qrcode-generator library (MIT), loaded lazily from cdnjs only
  // when someone clicks a QR button. If it can't load (blocked network) we say so instead of failing.
  let qrLib = null;
  function loadQr() {
    if (window.qrcode) return Promise.resolve();
    if (!qrLib) {
      qrLib = new Promise((resolve, reject) => {
        const el = document.createElement('script');
        el.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/2.0.4/qrcode.min.js';
        el.onload = () => resolve();
        el.onerror = () => { qrLib = null; reject(new Error('بارگذاری کتابخانه‌ی بارکد ممکن نشد')); };
        document.head.appendChild(el);
      });
    }
    return qrLib;
  }

  async function toggleQr(btn) {
    const blk = btn.closest('.linkblk') || btn.closest('.card');
    const box = blk && blk.querySelector('.qrbox');
    if (!box) return;
    if (!box.hidden) { box.hidden = true; return; }
    try {
      await loadQr();
      const qr = window.qrcode(0, 'M');
      qr.addData(btn.dataset.text);
      qr.make();
      box.innerHTML = qr.createSvgTag({ cellSize: 5, margin: 4 }) +
        '<p class="note">این بارکد را با برنامه‌ی کلاینت (مثلاً v2rayNG) اسکن کنید.</p>';
      box.hidden = false;
    } catch (e) { toast(e.message || 'خطا در ساخت بارکد', true); }
  }

  function sourcesBlock() {
    if (srcChecking) return '<p class="note">در حال بررسی منابع…</p>';
    if (!srcRes) return '<p class="note">قبل از بررسی، تنظیمات را ذخیره کنید؛ بررسی روی آدرس‌های ذخیره‌شده انجام می‌شود.</p>';
    const okCount = srcRes.sources.filter((x) => x.ok).length;
    return '<div class="verdict">' + okCount + ' از ' + srcRes.sources.length + ' منبع جواب دادند؛ در مجموع ' + srcRes.total + ' آی‌پی یکتا پیدا شد.</div>' +
      '<table><tr><th>منبع</th><th>وضعیت</th><th>تعداد</th><th>زمان</th></tr>' +
      srcRes.sources.map((x) => '<tr><td class="ltr">' + esc(x.url) + '</td><td>' +
        (x.ok ? '<span class="ok">✔ سالم</span>' : '<span class="bad">✖ ' + esc(x.error || 'ناموفق') + '</span>') +
        '</td><td>' + x.count + '</td><td>' + x.ms + ' ms</td></tr>').join('') + '</table>';
  }

  const views = {
    overview() {
      return routeStrip() +
        '<div class="stats">' +
        '<div class="stat"><span>دیتاسنتر فعلی</span><b>' + esc(S.colo || '—') + '</b></div>' +
        '<div class="stat"><span>کاربران</span><b>' + S.users.length + ' از ' + S.maxUsers + '</b></div>' +
        '<div class="stat"><span>ProxyIP</span><b>' + esc(modeLabel[S.proxyMode] || S.proxyMode) + '</b></div>' +
        '<div class="stat"><span>دامنه‌ی Worker</span><b class="ltr">' + esc(S.host) + '</b></div></div>' +
        '<section class="card"><h3>لینک اشتراک</h3><code class="blk">' + esc(S.subUrl) + '</code>' +
        '<button class="btn sm" data-copy="' + esc(S.subUrl) + '">کپی لینک اشتراک</button> ' +
        '<button class="btn sm ghost" data-act="qr" data-text="' + esc(S.subUrl) + '">بارکد</button><div class="qrbox" hidden></div>' +
        '<p class="note">این لینک را در کلاینت به‌عنوان Subscription اضافه کنید.</p></section>' +
        '<section class="card"><h3>اگر سایتی باز نمی‌شود</h3>' +
        '<p class="note">سایت‌های پشت کلودفلر (مثل ChatGPT) از Worker مستقیم قابل دسترسی نیستند و به ProxyIP نیاز دارند. ' +
        'از تب «تست اتصال» بررسی کنید کدام مسیر برای آن سایت جواب می‌دهد.</p>' +
        '<button class="btn sm" data-act="tab" data-tab="tools">رفتن به تست اتصال</button></section>';
    },

    users() {
      const GB = 1073741824;
      const list = S.users.map((u) => {
        const badge = u.status === 'expired' ? '<span class="badge bad">منقضی‌شده</span>'
          : u.status === 'quota' ? '<span class="badge bad">اتمام حجم</span>'
          : '<span class="badge ok">فعال</span>';
        const expiryVal = u.expiresAt ? new Date(u.expiresAt).toISOString().slice(0, 10) : '';
        const quotaVal = u.quotaBytes ? (u.quotaBytes / GB).toFixed(2) : '';
        const usedGB = (u.usedBytes / GB).toFixed(2);
        const quotaGB = u.quotaBytes ? (u.quotaBytes / GB).toFixed(2) : null;
        const pct = quotaGB ? Math.min(100, (u.usedBytes / u.quotaBytes) * 100) : 0;
        return '<div class="user"><div class="row"><span><b>' + esc(u.name) + '</b> ' + badge + '</span><span>' +
          '<button class="btn sm ghost" data-act="user-rename" data-uuid="' + esc(u.uuid) + '">تغییر نام</button> ' +
          '<button class="btn sm danger" data-act="user-delete" data-uuid="' + esc(u.uuid) + '">حذف</button></span></div>' +
          '<code class="blk">' + esc(u.uuid) + '</code>' +
          '<button class="btn sm ghost" data-copy="' + esc(u.uuid) + '">کپی UUID</button>' +
          '<h4>محدودیت‌ها</h4>' +
          '<div class="field"><label>تاریخ انقضا</label><input type="date" class="limit-expiry" value="' + esc(expiryVal) + '"></div>' +
          '<div class="field"><label>سقف حجم (گیگابایت)</label><input type="text" inputmode="decimal" class="limit-quota ltr" placeholder="نامحدود" value="' + esc(quotaVal) + '"></div>' +
          '<button class="btn sm" data-act="user-limits" data-uuid="' + esc(u.uuid) + '">ذخیره محدودیت‌ها</button>' +
          '<p class="note">مصرف تقریبی است و با تأخیر کوتاه، بعد از پایان هر اتصال به‌روز می‌شود (به دلیل معماری Workers، شمارش کاملاً لحظه‌ای در سطح جهانی ممکن نیست).</p>' +
          '<div class="row"><span>مصرف: <b>' + usedGB + ' GB</b>' + (quotaGB ? ' از ' + quotaGB + ' GB' : ' (نامحدود)') + '</span>' +
          '<button class="btn sm ghost" data-act="user-reset-usage" data-uuid="' + esc(u.uuid) + '">ریست مصرف</button></div>' +
          (quotaGB ? '<div class="bar' + (pct >= 100 ? ' bad' : '') + '"><div style="width:' + pct.toFixed(1) + '%"></div></div>' : '') +
          u.links.map((l) =>
            '<div class="linkblk"><div class="row" style="margin-top:8px"><small class="note">' + esc(l.label) + '</small><span>' +
            '<button class="btn sm ghost" data-act="qr" data-text="' + esc(l.url) + '">بارکد</button> ' +
            '<button class="btn sm" data-copy="' + esc(l.url) + '">کپی لینک VLESS</button></span></div>' +
            '<code class="blk">' + esc(l.url) + '</code><div class="qrbox" hidden></div></div>').join('') +
          '</div>';
      }).join('');
      return '<section class="card"><h3>کاربران (' + S.users.length + ' از ' + S.maxUsers + ')</h3>' + list + '</section>' +
        '<section class="card"><h3>افزودن کاربر</h3><input id="newname" placeholder="نام کاربر" maxlength="32">' +
        '<button class="btn" data-act="user-add">افزودن</button></section>';
    },

    proxy() {
      const chk = (m) => (S.proxyMode === m ? 'checked' : '');
      return '<section class="card"><h3>ProxyIP</h3>' +
        '<p class="note">ابتدا اتصال مستقیم امتحان می‌شود. فقط اگر نشد، ترافیک از یک رله عبور می‌کند.</p>' +
        '<label class="opt"><input type="radio" name="pmode" value="auto" ' + chk('auto') + '><span><b>خودکار</b><br>' +
        '<small class="note">لیست دستی (اگر پر باشد) و بعد آدرس‌هایی که از دامنه‌ی منبع خودکار پیدا می‌شوند.</small></span></label>' +
        '<label class="opt"><input type="radio" name="pmode" value="custom" ' + chk('custom') + '><span><b>فقط لیست دستی</b></span></label>' +
        '<label class="opt"><input type="radio" name="pmode" value="off" ' + chk('off') + '><span><b>غیرفعال</b></span></label>' +
        '<h4>لیست دستی</h4><textarea id="plist" rows="5" placeholder="1.2.3.4:443&#10;relay.example.com">' + esc(S.proxyList) + '</textarea>' +
        '<p class="note">هر خط یک IP یا دامنه، با پورت اختیاری. اگر دامنه رکورد TXT با چند آدرس داشته باشد، همه‌ی آن‌ها استفاده می‌شود.</p>' +
        '<h4>دامنه‌ی منبع خودکار</h4><input id="pdomain" class="ltr" value="' + esc(S.autoDomain) + '">' +
        '<label class="opt"><input type="checkbox" id="pcolo" ' + (S.autoPerColo ? 'checked' : '') + '><span>' +
        'استفاده از پیشوند دیتاسنتر <span class="ltr">(' + esc((S.colo || '?').toLowerCase()) + '.' + esc(S.autoDomain) + ')</span></span></label>' +
        '<h4>دریافت خودکار آی‌پی تمیز از اینترنت</h4>' +
        '<label class="opt"><input type="checkbox" id="pclean" ' + (S.cleanIpEnabled ? 'checked' : '') + '><span><b>فعال</b><br>' +
        '<small class="note">علاوه بر لیست بالا، هر چند دقیقه یک‌بار از این آدرس‌ها یک فهرست آی‌پی تازه گرفته می‌شود و به‌عنوان کاندیدهای رله اضافه می‌شود.</small></span></label>' +
        '<textarea id="pcleanurls" rows="3" placeholder="https://...">' + esc(S.cleanIpUrls) + '</textarea>' +
        '<button class="btn sm ghost" data-act="clean-default" type="button">بازگشت به آدرس‌های پیش‌فرض</button> ' +
        '<button class="btn sm" data-act="check-sources" type="button"' + (srcChecking ? ' disabled' : '') + '>بررسی وضعیت منابع</button>' +
        sourcesBlock() +
        '<p class="note warn">این آدرس‌ها فهرست‌های عمومی شخص ثالث‌اند، در اختیار ما نیستند و ممکن است هر لحظه از کار بیفتند یا تغییر کنند. کیفیت و صحتشان تضمین‌شده نیست؛ فقط به‌عنوان کاندیدهای اضافه برای رله امتحان می‌شوند.</p>' +
        '<h4>محدود کردن به کشور خاص</h4>' +
        '<input id="pcountry" class="ltr" value="' + esc(S.countryFilter) + '" placeholder="US یا US,CA">' +
        '<p class="note">اختیاری. کد دو حرفی کشور (مثلاً US برای آمریکا)، با ویرگول جدا برای چند کشور. خالی = بدون فیلتر. کشور هر آی‌پی با یک سرویس شخص ثالث (ip-api.com) بررسی می‌شود؛ اگر این سرویس در دسترس نباشد، آن آی‌پی نادیده گرفته می‌شود.</p>' +
        '<button class="btn" data-act="proxy-save">ذخیره</button> ' +
        '<button class="btn ghost" data-act="proxy-default">بازگشت به دامنه‌ی پیش‌فرض</button>' +
        '<p class="note warn">رله یک سرور شخص ثالث است. ترافیک HTTPS تا مقصد رمزنگاری‌شده می‌ماند، اما رله می‌تواند نام سایت مقصد را ببیند و ترافیک بدون رمز (HTTP ساده) برایش قابل مشاهده است. اگر این برایتان مهم است از «فقط لیست دستی» با رله‌ی خودتان یا «غیرفعال» استفاده کنید.</p></section>';
    },

    sub() {
      const chk = (m) => (S.addrMode === m ? 'checked' : '');
      return '<section class="card"><h3>لینک اشتراک</h3><code class="blk">' + esc(S.subUrl) + '</code>' +
        '<button class="btn sm" data-copy="' + esc(S.subUrl) + '">کپی</button> ' +
        '<button class="btn sm ghost" data-act="qr" data-text="' + esc(S.subUrl) + '">بارکد</button> ' +
        '<button class="btn sm danger" data-act="sub-regen">ساخت لینک جدید</button>' +
        '<div class="qrbox" hidden></div>' +
        '<p class="note">هر کس این لینک را داشته باشد به همه‌ی کاربران دسترسی دارد. با ساخت لینک جدید، لینک قبلی از کار می‌افتد.</p></section>' +
        '<section class="card"><h3>آدرس‌های اتصال</h3>' +
        '<p class="note">این آدرس‌ها همان چیزی‌اند که در لینک VLESS و لینک اشتراک، جلوی نام کاربر قرار می‌گیرند و کلاینت برای <b>رسیدن به این Worker</b> به آن‌ها وصل می‌شود (SNI و Host همیشه دامنه‌ی Worker می‌ماند). اگر دامنه‌ی Worker در شبکه‌ی شما فیلتر است، از یک IP یا دامنه‌ی جایگزین استفاده کنید. با ProxyIP در تب قبلی اشتباه نشود؛ آن، آدرسی است که خود Worker برای رسیدن به سایت‌های مقصد استفاده می‌کند.</p>' +
        '<label class="opt"><input type="radio" name="amode" value="manual" ' + chk('manual') + '><span><b>دستی</b><br>' +
        '<small class="note">فقط آدرس‌هایی که پایین می‌نویسید استفاده می‌شوند.</small></span></label>' +
        '<label class="opt"><input type="radio" name="amode" value="auto" ' + chk('auto') + '><span><b>خودکار (آی‌پی تمیز)</b><br>' +
        '<small class="note">علاوه بر لیست دستی، چند آی‌پی از همان منبع‌ها و فیلتر کشوری که در تب ProxyIP تنظیم کرده‌اید اضافه می‌شود. برای این حالت، «دریافت خودکار آی‌پی تمیز» در تب ProxyIP لازم نیست فعال باشد؛ همین‌جا مستقل کار می‌کند.</small></span></label>' +
        '<textarea id="addrs" rows="5" placeholder="104.16.0.1&#10;example.com:2053">' + esc(S.addrs) + '</textarea>' +
        '<div id="acountwrap" style="' + (S.addrMode === 'auto' ? '' : 'display:none') + '">' +
        '<h4>تعداد آی‌پی خودکار</h4><input id="acount" type="text" inputmode="numeric" class="ltr" value="' + esc(S.addrCount) + '" style="max-width:100px">' +
        '<p class="note">حداکثر ' + S.maxAutoAddrs + ' عدد.</p></div>' +
        '<button class="btn" data-act="addr-save">ذخیره</button>' +
        '<p class="note warn">چرا اسکنر خودکار نداریم: طبق مستندات خود کلودفلر، خود Worker اجازه ندارد به هیچ آی‌پی‌ای که متعلق به کلودفلر باشد وصل شود (Outbound TCP sockets to Cloudflare IP ranges are blocked). چون همه‌ی این آدرس‌های اتصال دقیقاً همین‌جور آی‌پی‌هایی هستند، Worker نمی‌تواند خودش آن‌ها را تست کند؛ فقط می‌تواند از لیست منبع‌های بیرونی (بالا) استفاده کند یا هر آدرسی که خودتان دستی وارد کنید. اگر می‌خواهید مطمئن‌ترین آی‌پی برای شبکه‌ی خودتان را پیدا کنید، بهترین راه اجرای یک ابزار اسکن روی سیستم خودتان (مثل CloudflareSpeedTest) و افزودن دستی نتیجه به لیست بالاست.</p></section>';
    },

    tools() {
      let out = '';
      if (testing) out = '<p class="note">در حال تست… (تا حدود ۱۰ ثانیه)</p>';
      else if (testRes) {
        const r = testRes;
        const cell = (x) => x.ok ? '<span class="ok">✔ ' + esc(x.status || 'پاسخ داد') + '</span>' : '<span class="bad">✖ ' + esc(x.error || x.status || 'بدون پاسخ') + '</span>';
        const good = r.candidates.filter((c) => c.ok).length;
        const verdict = r.direct.ok
          ? 'اتصال مستقیم به این سایت کار می‌کند و به رله نیازی نیست.'
          : good
            ? 'اتصال مستقیم جواب نداد ولی ' + good + ' رله‌ی سالم پیدا شد. ProxyIP برای این سایت کار می‌کند.'
            : r.resolved
              ? 'هیچ‌کدام از ' + Math.min(r.resolved, 6) + ' رله‌ی امتحان‌شده جواب ندادند. لیست دستی یا دامنه‌ی منبع را عوض کنید.'
              : 'هیچ رله‌ای پیدا نشد. منبع خودکار رکوردی برنگرداند یا لیست دستی خالی است.';
        out = '<h4>نتیجه برای ' + esc(r.host) + ' (دیتاسنتر ' + esc(r.colo || '؟') + ')</h4>' +
          '<div class="verdict">' + verdict + '</div>' +
          '<table><tr><th>مسیر</th><th>کشور</th><th>وضعیت</th><th>زمان</th></tr>' +
          '<tr><td>مستقیم</td><td>—</td><td>' + cell(r.direct) + '</td><td>' + r.direct.ms + ' ms</td></tr>' +
          r.candidates.map((c) => '<tr><td class="ltr">' + esc(c.addr) + ':' + c.port + '</td><td>' + esc(c.cc || '؟') + '</td><td>' + cell(c) + '</td><td>' + c.ms + ' ms</td></tr>').join('') +
          '</table><p class="note">منبع‌ها: <span class="ltr">' + esc(r.entries.join(' , ') || '—') + '</span> — ' + r.resolved + ' آدرس پیدا شد' +
          (r.countries.length ? '، فیلتر کشور: <span class="ltr">' + esc(r.countries.join(',')) + '</span>' : '') + '.</p>';
      }
      return '<section class="card"><h3>تست اتصال</h3>' +
        '<p class="note">از خود Worker، اتصال مستقیم و رله‌ها را برای یک سایت امتحان می‌کند. پاسخ 403 هم یعنی مسیر کار می‌کند.</p>' +
        '<input id="thost" class="ltr" value="' + esc(testHost) + '" placeholder="chatgpt.com">' +
        '<button class="btn" data-act="run-test"' + (testing ? ' disabled' : '') + '>اجرای تست</button>' + out + '</section>';
    },
  };

  function render() {
    if (!S) return;
    const tabs = [['overview', 'نمای کلی'], ['users', 'کاربران'], ['proxy', 'ProxyIP'], ['sub', 'اشتراک و آدرس‌ها'], ['tools', 'تست اتصال']];
    $('#app').innerHTML =
      '<header class="top"><h1>پنل مدیریت</h1><button class="btn sm ghost" data-act="logout">خروج</button></header>' +
      '<nav class="tabs">' + tabs.map((t) => '<button class="tab ' + (t[0] === tab ? 'on' : '') + '" data-act="tab" data-tab="' + t[0] + '">' + t[1] + '</button>').join('') + '</nav>' +
      views[tab]();
  }

  async function runTest() {
    const el = $('#thost');
    if (el) testHost = el.value.trim() || 'chatgpt.com';
    testing = true; testRes = null; render();
    try { testRes = await api('test', { host: testHost }); }
    catch (e) { toast(e.message, true); }
    testing = false; render();
  }

  document.addEventListener('change', (e) => {
    if (e.target.name === 'amode') {
      const w = $('#acountwrap');
      if (w) w.style.display = e.target.value === 'auto' ? '' : 'none';
    }
  });

  document.addEventListener('click', async (e) => {
    const c = e.target.closest('[data-copy]');
    if (c) { copy(c.dataset.copy); return; }
    const a = e.target.closest('[data-act]');
    if (!a) return;
    const act = a.dataset.act;
    if (act === 'tab') { tab = a.dataset.tab; render(); }
    else if (act === 'user-add') await doAct('user/add', { name: $('#newname').value }, 'کاربر اضافه شد');
    else if (act === 'user-delete') { if (window.confirm('این کاربر حذف شود؟')) await doAct('user/delete', { uuid: a.dataset.uuid }, 'کاربر حذف شد'); }
    else if (act === 'qr') await toggleQr(a);
    else if (act === 'check-sources') {
      srcChecking = true; srcRes = null; render();
      try { srcRes = await api('sources/check', {}); } catch (e) { toast(e.message, true); }
      srcChecking = false; render();
    }
    else if (act === 'user-rename') { const n = window.prompt('نام جدید:'); if (n) await doAct('user/rename', { uuid: a.dataset.uuid, name: n }, 'نام ذخیره شد'); }
    else if (act === 'user-limits') {
      const box = a.closest('.user');
      await doAct('user/set-limits', {
        uuid: a.dataset.uuid,
        expiresAt: box.querySelector('.limit-expiry').value,
        quotaGB: box.querySelector('.limit-quota').value,
      }, 'محدودیت‌ها ذخیره شد');
    }
    else if (act === 'user-reset-usage') { if (window.confirm('مصرف این کاربر صفر شود؟')) await doAct('user/reset-usage', { uuid: a.dataset.uuid }, 'مصرف صفر شد'); }
    else if (act === 'proxy-save') {
      const m = document.querySelector('input[name=pmode]:checked');
      await doAct('proxy/save', {
        proxyMode: m ? m.value : 'auto',
        proxyList: $('#plist').value,
        autoDomain: $('#pdomain').value,
        autoPerColo: $('#pcolo').checked,
        cleanIpEnabled: $('#pclean').checked,
        cleanIpUrls: $('#pcleanurls').value,
        countryFilter: $('#pcountry').value,
      }, 'تنظیمات ProxyIP ذخیره شد');
    }
    else if (act === 'proxy-default') { $('#pdomain').value = S.autoDomainDefault; $('#pcolo').checked = true; toast('دامنه‌ی پیش‌فرض گذاشته شد. برای اعمال ذخیره کنید.'); }
    else if (act === 'clean-default') { $('#pcleanurls').value = S.cleanIpUrlsDefault; toast('آدرس‌های پیش‌فرض گذاشته شد. برای اعمال ذخیره کنید.'); }
    else if (act === 'addr-save') {
      const m = document.querySelector('input[name=amode]:checked');
      await doAct('addr/save', {
        addrs: $('#addrs').value,
        addrMode: m ? m.value : 'manual',
        addrCount: $('#acount') ? $('#acount').value : 3,
      }, 'آدرس‌ها ذخیره شد');
    }
    else if (act === 'sub-regen') { if (window.confirm('لینک قبلی باطل می‌شود. ادامه؟')) await doAct('sub/regen', {}, 'لینک اشتراک جدید ساخته شد'); }
    else if (act === 'run-test') await runTest();
    else if (act === 'logout') { try { await api('logout', {}); } catch (_) {} location.reload(); }
  });

  api('state').then((j) => { S = j; render(); }).catch((e) => { $('#app').innerHTML = '<p class="bad">' + esc(e.message) + '</p>'; });
}

function parseCookies(str) {
  const out = {};
  str.split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}

async function sha256(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

/* ================================ VLESS over WS ================================ */

// null = OK to use; otherwise a short reason ('expired' | 'quota').
function checkUserStatus(user) {
  if (user.expiresAt && Date.now() > user.expiresAt) return 'expired';
  if (user.quotaBytes && (user.usedBytes || 0) >= user.quotaBytes) return 'quota';
  return null;
}

// Best-effort usage accounting: Workers has no free, globally-consistent counter without
// Durable Objects, so this does a fresh read-modify-write per connection close. Under many
// simultaneous connections for the same user across different Cloudflare colos this can
// undercount slightly (a race between two closes), but is accurate enough for personal use,
// and quota is also checked live during a transfer (see trackBytes in handleWebSocket).
async function flushUsage(env, uuid, bytes) {
  if (!bytes) return;
  try {
    const cfg = await getConfig(env, true);
    const u = cfg.users.find((x) => x.uuid === uuid);
    if (u) {
      u.usedBytes = (u.usedBytes || 0) + bytes;
      await saveConfig(env, cfg);
    }
  } catch (_) {}
}

function handleWebSocket(request, env, cfg, ctx) {
  const usersById = new Map(cfg.users.map((u) => [u.uuid.replace(/-/g, ''), u]));
  const colo = (request.cf && request.cf.colo) || '';
  const hasProxy =
    buildProxyEntries(cfg, env, colo).length > 0 ||
    (cfg.proxyMode !== 'off' && cfg.cleanIpEnabled && splitList(cfg.cleanIpUrls).length > 0);

  const [client, server] = Object.values(new WebSocketPair());
  // compat date >= 2026-03-17 delivers binary frames as Blob by default; force ArrayBuffer (before accept)
  server.binaryType = 'arraybuffer';
  try { server.accept({ allowHalfOpen: true }); } catch (_) { server.accept(); }

  let remoteSocket = null;
  let remoteWriter = null;
  let udpHandler = null;
  let switching = null;
  let closed = false;
  let activeUser = null;
  let bytesThisConn = 0;

  // Checked on every chunk in both directions so a quota is enforced mid-transfer, not just
  // at connection start. The persisted usedBytes total is only reconciled at connection close
  // (see flushUsage) - see the code comment there for why this can't be perfectly real-time.
  function trackBytes(n) {
    bytesThisConn += n;
    if (activeUser && activeUser.quotaBytes && (activeUser.usedBytes || 0) + bytesThisConn >= activeUser.quotaBytes) {
      closeAll();
    }
  }

  const closeAll = () => {
    if (closed) return;
    closed = true;
    try { remoteSocket && remoteSocket.close(); } catch (_) {}
    try { server.close(1000, 'closed'); } catch (_) {}
    if (activeUser && bytesThisConn > 0) {
      const p = flushUsage(env, activeUser.uuid, bytesThisConn);
      if (ctx && ctx.waitUntil) ctx.waitUntil(p);
    }
  };

  async function openRemote(host, port, payload, timeoutMs) {
    const sock = connect({ hostname: host, port });
    try {
      await withTimeout(sock.opened, timeoutMs, 'connect timeout');
      const writer = sock.writable.getWriter();
      const prev = remoteSocket;
      remoteSocket = sock;
      remoteWriter = writer;
      if (prev && prev !== sock) { try { prev.close(); } catch (_) {} }
      if (payload && payload.byteLength) {
        await writer.write(payload);
        trackBytes(payload.byteLength);
      }
      return sock;
    } catch (e) {
      try { sock.close(); } catch (_) {}
      throw e;
    }
  }

  // Try relay candidates in order. Returns true when one was connected.
  async function tryProxies(h, from, budget) {
    if (budget <= 0) return false;
    const { list } = await getProxies(cfg, env, colo);
    let tries = 0;
    for (let k = from; k < list.length && tries < budget; k++, tries++) {
      const [addr, p] = list[k];
      try {
        const sock = await openRemote(addr, p || h.port, h.payload, PROXY_TIMEOUT);
        const left = budget - tries - 1;
        pipeRemoteToWs(sock, server, h.version, () => retryViaProxies(h, k + 1, left), closeAll, trackBytes);
        return true;
      } catch (e) {
        console.log('proxy candidate failed:', addr, e && e.message ? e.message : e);
      }
    }
    return false;
  }

  function retryViaProxies(h, from, budget) {
    switching = tryProxies(h, from, budget).finally(() => { switching = null; });
    return switching;
  }

  async function connectSequence(h) {
    let lastErr = null;
    if (!hasProxy || !isDirectBlocked(h.address)) {
      try {
        const sock = await openRemote(h.address, h.port, h.payload, DIRECT_TIMEOUT);
        pipeRemoteToWs(sock, server, h.version, hasProxy ? () => retryViaProxies(h, 0, MAX_PROXY_TRIES) : null, closeAll, trackBytes);
        return;
      } catch (e) {
        lastErr = e;
        if (!hasProxy) throw e;
        markDirectFail(h.address);
      }
    }
    const ok = await tryProxies(h, 0, MAX_PROXY_TRIES);
    if (!ok) throw lastErr || new Error('no working relay for ' + h.address);
  }

  async function onChunk(data) {
    if (closed) return;
    if (switching) await switching;

    if (udpHandler) {
      await udpHandler(data);
      return;
    }
    if (remoteWriter) {
      trackBytes(data.byteLength);
      await remoteWriter.write(data);
      return;
    }

    const h = parseVless(data, usersById);
    if (h.error) throw new Error(h.error);

    const user = usersById.get(h.id);
    const status = user ? checkUserStatus(user) : 'invalid';
    if (status) throw new Error('user ' + status);
    activeUser = user;

    // UDP: only DNS (port 53) is supported, forwarded over DoH
    if (h.isUdp) {
      if (h.port !== 53) throw new Error('UDP is only supported for DNS (port 53)');
      udpHandler = createDnsHandler(server, h.version);
      if (h.payload.byteLength) await udpHandler(h.payload);
      return;
    }

    await connectSequence(h);
  }

  // Process messages sequentially to avoid race conditions
  let queue = Promise.resolve();
  const enqueue = (data) => {
    queue = queue
      .then(async () => onChunk(await toBytes(data)))
      .catch((e) => {
        console.log('vless error:', e && e.message ? e.message : e);
        closeAll();
      });
  };

  server.addEventListener('message', (event) => {
    const d = event.data;
    if (typeof d === 'string') return;
    enqueue(d);
  });
  server.addEventListener('close', closeAll);
  server.addEventListener('error', closeAll);

  // Only treat the header as early data if it really is a VLESS header for one of our UUIDs
  // (some clients send plain subprotocol names such as "binary" in this header).
  const early = decodeEarlyData(request.headers.get('sec-websocket-protocol'));
  if (early && early.byteLength >= 24) {
    const id = Array.from(early.slice(1, 17)).map((x) => x.toString(16).padStart(2, '0')).join('');
    if (usersById.has(id)) enqueue(early);
  }

  return new Response(null, {
    status: 101,
    webSocket: client,
    headers: { 'Sec-WebSocket-Extensions': '' },
  });
}

// Normalise whatever the runtime hands us (ArrayBuffer, Blob, typed array) to Uint8Array.
async function toBytes(d) {
  if (d instanceof Uint8Array) return d;
  if (d instanceof ArrayBuffer) return new Uint8Array(d);
  if (ArrayBuffer.isView(d)) return new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
  if (typeof Blob !== 'undefined' && d instanceof Blob) return new Uint8Array(await d.arrayBuffer());
  return new Uint8Array(0);
}

// onEmpty() may return a promise resolving to true when it took over (e.g. reconnected via a relay)
async function pipeRemoteToWs(remote, ws, version, onEmpty, closeAll, onBytes) {
  let header = new Uint8Array([version, 0]);
  let gotData = false;

  try {
    await remote.readable.pipeTo(
      new WritableStream({
        write(chunk) {
          gotData = true;
          if (onBytes) onBytes(chunk.byteLength);
          if (ws.readyState !== 1) return;
          if (header) {
            const out = new Uint8Array(header.length + chunk.byteLength);
            out.set(header, 0);
            out.set(chunk, header.length);
            ws.send(out);
            header = null;
          } else {
            ws.send(chunk);
          }
        },
      })
    );
  } catch (_) {}

  if (!gotData && onEmpty) {
    try { if (await onEmpty()) return; } catch (_) {}
  }
  closeAll();
}

// UDP DNS over VLESS: payload is [2-byte length][DNS query] repeated.
// Each query is forwarded to a DoH server and answered in the same framing.
function createDnsHandler(ws, version) {
  let headerSent = false;
  let buf = new Uint8Array(0);

  return async (chunk) => {
    const merged = new Uint8Array(buf.length + chunk.length);
    merged.set(buf, 0);
    merged.set(chunk, buf.length);
    buf = merged;

    while (buf.length >= 2) {
      const len = (buf[0] << 8) | buf[1];
      if (buf.length < 2 + len) break;
      const query = buf.slice(2, 2 + len);
      buf = buf.slice(2 + len);

      const resp = await fetch(DOH, {
        method: 'POST',
        headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
        body: query,
      });
      const answer = new Uint8Array(await resp.arrayBuffer());

      const prefix = headerSent ? 0 : 2;
      const out = new Uint8Array(prefix + 2 + answer.length);
      if (!headerSent) {
        out[0] = version;
        out[1] = 0;
        headerSent = true;
      }
      out[prefix] = (answer.length >> 8) & 0xff;
      out[prefix + 1] = answer.length & 0xff;
      out.set(answer, prefix + 2);

      if (ws.readyState === 1) ws.send(out);
    }
  };
}

function parseVless(buf, usersById) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (b.length < 24) return { error: 'header too short' };

  const version = b[0];
  const id = Array.from(b.slice(1, 17)).map((x) => x.toString(16).padStart(2, '0')).join('');
  if (!usersById.has(id)) return { error: 'invalid uuid' };

  const addonLen = b[17];
  let i = 18 + addonLen;

  const cmd = b[i++];
  if (cmd !== 1 && cmd !== 2) return { error: 'unsupported command ' + cmd };

  const port = (b[i] << 8) | b[i + 1];
  i += 2;

  const atype = b[i++];
  let address = '';

  if (atype === 1) {
    address = Array.from(b.slice(i, i + 4)).join('.');
    i += 4;
  } else if (atype === 2) {
    const len = b[i++];
    address = new TextDecoder().decode(b.slice(i, i + len));
    i += len;
  } else if (atype === 3) {
    const parts = [];
    for (let k = 0; k < 8; k++) parts.push(((b[i + k * 2] << 8) | b[i + k * 2 + 1]).toString(16));
    address = parts.join(':');
    i += 16;
  } else {
    return { error: 'unknown address type' };
  }

  if (!address) return { error: 'empty address' };
  return { version, id, address, port, payload: b.slice(i), isUdp: cmd === 2 };
}

function decodeEarlyData(s) {
  if (!s) return null;
  try {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch (_) {
    return null;
  }
}
