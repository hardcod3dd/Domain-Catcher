const express = require('express');
const path = require('node:path');
const fs = require('node:fs');
const multer = require('multer');
const { WebSocketServer, WebSocket } = require('ws');
const { db, settings, setSettings } = require('./db');
const { StreamWorker } = require('./stream');
const { drain, screenshotDir, refreshIpInfo, refreshScreenshot } = require('./enrichment');
const events = require('./events');
const { getDomain } = require('tldts');

const app = express();
const upload = multer({ dest: path.join(require('node:os').tmpdir(), 'domain-catcher-imports'), limits: { fileSize: 20 * 1024 * 1024 } });
const worker = new StreamWorker();
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.resolve('public')));
app.use('/screenshots', express.static(screenshotDir));

const cleanLines = value => [...new Set(String(value || '').split(/[\n,;]/).map(x => x.trim().toLowerCase()).filter(Boolean))];
const safeJson = value => { try { return JSON.parse(value); } catch { return null; } };
const findValue = (object, names) => {
  if (!object || typeof object !== 'object') return null;
  const wanted = names.map(x => x.replace(/[^a-z0-9]/gi, '').toLowerCase());
  for (const [key, value] of Object.entries(object)) {
    if (wanted.includes(key.replace(/[^a-z0-9]/gi, '').toLowerCase()) && value != null && value !== '') return Array.isArray(value) ? value[0] : value;
    if (value && typeof value === 'object') { const nested = findValue(value, names); if (nested != null) return nested; }
  }
  return null;
};
const serialize = row => {
  const whois = safeJson(row.whois_json), ip = safeJson(row.ip_json), primaryIp = Array.isArray(ip) ? ip[0] : ip;
  const rdapRegistrar = whois?.entities?.find(entity => entity.roles?.includes('registrar'));
  const rdapRegistrarName = rdapRegistrar?.vcardArray?.[1]?.find(field => field[0] === 'fn')?.[3];
  const rdapRegistration = whois?.events?.find(event => ['registration','created'].includes(event.eventAction))?.eventDate;
  return { ...row, whois, ip, summary: {
    hostname: row.domain, base_domain: getDomain(row.domain) || row.domain,
    ip: primaryIp?.ip || null, country: primaryIp?.country || null,
    asn: primaryIp?.org || primaryIp?.asn?.asn || primaryIp?.asn || null,
    registrar: findValue(whois, ['registrar', 'registrarName', 'sponsoringRegistrar']) || rdapRegistrarName || null,
    registered_at: findValue(whois, ['creationDate', 'createdDate', 'created', 'registrationDate', 'registered']) || rdapRegistration || null
  }, whois_json: undefined, ip_json: undefined };
};

app.get('/api/status', (_req, res) => res.json({ worker: worker.status(), counts: {
  catches: db.prepare('SELECT COUNT(*) n FROM catches').get().n,
  keywords: db.prepare('SELECT COUNT(*) n FROM keywords WHERE enabled=1').get().n,
  queued: db.prepare("SELECT COUNT(*) n FROM catches WHERE status IN ('queued','processing')").get().n
}}));
app.post('/api/worker/start', (_req, res) => { worker.start(); res.json(worker.status()); });
app.post('/api/worker/stop', (_req, res) => { worker.stop(); res.json(worker.status()); });

app.get('/api/settings', (_req, res) => { const cfg = settings(); res.json({ ...cfg, ipinfo_token: cfg.ipinfo_token ? '••••••••' : '' }); });
app.put('/api/settings', (req, res) => {
  const allowed = ['certstream_url', 'ipinfo_token', 'screenshot_proxy', 'screenshot_enabled'];
  const values = Object.fromEntries(allowed.filter(k => req.body[k] !== undefined && !(k === 'ipinfo_token' && req.body[k] === '••••••••')).map(k => [k, req.body[k]]));
  setSettings(values); res.json({ ok: true });
});

function listRoutes(table, field) {
  app.get(`/api/${table}`, (_req, res) => res.json(db.prepare(`SELECT * FROM ${table} ORDER BY ${field}`).all()));
  app.post(`/api/${table}/bulk`, (req, res) => {
    const values = cleanLines(req.body.values);
    const stmt = db.prepare(`INSERT OR IGNORE INTO ${table}(${field}) VALUES(?)`);
    db.transaction(() => values.forEach(v => stmt.run(v)))();
    res.json({ added: values.length });
  });
  app.delete(`/api/${table}/:id`, (req, res) => { db.prepare(`DELETE FROM ${table} WHERE id=?`).run(req.params.id); res.json({ ok: true }); });
}
listRoutes('keywords', 'value'); listRoutes('whitelist', 'domain');
app.patch('/api/keywords/:id', (req, res) => {
  const scope = req.body.match_scope === 'base' ? 'base' : 'all';
  const result = db.prepare('UPDATE keywords SET match_scope=? WHERE id=?').run(scope, req.params.id);
  result.changes ? res.json({ ok: true, match_scope: scope }) : res.status(404).json({ error: 'Keyword not found' });
});

app.get('/api/catches', (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 200), offset = Math.max(Number(req.query.offset) || 0, 0);
  const clauses = [], args = [];
  const contains = (fields, value) => { if (!value) return; clauses.push(`(${fields.map(f => `${f} LIKE ?`).join(' OR ')})`); fields.forEach(() => args.push(`%${value}%`)); };
  contains(['domain','matched_keyword','match_type','status','COALESCE(ip_json,\'\')','COALESCE(whois_json,\'\')'], String(req.query.q || '').trim());
  contains(['COALESCE(ip_json,\'\')'], String(req.query.country || '').trim());
  contains(['COALESCE(ip_json,\'\')'], String(req.query.asn || '').trim());
  contains(['COALESCE(whois_json,\'\')'], String(req.query.registrar || '').trim());
  if (req.query.status) { clauses.push('status=?'); args.push(String(req.query.status)); }
  if (req.query.match_type) { clauses.push('match_type=?'); args.push(String(req.query.match_type)); }
  if (req.query.favorite === '1') clauses.push('favorite=1');
  if (req.query.registered_from) { clauses.push("COALESCE(whois_json,'') LIKE ?"); args.push(`%${req.query.registered_from}%`); }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = db.prepare(`SELECT * FROM catches ${where} ORDER BY caught_at DESC LIMIT ? OFFSET ?`).all(...args, limit, offset).map(serialize);
  const total = db.prepare(`SELECT COUNT(*) n FROM catches ${where}`).get(...args).n;
  res.json({ rows, total, limit, offset });
});
app.get('/api/catches/:id', (req, res) => { const row = db.prepare('SELECT * FROM catches WHERE id=?').get(req.params.id); row ? res.json(serialize(row)) : res.status(404).json({ error: 'Not found' }); });
app.patch('/api/catches/:id/favorite', (req, res) => {
  const favorite = req.body.favorite ? 1 : 0;
  const result = db.prepare('UPDATE catches SET favorite=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(favorite, req.params.id);
  if (!result.changes) return res.status(404).json({ error: 'Catch not found' });
  events.emit('update', 'catches'); res.json({ ok: true, favorite: Boolean(favorite) });
});
app.get('/get-all', (_req, res) => res.json(db.prepare('SELECT * FROM catches ORDER BY caught_at DESC').all().map(row => ({ ...row, whois_json: safeJson(row.whois_json), ip_json: safeJson(row.ip_json) }))));
app.post('/api/catches/:id/retry', (req, res) => { db.prepare("UPDATE catches SET status='queued',error=NULL WHERE id=?").run(req.params.id); drain(); res.json({ ok: true }); });
app.post('/api/catches/:id/refresh-ip', (req, res) => {
  res.status(202).json({ queued: true });
  refreshIpInfo(req.params.id).catch(error => { db.prepare('UPDATE catches SET error=? WHERE id=?').run(`IPinfo: ${error.message}`, req.params.id); events.emit('update', 'catches'); });
});
app.post('/api/catches/refresh-all-ip', (req, res) => {
  const ids = db.prepare('SELECT id FROM catches ORDER BY id').all().map(row => row.id);
  res.status(202).json({ queued: ids.length });
  (async () => {
    for (const id of ids) {
      try { await refreshIpInfo(id); }
      catch (error) { db.prepare('UPDATE catches SET error=? WHERE id=?').run(`IPinfo: ${error.message}`, id); events.emit('update', 'catches'); }
    }
    events.emit('update', 'status');
  })();
});
app.post('/api/catches/:id/refresh-screenshot', (req, res) => {
  res.status(202).json({ queued: true });
  refreshScreenshot(req.params.id).catch(error => { db.prepare('UPDATE catches SET screenshot_error=?,error=? WHERE id=?').run(error.message, `Screenshot: ${error.message}`, req.params.id); events.emit('update', 'catches'); });
});
app.delete('/api/catches/:id', (req, res) => { const row = db.prepare('SELECT screenshot_path FROM catches WHERE id=?').get(req.params.id); db.prepare('DELETE FROM catches WHERE id=?').run(req.params.id); if (row?.screenshot_path) fs.rm(path.join(screenshotDir, path.basename(row.screenshot_path)), { force: true }, () => {}); res.json({ ok: true }); });

app.get('/api/export/json', (_req, res) => { res.attachment(`domain-catches-${Date.now()}.json`).json(db.prepare('SELECT * FROM catches ORDER BY caught_at DESC').all().map(serialize)); });
app.get('/api/export/csv', (_req, res) => {
  const rows = db.prepare('SELECT domain,matched_keyword,match_type,caught_at,status,screenshot_path,error FROM catches ORDER BY caught_at DESC').all();
  const quote = v => `"${String(v ?? '').replaceAll('"', '""')}"`;
  res.type('text/csv').attachment(`domain-catches-${Date.now()}.csv`).send([Object.keys(rows[0] || { domain: '' }).map(quote).join(','), ...rows.map(r => Object.values(r).map(quote).join(','))].join('\n'));
});
app.post('/api/import', upload.single('file'), (req, res, next) => {
  try {
    const rows = JSON.parse(fs.readFileSync(req.file.path, 'utf8')); if (!Array.isArray(rows)) throw new Error('Import must contain a JSON array');
    const stmt = db.prepare(`INSERT INTO catches(domain,matched_keyword,match_type,caught_at,status,screenshot_path,screenshot_error,whois_json,ip_json,error) VALUES(@domain,@matched_keyword,@match_type,@caught_at,@status,@screenshot_path,@screenshot_error,@whois_json,@ip_json,@error) ON CONFLICT(domain) DO NOTHING`);
    db.transaction(() => rows.forEach(r => stmt.run({ domain: r.domain, matched_keyword: r.matched_keyword || r.matchedKeyword || 'imported', match_type: r.match_type || 'imported', caught_at: r.caught_at || new Date().toISOString(), status: r.status || 'complete', screenshot_path: r.screenshot_path || null, screenshot_error: r.screenshot_error || null, whois_json: JSON.stringify(r.whois ?? null), ip_json: JSON.stringify(r.ip ?? null), error: r.error || null })))();
    res.json({ imported: rows.length });
  } catch (e) { next(e); } finally { if (req.file) fs.rm(req.file.path, { force: true }, () => {}); }
});
app.delete('/api/data/purge', (_req, res, next) => {
  try {
    const deleted = db.prepare('SELECT COUNT(*) AS count FROM catches').get().count;
    db.prepare('DELETE FROM catches').run();
    let screenshots = 0;
    for (const entry of fs.readdirSync(screenshotDir, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      fs.rmSync(path.join(screenshotDir, entry.name), { force: true }); screenshots++;
    }
    db.exec('VACUUM'); events.emit('update', 'catches'); events.emit('update', 'status');
    res.json({ ok: true, deleted, screenshots });
  } catch (error) { next(error); }
});

app.use((err, _req, res, _next) => { console.error(err); res.status(400).json({ error: err.message }); });
const port = Number(process.env.PORT || 3000);
const server = app.listen(port, () => { console.log(`Domain Catcher listening on http://localhost:${port}`); if (settings().worker_enabled === '1') worker.start(); drain(); });
const live = new WebSocketServer({ server, path: '/live' });
const broadcast = type => { const message = JSON.stringify({ type, at: Date.now() }); for (const client of live.clients) if (client.readyState === WebSocket.OPEN) client.send(message); };
events.on('update', broadcast);
