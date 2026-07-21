const WebSocket = require('ws');
const { db, settings, setSettings } = require('./db');
const { canonicalDomain, isWhitelisted, matchDomain } = require('./matcher');
const { drain } = require('./enrichment');
const events = require('./events');

class StreamWorker {
  constructor() { this.ws = null; this.timer = null; this.state = 'stopped'; this.lastError = ''; this.seen = 0; }
  start() { setSettings({ worker_enabled: '1' }); this.connect(); events.emit('update', 'status'); }
  stop() { setSettings({ worker_enabled: '0' }); clearTimeout(this.timer); this.ws?.close(); this.ws = null; this.state = 'stopped'; events.emit('update', 'status'); }
  connect() {
    if (settings().worker_enabled !== '1' || this.ws) return;
    const url = settings().certstream_url;
    if (!url) { this.state = 'error'; this.lastError = 'Certstream URL is empty'; return; }
    this.state = 'connecting';
    try { this.ws = new WebSocket(url); } catch (e) { this.failed(e); return; }
    this.ws.on('open', () => { this.state = 'running'; this.lastError = ''; events.emit('update', 'status'); });
    this.ws.on('message', data => this.handle(data));
    this.ws.on('error', e => { this.lastError = e.message; });
    this.ws.on('close', () => { this.ws = null; if (settings().worker_enabled === '1') { this.state = 'reconnecting'; this.timer = setTimeout(() => this.connect(), 5000); } });
  }
  failed(e) { this.ws = null; this.lastError = e.message; this.state = 'reconnecting'; this.timer = setTimeout(() => this.connect(), 5000); }
  handle(data) {
    let event; try { event = JSON.parse(data.toString()); } catch { return; }
    const domains = event?.data?.leaf_cert?.all_domains || event?.data?.domains || [];
    const keywords = db.prepare('SELECT value,match_scope FROM keywords WHERE enabled=1').all();
    const whitelist = db.prepare('SELECT domain FROM whitelist').all().map(x => x.domain);
    let inserted = false;
    for (const name of domains) {
      const domain = canonicalDomain(name); this.seen++;
      if (!domain || isWhitelisted(domain, whitelist)) continue;
      const match = matchDomain(name, keywords); if (!match) continue;
      inserted = db.prepare('INSERT OR IGNORE INTO catches(domain,matched_keyword,match_type) VALUES(?,?,?)').run(domain, match.keyword, match.type).changes > 0 || inserted;
    }
    if (inserted) events.emit('update', 'catches');
    if (this.seen % 250 < domains.length) events.emit('update', 'status');
    drain();
  }
  status() { return { state: this.state, lastError: this.lastError, seen: this.seen, url: settings().certstream_url }; }
}

module.exports = { StreamWorker };
