const dns = require('node:dns').promises;
const path = require('node:path');
const fs = require('node:fs');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { chromium } = require('playwright-core');
const { getDomain } = require('tldts');
const { db, settings } = require('./db');
const events = require('./events');

const screenshotDir = path.resolve(process.env.SCREENSHOT_DIR || 'screenshots');
const execFileAsync = promisify(execFile);
fs.mkdirSync(screenshotDir, { recursive: true });
let processing = false;

async function fetchIpInfo(domain, token) {
  const addresses = await dns.resolve4(domain).catch(() => []);
  return Promise.all(addresses.slice(0, 4).map(async ip => {
    if (!token) return { ip, warning: 'IPinfo token not configured' };
    const response = await fetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(token)}`, { signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error(`IPinfo returned ${response.status}`);
    return response.json();
  }));
}

function parseWhois(output) {
  const parsed = { source: 'local whois', raw: output };
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/^\s*([^:%][^:]{1,80}):\s*(.+?)\s*$/); if (!match) continue;
    const key = match[1].trim().replace(/\s+/g, ' '), value = match[2].trim();
    if (parsed[key] === undefined) parsed[key] = value;
    else if (Array.isArray(parsed[key])) parsed[key].push(value);
    else parsed[key] = [parsed[key], value];
  }
  return parsed;
}

async function fetchRegistration(domain) {
  const { stdout, stderr } = await execFileAsync('whois', [domain], { timeout: 30000, maxBuffer: 2 * 1024 * 1024 });
  if (!stdout.trim()) throw new Error(stderr.trim() || 'Local whois returned no data');
  return parseWhois(stdout);
}

async function screenshot(domain, proxy) {
  const filename = `${domain.replace(/[^a-z0-9.-]/gi, '_')}-${Date.now()}.png`;
  const target = path.join(screenshotDir, filename);
  const launch = { executablePath: process.env.CHROME_PATH || '/usr/bin/google-chrome', headless: true };
  if (proxy) launch.proxy = { server: proxy };
  const browser = await chromium.launch(launch);
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
    let firstError;
    try { await page.goto(`http://${domain}`, { waitUntil: 'domcontentloaded', timeout: 20000 }); }
    catch (error) { firstError = error; await page.goto(`https://${domain}`, { waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => { throw firstError; }); }
    await page.screenshot({ path: target, fullPage: true });
    return `/screenshots/${filename}`;
  } finally { await browser.close(); }
}

async function enrichOne(row) {
  const cfg = settings();
  db.prepare("UPDATE catches SET status='processing',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(row.id);
  events.emit('update', 'catches');
  const errors = [];
  let whoisData = null, ipData = null, screenshotPath = null, screenshotError = null;
  const registrableDomain = getDomain(row.domain) || row.domain;
  try { whoisData = await fetchRegistration(registrableDomain); } catch (e) { errors.push(`Registration lookup: ${e.message}`); }
  try { ipData = await fetchIpInfo(row.domain, cfg.ipinfo_token); } catch (e) { errors.push(`IPinfo: ${e.message}`); }
  if (cfg.screenshot_enabled === '1') {
    try { screenshotPath = await screenshot(row.domain, cfg.screenshot_proxy); }
    catch (e) { screenshotError = e.message; errors.push(`Screenshot: ${e.message}`); }
  }
  if (!db.prepare('SELECT 1 FROM catches WHERE id=?').get(row.id)) {
    if (screenshotPath) fs.rm(path.join(screenshotDir, path.basename(screenshotPath)), { force: true }, () => {});
    return;
  }
  db.prepare(`UPDATE catches SET status='complete',whois_json=?,ip_json=?,screenshot_path=?,screenshot_error=?,error=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`)
    .run(JSON.stringify(whoisData), JSON.stringify(ipData), screenshotPath, screenshotError, errors.join('\n'), row.id);
  events.emit('update', 'catches');
}

async function drain() {
  if (processing) return;
  processing = true;
  try {
    let row;
    while ((row = db.prepare("SELECT * FROM catches WHERE status='queued' ORDER BY id LIMIT 1").get())) await enrichOne(row);
  } finally { processing = false; }
}

async function refreshIpInfo(id) {
  const row = db.prepare('SELECT * FROM catches WHERE id=?').get(id);
  if (!row) throw new Error('Catch not found');
  const ipData = await fetchIpInfo(row.domain, settings().ipinfo_token);
  db.prepare('UPDATE catches SET ip_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(JSON.stringify(ipData), id);
  events.emit('update', 'catches');
  return ipData;
}

async function refreshScreenshot(id) {
  const row = db.prepare('SELECT * FROM catches WHERE id=?').get(id);
  if (!row) throw new Error('Catch not found');
  const screenshotPath = await screenshot(row.domain, settings().screenshot_proxy);
  if (!db.prepare('SELECT 1 FROM catches WHERE id=?').get(id)) { fs.rm(path.join(screenshotDir, path.basename(screenshotPath)), { force: true }, () => {}); return null; }
  db.prepare('UPDATE catches SET screenshot_path=?,screenshot_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(screenshotPath, id);
  events.emit('update', 'catches');
  return screenshotPath;
}

module.exports = { drain, screenshotDir, fetchIpInfo, refreshIpInfo, refreshScreenshot, fetchRegistration, parseWhois };
