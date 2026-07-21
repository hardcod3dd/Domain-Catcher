const { remove } = require('confusables');
const { domainToASCII, domainToUnicode } = require('node:url');
const { getDomain } = require('tldts');

function normalize(value) {
  let decoded = String(value || '').trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  decoded = domainToUnicode(decoded) || decoded;
  return remove(decoded).normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]/g, '');
}

function canonicalDomain(value) {
  const clean = String(value || '').trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  return domainToASCII(clean) || clean;
}

function isWhitelisted(domain, list) {
  const d = canonicalDomain(domain);
  return list.some(item => d === canonicalDomain(item) || d.endsWith(`.${canonicalDomain(item)}`));
}

function matchDomain(domain, keywords) {
  const unicode = String(domain).toLowerCase();
  const ascii = canonicalDomain(domain);
  for (const item of keywords) {
    const keyword = typeof item === 'string' ? item : item.value;
    const scope = typeof item === 'string' ? 'all' : item.match_scope;
    if (scope === 'domain') {
      const target = canonicalDomain(keyword);
      if (target && (ascii === target || ascii.endsWith(`.${target}`))) return { keyword, type: 'exact-domain' };
      continue;
    }
    const candidateAscii = scope === 'base' ? (getDomain(ascii) || ascii) : ascii;
    const candidateUnicode = domainToUnicode(candidateAscii) || candidateAscii;
    const skeleton = normalize(candidateUnicode);
    const raw = String(keyword).trim().toLowerCase();
    if (!raw) continue;
    if (candidateUnicode.includes(raw) || candidateAscii.includes(raw)) return { keyword, type: 'exact' };
    const keySkeleton = normalize(raw);
    if (keySkeleton && skeleton.includes(keySkeleton)) return { keyword, type: 'homoglyph' };
  }
  return null;
}

module.exports = { normalize, canonicalDomain, isWhitelisted, matchDomain };
