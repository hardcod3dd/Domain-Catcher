const test = require('node:test');
const assert = require('node:assert/strict');
const { matchDomain, isWhitelisted, canonicalDomain } = require('../src/matcher');

test('matches an ordinary keyword', () => assert.deepEqual(matchDomain('login-paypal.example', ['paypal']), { keyword: 'paypal', type: 'exact' }));
test('matches Cyrillic homoglyphs', () => assert.deepEqual(matchDomain('раypal.example', ['paypal']), { keyword: 'paypal', type: 'homoglyph' }));
test('normalizes wildcard certificate domains', () => assert.equal(canonicalDomain('*.EXAMPLE.com'), 'example.com'));
test('whitelists domain and subdomains, not suffix tricks', () => {
  assert.equal(isWhitelisted('login.example.com', ['example.com']), true);
  assert.equal(isWhitelisted('example.com.evil.test', ['example.com']), false);
});
test('base-only scope ignores a keyword found only in a subdomain', () => {
  assert.equal(matchDomain('google.login.example.com', [{ value: 'google', match_scope: 'base' }]), null);
  assert.deepEqual(matchDomain('login.google-example.com', [{ value: 'google', match_scope: 'base' }]), { keyword: 'google', type: 'exact' });
  assert.deepEqual(matchDomain('google.login.example.com', [{ value: 'google', match_scope: 'all' }]), { keyword: 'google', type: 'exact' });
});
