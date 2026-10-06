const h = require('./helpers');
const { test, afterEach, after, before } = require('node:test');
const assert = require('node:assert/strict');
const { mock, chain, User } = h;
let app;
before(async () => { app = await h.startApp(); mock.method(User, 'findOne', () => chain(null)); });
after(async () => { await app.close(); mock.restoreAll(); });

const burst = async (method, path, body, n) => {
  const codes = [];
  for (let i = 0; i < n; i++) codes.push((await app.call(method, path, { body })).status);
  return codes;
};

test('login: 11th attempt in the window -> 429 { message }', async () => {
  const codes = await burst('POST', '/api/auth/login', { email: 'a@brainwareuniversity.ac.in', password: 'x' }, 11);
  assert.equal(codes.slice(0, 10).every((c) => c === 401), true);
  assert.equal(codes[10], 429);
  const r = await app.call('POST', '/api/auth/login', { body: { email: 'a@brainwareuniversity.ac.in', password: 'x' } });
  assert.equal(typeof r.json.message, 'string');
  assert.ok(r.headers.get('ratelimit') || r.headers.get('ratelimit-policy'));
});

test('resend-otp: 6th request -> 429', async () => {
  const codes = await burst('POST', '/api/auth/resend-otp', { email: 'a@brainwareuniversity.ac.in' }, 6);
  assert.deepEqual(codes, [404, 404, 404, 404, 404, 429]);
});

test('verify-otp: limited after 20 requests', async () => {
  const codes = await burst('POST', '/api/auth/verify-otp', { email: 'a@brainwareuniversity.ac.in', otp: '111111' }, 21);
  assert.equal(codes.slice(0, 20).every((c) => c === 404), true);
  assert.equal(codes[20], 429);
});

test('signup: 11th request in the hour -> 429', async () => {
  const codes = await burst('POST', '/api/auth/signup', { email: 'bad' }, 11);
  assert.equal(codes.slice(0, 10).every((c) => c === 400), true);
  assert.equal(codes[10], 429);
});

test('forgot-password and reset-password are limited', async () => {
  const f = await burst('POST', '/api/auth/forgot-password', { email: 'a@brainwareuniversity.ac.in' }, 11);
  assert.equal(f[10], 429);
  const r = await burst('POST', `/api/auth/reset-password/${'a'.repeat(64)}`, { password: 'secret1' }, 11);
  assert.equal(r[10], 429);
});

test('non-auth routes are NOT globally limited (normal browsing keeps working)', async () => {
  mock.method(require('../src/models/Product'), 'find', () => chain([]));
  const codes = [];
  for (let i = 0; i < 40; i++) codes.push((await app.call('GET', '/api/products')).status);
  assert.equal(codes.every((c) => c === 200), true);
});
