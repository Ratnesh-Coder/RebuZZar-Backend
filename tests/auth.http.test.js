const h = require('./helpers');
const { test, beforeEach, afterEach, after, before } = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { hashOtp } = require('../src/utils/otp');
const { hashToken } = require('../src/utils/token');
const passport = require('../src/config/passport');

const { mock, chain, makeUser, User } = h;
let app;
before(async () => { app = await h.startApp(); });
after(async () => { await app.close(); });
afterEach(() => mock.restoreAll());

const signupBody = (over = {}) => ({
  name: 'New Student', email: 'new@brainwareuniversity.ac.in', password: 'secret1',
  programType: 'UG', department: 'CSE', year: '1st Year', ...over,
});

test('signup: new user -> 201 {message,userId}; OTP mail sent; response has no secrets', async () => {
  const sent = h.stubMail();
  let created;
  mock.method(User, 'findOne', () => chain(null));
  mock.method(User, 'create', async (doc) => { created = doc; return makeUser({ ...doc }); });
  const r = await app.call('POST', '/api/auth/signup', { body: signupBody({ studentCode: 'BWU1' }) });
  assert.equal(r.status, 201);
  assert.equal(r.json.message, 'Signup successful. Verify OTP.');
  assert.ok(r.json.userId);
  assert.equal(created.studentCode, 'BWU1');
  assert.notEqual(created.password, 'secret1');                 // hashed
  assert.match(created.emailOTP, /^[a-f0-9]{64}$/);              // OTP stored hashed
  assert.equal(sent.length, 1);
  assert.match(sent[0].html, /\d{6}/);
});

test('signup: existing UNVERIFIED -> 409 + needsVerification (frontend contract)', async () => {
  mock.method(User, 'findOne', () => chain(makeUser({ isVerified: false })));
  const r = await app.call('POST', '/api/auth/signup', { body: signupBody() });
  assert.equal(r.status, 409);
  assert.equal(r.json.needsVerification, true);
  assert.equal(typeof r.json.message, 'string');
});

test('signup: existing VERIFIED -> 409 (was a 500)', async () => {
  mock.method(User, 'findOne', () => chain(makeUser({ isVerified: true })));
  const r = await app.call('POST', '/api/auth/signup', { body: signupBody() });
  assert.equal(r.status, 409);
  assert.equal(r.json.needsVerification, undefined);
});

test('signup: concurrent duplicate (E11000) -> 409, not 500', async () => {
  mock.method(User, 'findOne', () => chain(null));
  mock.method(User, 'create', async () => { throw Object.assign(new Error('E11000'), { code: 11000 }); });
  h.stubMail();
  assert.equal((await app.call('POST', '/api/auth/signup', { body: signupBody() })).status, 409);
});

test('signup: mail failure -> 500 with the previous message (delivery is the operation)', async () => {
  h.stubMail({ fail: true });
  mock.method(User, 'findOne', () => chain(null));
  mock.method(User, 'create', async (doc) => makeUser({ ...doc }));
  const r = await app.call('POST', '/api/auth/signup', { body: signupBody() });
  assert.equal(r.status, 500);
  assert.equal(r.json.message, 'Failed to send verification email');
});

const otpUser = (over = {}) => makeUser({
  isVerified: false, emailOTP: hashOtp('123456'), emailOTPExpires: new Date(Date.now() + 60000), emailOTPAttempts: 0, ...over,
});

test('verify-otp: frontend contract {email, otp} -> {message}', async () => {
  const u = otpUser();
  mock.method(User, 'findOne', () => chain(u));
  mock.method(User, 'findOneAndUpdate', () => chain({ emailOTPAttempts: 1 }));
  let upd;
  mock.method(User, 'updateOne', async (f, u2) => { upd = u2; return { modifiedCount: 1 }; });
  const r = await app.call('POST', '/api/auth/verify-otp', { body: { email: u.email, otp: '123456' } });
  assert.equal(r.status, 200);
  assert.equal(r.json.message, 'Email verified successfully.');
  assert.equal(r.json.token, undefined);               // no token, exactly like the frontend expects
  assert.equal(upd.$set.isVerified, true);
});

test('verify-otp: wrong OTP -> 400; attempt cap -> 429 and OTP invalidated', async () => {
  const u = otpUser();
  mock.method(User, 'findOne', () => chain(u));
  let attempts = 0;
  mock.method(User, 'findOneAndUpdate', () => chain({ emailOTPAttempts: ++attempts }));
  const invalidations = [];
  mock.method(User, 'updateOne', async (f, upd) => { invalidations.push(upd); return { modifiedCount: 1 }; });
  const codes = [];
  for (let i = 0; i < 5; i++) codes.push((await app.call('POST', '/api/auth/verify-otp', { body: { email: u.email, otp: '000000' } })).status);
  assert.deepEqual(codes, [400, 400, 400, 400, 429]);
  assert.equal(invalidations.length, 1);
  assert.ok(invalidations[0].$unset.emailOTP);
});

test('verify-otp: correct OTP is also refused once the cap is exceeded (cannot win by brute force)', async () => {
  const u = otpUser();
  mock.method(User, 'findOne', () => chain(u));
  mock.method(User, 'findOneAndUpdate', () => chain({ emailOTPAttempts: 6 }));
  mock.method(User, 'updateOne', async () => ({ modifiedCount: 1 }));
  const r = await app.call('POST', '/api/auth/verify-otp', { body: { email: u.email, otp: '123456' } });
  assert.equal(r.status, 429);
});

test('verify-otp: expired, already verified, unknown, operator injection', async () => {
  mock.method(User, 'findOne', () => chain(otpUser({ emailOTPExpires: new Date(Date.now() - 1000) })));
  assert.equal((await app.call('POST', '/api/auth/verify-otp', { body: { email: 'a@brainwareuniversity.ac.in', otp: '123456' } })).json.message, 'OTP expired.');
  mock.restoreAll();
  mock.method(User, 'findOne', () => chain(makeUser({ isVerified: true })));
  assert.equal((await app.call('POST', '/api/auth/verify-otp', { body: { email: 'a@brainwareuniversity.ac.in', otp: '1' } })).json.message, 'Account already verified.');
  mock.restoreAll();
  mock.method(User, 'findOne', () => chain(null));
  assert.equal((await app.call('POST', '/api/auth/verify-otp', { body: { email: 'a@brainwareuniversity.ac.in', otp: '1' } })).status, 404);
  const inj = await app.call('POST', '/api/auth/verify-otp', { body: { email: { $gt: '' }, otp: { $gt: '' } } });
  assert.equal(inj.status, 400);
});

test('resend-otp: cooldown -> 429; allowed -> 200 + mail; unknown -> 404', async () => {
  const sent = h.stubMail();
  const u = otpUser({ emailOTPLastSentAt: new Date() });
  mock.method(User, 'findOne', () => chain(u));
  mock.method(User, 'findOneAndUpdate', () => chain(null));            // slot not claimed (inside cooldown)
  const r1 = await app.call('POST', '/api/auth/resend-otp', { body: { email: u.email } });
  assert.equal(r1.status, 429);
  assert.match(r1.json.message, /wait \d+ seconds/);
  mock.restoreAll();
  h.stubMail();
  mock.method(User, 'findOne', () => chain(u));
  mock.method(User, 'findOneAndUpdate', () => chain(u));               // claimed
  const sent2 = h.stubMail();
  const r2 = await app.call('POST', '/api/auth/resend-otp', { body: { email: u.email } });
  assert.equal(r2.status, 200);
  assert.equal(r2.json.message, 'OTP resent successfully.');
  assert.equal(sent2.length, 1);
  mock.restoreAll();
  mock.method(User, 'findOne', () => chain(null));
  assert.equal((await app.call('POST', '/api/auth/resend-otp', { body: { email: 'x@brainwareuniversity.ac.in' } })).status, 404);
});

test('login: success returns user (no secrets) + HS256 token with env expiry', async () => {
  const pw = await bcrypt.hash('secret1', 4);
  const u = makeUser({ password: pw, studentCode: 'S9', phoneNumber: '9876543210', resetPasswordToken: 'leak?' });
  mock.method(User, 'findOne', () => chain(u));
  const r = await app.call('POST', '/api/auth/login', { body: { email: u.email, password: 'secret1' } });
  assert.equal(r.status, 200);
  assert.equal(r.json.message, 'Login successful');
  for (const k of ['password', 'emailOTP', 'resetPasswordToken', 'resetPasswordExpires']) assert.equal(k in r.json.user, false);
  assert.equal(r.json.user.studentCode, 'S9');
  assert.equal(r.json.user.phoneNumber, '9876543210');
  const d = jwt.decode(r.json.token, { complete: true });
  assert.equal(d.header.alg, 'HS256');
  assert.equal(d.payload.exp - d.payload.iat, 7200);
});

test('login: wrong password 401, unknown 401, unverified 403, missing 400, injection 400', async () => {
  const pw = await bcrypt.hash('secret1', 4);
  mock.method(User, 'findOne', () => chain(makeUser({ password: pw })));
  assert.equal((await app.call('POST', '/api/auth/login', { body: { email: 'a@brainwareuniversity.ac.in', password: 'nope' } })).status, 401);
  mock.restoreAll();
  mock.method(User, 'findOne', () => chain(null));
  assert.equal((await app.call('POST', '/api/auth/login', { body: { email: 'a@brainwareuniversity.ac.in', password: 'x' } })).status, 401);
  mock.restoreAll();
  mock.method(User, 'findOne', () => chain(makeUser({ isVerified: false, password: pw })));
  assert.equal((await app.call('POST', '/api/auth/login', { body: { email: 'a@brainwareuniversity.ac.in', password: 'secret1' } })).status, 403);
  assert.equal((await app.call('POST', '/api/auth/login', { body: {} })).status, 400);
  assert.equal((await app.call('POST', '/api/auth/login', { body: { email: { $ne: null }, password: { $ne: null } } })).status, 400);
});

test('forgot-password: identical generic answer for unknown email, known email, and mail failure', async () => {
  const msg = 'If an account exists, a link was sent.';
  mock.method(User, 'findOne', () => chain(null));
  assert.deepEqual((await app.call('POST', '/api/auth/forgot-password', { body: { email: 'none@brainwareuniversity.ac.in' } })).json, { message: msg });
  mock.restoreAll();
  const sent = h.stubMail();
  const u = makeUser();
  let stored;
  mock.method(User, 'findOne', () => chain(u));
  mock.method(User, 'updateOne', async (f, upd) => { stored = upd; return {}; });
  const ok = await app.call('POST', '/api/auth/forgot-password', { body: { email: u.email } });
  assert.deepEqual(ok.json, { message: msg });
  assert.equal(sent.length, 1);
  assert.match(sent[0].html, /http:\/\/frontend\.test\/reset-password\/[a-f0-9]{64}/);
  const token = sent[0].html.match(/reset-password\/([a-f0-9]{64})/)[1];
  assert.equal(stored.$set.resetPasswordToken, hashToken(token));      // only the hash is stored
  assert.ok(stored.$set.resetPasswordExpires > new Date());
  h.stubMail({ fail: true });                                           // mail failure must not reveal the account exists
  const failed = await app.call('POST', '/api/auth/forgot-password', { body: { email: u.email } });
  assert.equal(failed.status, 200);
  assert.deepEqual(failed.json, { message: msg });
});

test('reset-password: weak password 400, bad token format 400, expired 400, success 200 + token single-use', async () => {
  const token = 'a'.repeat(64);
  assert.equal((await app.call('POST', `/api/auth/reset-password/${token}`, { body: { password: '123' } })).status, 400);
  assert.equal((await app.call('POST', `/api/auth/reset-password/${token}`, { body: {} })).json.message, 'Password is required');
  assert.equal((await app.call('POST', '/api/auth/reset-password/not-a-token', { body: { password: 'secret1' } })).json.message, 'Invalid or expired token');
  mock.method(User, 'findOne', () => chain(null));
  assert.equal((await app.call('POST', `/api/auth/reset-password/${token}`, { body: { password: 'secret1' } })).json.message, 'Invalid or expired token');
  mock.restoreAll();
  const u = makeUser();
  let upd;
  mock.method(User, 'findOne', () => chain(u));
  mock.method(User, 'updateOne', async (f, x) => { upd = { f, x }; return { modifiedCount: 1 }; });
  const ok = await app.call('POST', `/api/auth/reset-password/${token}`, { body: { password: 'brandnew1' } });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.message, 'Password reset successful');
  assert.equal(upd.f.resetPasswordToken, hashToken(token));             // update only matches while the same token is stored
  assert.ok(await bcrypt.compare('brandnew1', upd.x.$set.password));
  assert.ok(upd.x.$unset.resetPasswordToken);
});

test('Google OAuth: callback redirects to FRONTEND_URL with token+user exactly as App.tsx parses them', async () => {
  const u = makeUser({ studentCode: 'G1', phoneNumber: '9876543210', role: 'admin' });
  mock.method(passport, 'authenticate', (strategy, opts, cb) => (req, res, next) => cb(null, u));
  const r = await app.call('GET', '/api/auth/google/callback?code=x');
  assert.equal(r.status, 302);
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.origin, 'http://frontend.test');                      // no hardcoded localhost
  // --- same steps as the frontend (App.tsx) ---
  const token = loc.searchParams.get('token');
  const userParam = loc.searchParams.get('user');
  const user = JSON.parse(decodeURIComponent(userParam));
  assert.ok(token && user);
  assert.equal(user._id, String(u._id));
  assert.equal(user.role, 'admin');
  assert.equal(user.studentCode, 'G1');
  assert.equal(user.phoneNumber, '******3210');                          // masked in the URL
  assert.equal('password' in user, false);
  assert.equal(jwt.verify(token, process.env.JWT_SECRET).id, String(u._id));
});

test('Google OAuth: error redirects use the codes the frontend understands', async () => {
  mock.method(passport, 'authenticate', (s, o, cb) => (req, res, next) => cb(null, false, { message: passport.DOMAIN_ERROR }));
  assert.equal(new URL((await app.call('GET', '/api/auth/google/callback')).headers.get('location')).searchParams.get('error'), 'invalid_email');
  mock.restoreAll();
  mock.method(passport, 'authenticate', (s, o, cb) => (req, res, next) => cb(null, false, { message: 'Account not found. Please sign up first.' }));
  assert.equal(new URL((await app.call('GET', '/api/auth/google/callback')).headers.get('location')).searchParams.get('error'), 'no_account');
  mock.restoreAll();
  mock.method(passport, 'authenticate', (s, o, cb) => (req, res, next) => cb(new Error('boom')));
  const r = await app.call('GET', '/api/auth/google/callback');
  assert.equal(new URL(r.headers.get('location')).searchParams.get('error'), 'server');
  assert.equal(new URL(r.headers.get('location')).origin, 'http://frontend.test');
  const denied = await app.call('GET', '/api/auth/google/callback?error=access_denied');
  assert.equal(new URL(denied.headers.get('location')).searchParams.get('error'), 'denied');
});

test('Google OAuth: /auth/google redirects to Google when configured', async () => {
  const r = await app.call('GET', '/api/auth/google');
  assert.equal(r.status, 302);
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.hostname, 'accounts.google.com');
  assert.equal(loc.searchParams.get('redirect_uri'), process.env.GOOGLE_CALLBACK_URL);   // GOOGLE_CALLBACK_URL is used
  assert.equal(loc.searchParams.get('client_id'), 'test-client-id');
});

test('unknown route -> JSON 404 with { message }; security headers present; CORS limited to frontend', async () => {
  const r = await app.call('GET', '/api/nope', { headers: { origin: 'http://frontend.test' } });
  assert.equal(r.status, 404);
  assert.equal(r.json.message, 'Route not found.');
  assert.ok(r.headers.get('x-content-type-options'));
  assert.equal(r.headers.get('x-powered-by'), null);
  assert.equal(r.headers.get('access-control-allow-origin'), 'http://frontend.test');
  const evil = await app.call('GET', '/api/nope', { headers: { origin: 'http://evil.test' } });
  assert.notEqual(evil.headers.get('access-control-allow-origin'), 'http://evil.test');
});

test('malformed JSON / oversized body -> controlled 4xx with { message }', async () => {
  const bad = await fetch(`${app.base}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{oops' });
  assert.equal(bad.status, 400);
  assert.equal(typeof (await bad.json()).message, 'string');
  const big = await fetch(`${app.base}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'x'.repeat(20000), password: 'y' }) });
  assert.equal(big.status, 413);
});
