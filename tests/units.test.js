require('./helpers');
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');

const escapeHtml = require('../src/utils/escapeHtml');
const escapeRegex = require('../src/utils/escapeRegex');
const { generateOtp, hashOtp, otpMatches } = require('../src/utils/otp');
const { signToken, DEFAULT_EXPIRES_IN } = require('../src/utils/token');
const { serializeUser, serializeUserForUrl, maskPhone } = require('../src/utils/serializeUser');
const { createLimiter } = require('../src/middlewares/rateLimiters');
const sanitize = require('../src/middlewares/sanitize');
const { errorHandler } = require('../src/middlewares/errorHandler');
const HttpError = require('../src/utils/httpError');
const emailService = require('../src/services/email/email.service');
const productEmail = require('../src/services/email/product.email');
const bookingEmail = require('../src/services/email/booking.email');
const { _validateProductInput: validateProduct } = require('../src/controllers/product.controller');
const { parseBookingRequest } = require('../src/services/booking.service');
const { makeUser, makeProduct, makeBooking, oid } = require('./helpers');
const jwt = require('jsonwebtoken');

test('escapeHtml neutralises markup', () => {
  assert.equal(escapeHtml('<img src=x onerror="a()">&\''), '&lt;img src=x onerror=&quot;a()&quot;&gt;&amp;&#39;');
  assert.equal(escapeHtml(undefined), '');
});

test('escapeRegex makes metacharacters literal and produces valid patterns', () => {
  for (const evil of ['(', '[', '.*', '(a+)+$', 'a|b', '\\', '$^']) {
    const re = new RegExp(escapeRegex(evil), 'i');
    assert.ok(re.test(evil), `pattern for ${evil} should match itself literally`);
  }
  assert.equal(new RegExp(`^${escapeRegex('C++')}$`, 'i').test('c++'), true);
  assert.equal(new RegExp(escapeRegex('.*')).test('anything'), false);
});

test('OTP: 6 digits, hashed, constant-time compare', () => {
  for (let i = 0; i < 200; i++) assert.match(generateOtp(), /^\d{6}$/);
  const h = hashOtp('123456');
  assert.equal(otpMatches('123456', h), true);
  assert.equal(otpMatches('123457', h), false);
  assert.equal(otpMatches({ $ne: 1 }, h), false);
});

test('JWT: HS256 and expiry from JWT_EXPIRES_IN', () => {
  const t = signToken(oid());
  const { header, payload } = jwt.decode(t, { complete: true });
  assert.equal(header.alg, 'HS256');
  assert.equal(payload.exp - payload.iat, 2 * 3600); // JWT_EXPIRES_IN=2h in the test env
  const saved = process.env.JWT_EXPIRES_IN;
  delete process.env.JWT_EXPIRES_IN;
  const d = jwt.decode(signToken(oid()));
  assert.equal(d.exp - d.iat, 7 * 24 * 3600);
  assert.equal(DEFAULT_EXPIRES_IN, '7d');
  process.env.JWT_EXPIRES_IN = saved;
});

test('serializeUser never leaks secrets; keeps every field the frontend reads', () => {
  const u = makeUser({ studentCode: 'S1', phoneNumber: '9876543210', emailOTP: 'h', resetPasswordToken: 'r', emailOTPAttempts: 3 });
  const out = serializeUser(u);
  for (const k of ['password', 'emailOTP', 'emailOTPExpires', 'emailOTPAttempts', 'resetPasswordToken', 'resetPasswordExpires', '__v']) {
    assert.equal(k in out, false, `${k} must not be serialized`);
  }
  for (const k of ['_id', 'name', 'email', 'role', 'avatar', 'studentCode', 'programType', 'department', 'year', 'phoneNumber', 'contactPreference']) {
    assert.ok(k in out, `${k} must be present`);
  }
  // Defence in depth: raw res.json(userDoc) is also safe thanks to the schema toJSON transform.
  const viaJson = JSON.parse(JSON.stringify(u));
  assert.equal('password' in viaJson, false);
  assert.equal('emailOTP' in viaJson, false);
});

test('Google redirect user blob masks the phone number', () => {
  const blob = serializeUserForUrl(makeUser({ phoneNumber: '9876543210' }));
  assert.equal(blob.phoneNumber, '******3210');
  assert.equal(maskPhone(null), null);
  assert.equal('password' in blob, false);
});

test('sanitize rejects operator objects in body, accepts normal payloads', async () => {
  const run = (body, params = {}) => new Promise((resolve) => {
    const res = { status(c) { this.code = c; return this; }, json(j) { resolve({ code: this.code, j }); } };
    sanitize({ body, params }, res, () => resolve({ code: 'next' }));
  });
  assert.equal((await run({ price: { $gt: 0 } })).code, 400);
  assert.equal((await run({ role: { $ne: 'student' } })).code, 400);
  assert.equal((await run({ a: [{ $where: '1' }] })).code, 400);
  assert.equal((await run({ 'a.b': 1 })).code, 400);
  assert.equal((await run({ email: 'a@b.c', products: [{ productId: 'x', quantity: 2 }] })).code, 'next');
  assert.equal((await run(undefined)).code, 'next');
});

test('errorHandler: consistent { message } shape and sensible statuses', async () => {
  const render = (err) => new Promise((resolve) => {
    const res = { headersSent: false, status(c) { this.code = c; return this; }, json(j) { resolve({ code: this.code, j }); } };
    errorHandler(err, { method: 'GET', originalUrl: '/x' }, res, () => {});
  });
  assert.deepEqual(await render(new HttpError(409, 'dup', { needsVerification: true })), { code: 409, j: { message: 'dup', needsVerification: true } });
  const cast = Object.assign(new Error('x'), { name: 'CastError', path: '_id' });
  assert.equal((await render(cast)).code, 400);
  assert.equal((await render(Object.assign(new Error('E11000 dup key {email}'), { code: 11000 }))).code, 409);
  assert.equal((await render(Object.assign(new Error('big'), { name: 'MulterError', code: 'LIMIT_FILE_SIZE' }))).code, 413);
  assert.equal((await render(Object.assign(new Error('bad'), { name: 'JsonWebTokenError' }))).code, 401);
  const r = await render(new Error('secret db detail'));
  assert.equal(r.code, 500);
  assert.equal(typeof r.j.message, 'string');
  // production: no internal detail
  const prev = process.env.NODE_ENV; process.env.NODE_ENV = 'production';
  assert.equal((await render(new Error('secret db detail'))).j.message, 'Internal server error.');
  process.env.NODE_ENV = prev;
});

test('rate limiter answers 429 with { message } after the limit', async () => {
  const app = express();
  app.use(createLimiter({ windowMs: 60000, max: 3, message: 'slow down' }));
  app.get('/', (req, res) => res.json({ ok: true }));
  const server = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
  const url = `http://127.0.0.1:${server.address().port}/`;
  const codes = [];
  for (let i = 0; i < 5; i++) codes.push((await fetch(url)).status);
  const last = await fetch(url);
  assert.deepEqual(codes, [200, 200, 200, 429, 429]);
  assert.deepEqual(await last.json(), { message: 'slow down' });
  await new Promise((r) => server.close(r));
});

test('email: sendSafe never throws, dispatch is independent per mail', async () => {
  const sent = [];
  let n = 0;
  emailService.setTransporter({ sendMail: async (m) => { n++; if (m.to === 'bad@x') throw new Error('boom'); sent.push(m.to); } });
  assert.equal(await emailService.sendSafe({ to: 'bad@x', subject: 's', html: 'h' }), false);
  assert.equal(await emailService.sendSafe({ to: '', subject: 's', html: 'h' }), false); // no recipient
  const res = await emailService.dispatch([{ to: 'a@x', subject: 's', html: 'h' }, { to: 'bad@x', subject: 's', html: 'h' }, { to: 'c@x', subject: 's', html: 'h' }]);
  assert.deepEqual(res, [true, false, true]);
  assert.deepEqual(sent, ['a@x', 'c@x']);
  await assert.rejects(emailService.sendEmail({ to: 'bad@x', subject: 's', html: 'h' })); // sendEmail itself still throws
});

test('email templates escape user-controlled data (HTML injection)', () => {
  const evil = '<script>alert(1)</script>';
  const seller = { name: evil, email: 'a@b.c', _id: oid() };
  const product = makeProduct({ title: evil });
  const html = productEmail.buildProductSubmitted({ seller, product }).map((m) => m.html).join('');
  assert.equal(html.includes('<script>'), false);
  assert.ok(html.includes('&lt;script&gt;'));
  const booking = makeBooking({ buyerName: evil });
  booking.products[0].title = evil;
  const bh = bookingEmail.buildBookingCreated({ buyer: { name: evil, email: 'b@c.d' }, booking }).map((m) => m.html).join('');
  assert.equal(bh.includes('<script>'), false);
});

test('booking emails list ALL items per seller (old code kept only the last)', () => {
  const booking = makeBooking();
  booking.products = [
    { productId: oid(), title: 'First', imageUrl: ['u'], quantity: 1, price: 10, sellerName: 'S', sellerEmail: 's@x.in' },
    { productId: oid(), title: 'Second', imageUrl: ['u'], quantity: 2, price: 20, sellerName: 'S', sellerEmail: 's@x.in' },
  ];
  const mails = bookingEmail.buildBookingCreated({ buyer: { name: 'B', email: 'b@x.in' }, booking });
  const sellerMails = mails.filter((m) => m.label === 'booking-created (seller)');
  assert.equal(sellerMails.length, 1);
  assert.ok(sellerMails[0].html.includes('First') && sellerMails[0].html.includes('Second'));
});

test('product input validation', () => {
  const ok = validateProduct({ title: ' T ', description: 'd', category: 'Books', price: '12.5', quantity: '2' });
  assert.deepEqual(ok, { title: 'T', description: 'd', category: 'Books', price: 12.5, quantity: 2 });
  const bad = [
    { title: '', description: 'd', category: 'c', price: 1, quantity: 1 },
    { title: 't', description: 'd', category: 'c', price: 0, quantity: 1 },
    { title: 't', description: 'd', category: 'c', price: -5, quantity: 1 },
    { title: 't', description: 'd', category: 'c', price: 'abc', quantity: 1 },
    { title: 't', description: 'd', category: 'c', price: { $gt: 0 }, quantity: 1 },
    { title: 't', description: 'd', category: 'c', price: 1, quantity: 1.5 },
    { title: 't', description: 'd', category: 'c', price: 1, quantity: 0 },
    { title: { a: 1 }, description: 'd', category: 'c', price: 1, quantity: 1 },
    { description: 'd', category: 'c', price: 1, quantity: 1 },
  ];
  for (const b of bad) assert.throws(() => validateProduct(b), (e) => e.status === 400, JSON.stringify(b));
  // partial (edit): only provided fields are checked
  assert.deepEqual(validateProduct({ price: 5 }, { partial: true }), { price: 5 });
  assert.throws(() => validateProduct({ quantity: -1 }, { partial: true }), (e) => e.status === 400);
});

test('booking request parsing: client price/total/seller fields are ignored', () => {
  const id = oid().toString();
  const items = parseBookingRequest({
    totalPrice: 1, products: [{ productId: id, quantity: 2, price: 0.01, title: 'x', sellerEmail: 'evil@x', imageUrl: ['x'] }],
  });
  assert.deepEqual(items, [{ productId: id, quantity: 2 }]);
  assert.deepEqual(parseBookingRequest({ products: [{ productId: id }] }), [{ productId: id, quantity: 1 }]); // default kept
  const a = oid().toString();
  const bad = [
    undefined, {}, { products: [] }, { products: 'x' },
    { products: [{ productId: 'nope', quantity: 1 }] },
    { products: [{ productId: { $ne: null }, quantity: 1 }] },
    { products: [{ productId: a, quantity: 0 }] },
    { products: [{ productId: a, quantity: -3 }] },
    { products: [{ productId: a, quantity: 1.5 }] },
    { products: [{ productId: a, quantity: 'many' }] },
    { products: [{ productId: a, quantity: 1000 }] },
    { products: [{ productId: a, quantity: 1 }, { productId: a, quantity: 2 }] }, // duplicate
    { products: Array.from({ length: 21 }, () => ({ productId: oid().toString(), quantity: 1 })) }, // too many
  ];
  for (const b of bad) assert.throws(() => parseBookingRequest(b), (e) => e.status === 400, JSON.stringify(b));
});
