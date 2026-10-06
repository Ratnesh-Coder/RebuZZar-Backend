const h = require('./helpers');
const { test, afterEach, after, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { attach } = require('./fakedb');
const { signToken } = require('../src/utils/token');
const Cart = require('../src/models/Cart');

const { mock, oid, makeUser, makeProduct, User, Product, Booking } = h;
let app, db;
before(async () => { app = await h.startApp(); });
after(async () => { await app.close(); });
beforeEach(() => { db = attach([User, Product, Booking, Cart]); });
afterEach(() => mock.restoreAll());

const BAD_IDS = ['not-an-id', 'null', 'undefined', '{}', '12345', 'a'.repeat(300), '%00', '..%2f..%2fetc%2fpasswd', '507f1f77bcf86cd79943901', '507f1f77bcf86cd7994390111', '507f1f77bcf86cd79943901z'];
const LEAK = /CastError|MongoServerError|MongooseError|BSONError|ObjectId|stack|\bat\s+\S+\s+\(|node_modules|\.js:\d+/;

test('malformed ids on every :id endpoint -> predictable { message }, 400/404, and NO database access at all', async () => {
  const user = db.seed(User, makeUser());
  const admin = db.seed(User, makeUser({ email: 'adm@brainwareuniversity.ac.in', role: 'admin' }));
  const t = signToken(user._id), at = signToken(admin._id);
  const endpoints = [
    ['GET', (id) => `/api/products/${id}`, null, false],
    ['PUT', (id) => `/api/products/${id}`, { title: 'x' }, false],
    ['DELETE', (id) => `/api/products/${id}`, undefined, false],
    ['GET', (id) => `/api/bookings/${id}`, undefined, false],
    ['PUT', (id) => `/api/bookings/${id}/cancel`, undefined, false],
    ['PUT', (id) => `/api/admin/products/${id}/status`, { status: 'approved' }, true],
    ['PUT', (id) => `/api/cart/item/${id}`, { quantity: 1 }, false],
    ['DELETE', (id) => `/api/cart/item/${id}`, undefined, false],
  ];
  const touched = () => ['products', 'bookings', 'carts'].reduce((n, c) => n + db.store[c].length, 0);
  let calls = 0;
  for (const Model of [Product, Booking, Cart]) for (const op of ['find', 'findOne', 'updateOne', 'updateMany', 'findOneAndUpdate', 'deleteOne', 'insertOne']) {
    const orig = Model.collection[op];
    mock.method(Model.collection, op, async (...a) => { calls++; return orig(...a); });
  }
  for (const [method, url, body, asAdmin] of endpoints) {
    for (const id of BAD_IDS) {
      const r = await app.call(method, url(id), { token: asAdmin ? at : t, body: body === null ? undefined : body });
      const label = `${method} ${url(id.slice(0, 20))}`;
      assert.ok([400, 404].includes(r.status), `${label} -> ${r.status}`);
      assert.deepEqual(Object.keys(r.json), ['message'], label);
      assert.equal(typeof r.json.message, 'string', label);
      assert.doesNotMatch(JSON.stringify(r.json), LEAK, label);
    }
  }
  assert.equal(calls, 0, 'malformed ids must be rejected before any products/bookings/carts query');
  assert.equal(touched(), 0);
});

test('well-formed but unknown ids -> 404 { message }', async () => {
  const user = db.seed(User, makeUser()); const admin = db.seed(User, makeUser({ email: 'adm@brainwareuniversity.ac.in', role: 'admin' }));
  const t = signToken(user._id), at = signToken(admin._id); const id = String(oid());
  const cases = [
    ['GET', `/api/products/${id}`, t], ['PUT', `/api/products/${id}`, t, { title: 'x' }], ['DELETE', `/api/products/${id}`, t],
    ['GET', `/api/bookings/${id}`, t], ['PUT', `/api/bookings/${id}/cancel`, t], ['PUT', `/api/admin/products/${id}/status`, at, { status: 'approved' }],
  ];
  for (const [m, u, token, body] of cases) {
    const r = await app.call(m, u, { token, body });
    assert.equal(r.status, 404, `${m} ${u}`);
    assert.deepEqual(Object.keys(r.json), ['message']);
  }
});

test('driver / database errors never leak internals in production; dev shows the message but never a stack', async () => {
  const secretMsg = 'connection to mongodb://dbuser:TOPSECRET@cluster0.example.mongodb.net failed: E11000 duplicate key';
  mock.method(Product.collection, 'find', () => { const e = new Error(secretMsg); e.name = 'MongoServerError'; e.stack = 'MongoServerError: ...\n    at secret (/srv/app/node_modules/mongodb/lib/x.js:1:1)'; throw e; });
  const prev = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = 'production';
    const prod = await app.call('GET', '/api/products');
    assert.equal(prod.status, 500);
    assert.deepEqual(prod.json, { message: 'Internal server error.' });
    assert.doesNotMatch(JSON.stringify(prod.json), /TOPSECRET|mongodb|stack|node_modules/);
    process.env.NODE_ENV = 'development';
    const dev = await app.call('GET', '/api/products');
    assert.equal(dev.status, 500);
    assert.deepEqual(Object.keys(dev.json), ['message']);
    assert.doesNotMatch(JSON.stringify(dev.json), /node_modules|\.js:\d+|stack/);
  } finally { process.env.NODE_ENV = prev; }
});

test('duplicate-key at the driver (race on signup) is a 409, not a 500', async () => {
  mock.method(User.collection, 'insertOne', async () => { const e = new Error('E11000 duplicate key error collection: x index: email_1 dup key: { email: "a@b" }'); e.name = 'MongoServerError'; e.code = 11000; throw e; });
  h.stubMail();
  const r = await app.call('POST', '/api/auth/signup', { body: { name: 'N', email: 'race@brainwareuniversity.ac.in', password: 'secret12', programType: 'UG', department: 'CSE', year: '1st Year' } });
  assert.equal(r.status, 409);
  assert.doesNotMatch(JSON.stringify(r.json), /E11000|index|dup key/);
});

test('every error body the frontend can receive has a top-level string message (sampled across areas)', async () => {
  const user = db.seed(User, makeUser()); const t = signToken(user._id);
  const samples = [
    app.call('GET', '/api/cart'), app.call('POST', '/api/auth/login', { body: {} }), app.call('GET', '/api/nope'),
    app.call('POST', '/api/bookings/create', { token: t, body: {} }), app.call('PUT', '/api/users/contact', { token: t, body: {} }),
    app.call('GET', '/api/admin/products/pending', { token: t }), app.call('POST', '/api/cart/add', { token: t, body: {} }),
    app.call('PUT', '/api/profile', { token: t, body: { programType: 'X' } }), app.call('GET', '/api/products', { headers: { authorization: 'Bearer garbage' } }),
    app.call('GET', '/api/cart', { headers: { authorization: 'Bearer garbage' } }),
  ];
  for (const r of await Promise.all(samples)) {
    if (r.status < 400) continue;
    assert.equal(typeof r.json.message, 'string', `${r.status} ${JSON.stringify(r.json)}`);
  }
});
