/**
 * Multi-request SCENARIOS on a stateful in-memory fake of the MongoDB driver (see fakedb.js).
 * Real app, real middleware, real controllers, real Mongoose models - only the driver is simulated.
 * These prove request-level behaviour and state transitions; they do NOT prove MongoDB-server semantics.
 */
const h = require('./helpers');
const { test, afterEach, after, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const { attach } = require('./fakedb');
const { hashOtp } = require('../src/utils/otp');
const { signToken } = require('../src/utils/token');

const { mock, oid, makeUser, makeProduct, User, Product, Booking } = h;
const Cart = require('../src/models/Cart');
let app, db;
before(async () => { app = await h.startApp(); });
after(async () => { await app.close(); });
beforeEach(() => { db = attach([User, Product, Booking, Cart]); });
afterEach(() => mock.restoreAll());

const tick = () => new Promise((r) => setTimeout(r, 60));
const tok = (u) => signToken(u._id);
const seedUser = (over = {}) => db.seed(User, makeUser(over));
const seedProduct = (over = {}) => db.seed(Product, makeProduct(over));
const row = (Model, id) => db.store[Model.collection.name].find((d) => String(d._id) === String(id));

/* ------------------------------------------------------------------ OTP */

test('SCENARIO OTP brute force: cap enforced, OTP invalidated for good, correct code refused afterwards, resend restores a clean slate', async () => {
  const sent = h.stubMail();
  const OTP = '424242';
  const user = seedUser({ isVerified: false, emailOTP: hashOtp(OTP), emailOTPExpires: new Date(Date.now() + 600000), emailOTPAttempts: 0, emailOTPLastSentAt: new Date() });
  const verify = (otp) => app.call('POST', '/api/auth/verify-otp', { body: { email: user.email, otp } });

  const wrong = [];
  for (let i = 0; i < 5; i++) wrong.push((await verify(String(100000 + i))).status);
  assert.deepEqual(wrong, [400, 400, 400, 400, 429], 'five wrong guesses, the fifth locks the OTP');
  assert.equal(row(User, user._id).emailOTP, undefined, 'OTP hash is wiped after the cap');

  const late = await verify(OTP);                                        // attacker gets lucky AFTER the cap
  assert.equal(late.status, 400);
  assert.equal(row(User, user._id).isVerified, false, 'a correct code after lock-out must NOT verify the account');

  const tooSoon = await app.call('POST', '/api/auth/resend-otp', { body: { email: user.email } });
  assert.equal(tooSoon.status, 429, 'resend is rate-limited by the cooldown');
  assert.match(tooSoon.json.message, /wait \d+ seconds/);

  row(User, user._id).emailOTPLastSentAt = new Date(Date.now() - 61000);   // time passes
  const resend = await app.call('POST', '/api/auth/resend-otp', { body: { email: user.email } });
  assert.equal(resend.status, 200);
  assert.equal(row(User, user._id).emailOTPAttempts, 0, 'attempt counter reset by a fresh OTP');
  const fresh = sent.at(-1).html.match(/<h2>(\d{6})<\/h2>/)[1];
  assert.equal((await verify(fresh)).status, 200);
  assert.equal(row(User, user._id).isVerified, true);
  assert.equal(row(User, user._id).emailOTP, undefined);
  assert.equal(row(User, user._id).emailOTPAttempts, undefined);
});

test('SCENARIO OTP: parallel guesses cannot exceed the attempt cap', async () => {
  const user = seedUser({ isVerified: false, emailOTP: hashOtp('777777'), emailOTPExpires: new Date(Date.now() + 600000), emailOTPAttempts: 0 });
  const results = await Promise.all(Array.from({ length: 8 }, (_, i) => app.call('POST', '/api/auth/verify-otp', { body: { email: user.email, otp: String(200000 + i) } })));
  const counted = results.filter((r) => r.status === 400 || r.status === 429).length;
  assert.equal(counted, 8);
  assert.equal(results.filter((r) => r.status === 200).length, 0);
  assert.equal(row(User, user._id).isVerified, false);
});

/* ------------------------------------------------------------------ BOOKING */

const bookingFixture = () => {
  const seller = seedUser({ name: 'Real Seller', email: 'real.seller@brainwareuniversity.ac.in' });
  const A = seedUser({ name: 'User A', email: 'a@brainwareuniversity.ac.in' });
  const B = seedUser({ name: 'User B', email: 'b@brainwareuniversity.ac.in' });
  const admin = seedUser({ name: 'Admin', email: 'admin@brainwareuniversity.ac.in', role: 'admin' });
  const product = seedProduct({ title: 'Real Book', price: 250, sellerId: seller._id, sellerName: 'Stale Snapshot', sellerEmail: 'stale@x.in' });
  return { seller, A, B, admin, product };
};

test('SCENARIO price manipulation (the exact payload from the brief): stored booking uses the database price and seller', async () => {
  h.stubMail();
  const { A, product } = bookingFixture();
  const r = await app.call('POST', '/api/bookings/create', { token: tok(A), body: {
    products: [{ productId: String(product._id), quantity: 1, price: 1, sellerName: 'Fake Seller', sellerEmail: 'attacker@example.com' }],
    totalPrice: 1,
  } });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const stored = row(Booking, r.json.bookingId);
  assert.equal(stored.totalPrice, 250, 'stored total must be the database price, not 1');
  assert.equal(stored.products[0].price, 250);
  assert.equal(stored.products[0].sellerName, 'Real Seller', 'seller name comes from the seller account');
  assert.equal(stored.products[0].sellerEmail, 'real.seller@brainwareuniversity.ac.in');
  assert.equal(stored.products[0].title, 'Real Book');
  assert.equal(String(stored.buyerId), String(A._id));
  assert.equal(row(Product, product._id).isBooked, true);
  await tick();
});

test('SCENARIO booking IDOR + cancellation ownership + admin access (User A vs User B)', async () => {
  const sent = h.stubMail();
  const { A, B, admin, product } = bookingFixture();
  const created = await app.call('POST', '/api/bookings/create', { token: tok(A), body: { products: [{ productId: String(product._id), quantity: 1 }] } });
  assert.equal(created.status, 201);
  const id = created.json.bookingId;
  await tick();

  // User B guesses/knows the id
  const peek = await app.call('GET', `/api/bookings/${id}`, { token: tok(B) });
  assert.equal(peek.status, 404);
  assert.deepEqual(peek.json, { message: 'Booking not found.' });
  const missing = await app.call('GET', `/api/bookings/${oid()}`, { token: tok(B) });
  assert.deepEqual(missing.json, peek.json, 'no existence oracle');
  const bList = await app.call('GET', '/api/bookings/my-bookings', { token: tok(B) });
  assert.deepEqual(bList.json, [], "B's list never contains A's booking");

  // owner and admin can read
  assert.equal((await app.call('GET', `/api/bookings/${id}`, { token: tok(A) })).status, 200);
  assert.equal((await app.call('GET', `/api/bookings/${id}`, { token: tok(admin) })).status, 200);
  assert.equal((await app.call('GET', '/api/bookings/my-bookings', { token: tok(A) })).json.length, 1);

  // B cannot cancel A's booking, nothing changes, nothing is emailed
  const mailsBefore = sent.length;
  const evil = await app.call('PUT', `/api/bookings/${id}/cancel`, { token: tok(B) });
  assert.equal(evil.status, 404);
  assert.equal(row(Booking, id).status, 'Booked');
  assert.equal(row(Product, product._id).isBooked, true, "B's failed cancel must not release A's product");
  await tick();
  assert.equal(sent.length, mailsBefore);

  // B cannot book the already-booked product
  assert.equal((await app.call('POST', '/api/bookings/create', { token: tok(B), body: { products: [{ productId: String(product._id), quantity: 1 }] } })).status, 400);
  // admin is not an implicit canceller
  assert.equal((await app.call('PUT', `/api/bookings/${id}/cancel`, { token: tok(admin) })).status, 404);

  // A cancels: product is released, second cancel refused
  const cancel = await app.call('PUT', `/api/bookings/${id}/cancel`, { token: tok(A) });
  assert.equal(cancel.status, 200);
  assert.equal(row(Booking, id).status, 'Cancelled');
  assert.equal(row(Product, product._id).isBooked, false);
  assert.equal((await app.call('PUT', `/api/bookings/${id}/cancel`, { token: tok(A) })).status, 400);

  // now B may book it - still at the database price
  const again = await app.call('POST', '/api/bookings/create', { token: tok(B), body: { totalPrice: 5, products: [{ productId: String(product._id), quantity: 1, price: 5 }] } });
  assert.equal(again.status, 201);
  assert.equal(row(Booking, again.json.bookingId).totalPrice, 250);
  await tick();
});

test('SCENARIO two buyers race for one product: exactly one booking wins, product locked once', async () => {
  h.stubMail();
  const { A, B, product } = bookingFixture();
  const body = { products: [{ productId: String(product._id), quantity: 1 }] };
  const [ra, rb] = await Promise.all([
    app.call('POST', '/api/bookings/create', { token: tok(A), body }),
    app.call('POST', '/api/bookings/create', { token: tok(B), body }),
  ]);
  const statuses = [ra.status, rb.status].sort();
  assert.ok(statuses[0] === 201 && statuses[1] >= 400 && statuses[1] < 500, `got ${statuses}`);
  assert.equal(db.store.bookings.length, 1, 'never two bookings for the same product (single-threaded fake: the conditional lock decides)');
  await tick();
});

test('SCENARIO unapproved products cannot be booked even by direct API calls', async () => {
  const { A } = bookingFixture();
  for (const status of ['pending', 'rejected']) {
    const p = seedProduct({ status });
    const r = await app.call('POST', '/api/bookings/create', { token: tok(A), body: { products: [{ productId: String(p._id), quantity: 1 }] } });
    assert.equal(r.status, 400, status);
    assert.equal(row(Product, p._id).isBooked, false);
  }
  const deleted = seedProduct({ isDeleted: true });
  assert.equal((await app.call('POST', '/api/bookings/create', { token: tok(A), body: { products: [{ productId: String(deleted._id), quantity: 1 }] } })).status, 400);
  assert.equal(db.store.bookings.length, 0);
});

/* ------------------------------------------------------------------ FULL JOURNEY (simulated) */

test('SIMULATED end-to-end journey: signup -> OTP verify -> login -> browse -> view -> book -> view -> cancel; admin approve/reject', async () => {
  const sent = h.stubMail();
  const seller = seedUser({ name: 'Journey Seller', email: 'journey.seller@brainwareuniversity.ac.in' });
  const approved = seedProduct({ title: 'Journey Book', price: 120, sellerId: seller._id });
  const pending = seedProduct({ title: 'Needs Review', status: 'pending', sellerId: seller._id });

  // register
  const email = 'journey.buyer@brainwareuniversity.ac.in';
  const signup = await app.call('POST', '/api/auth/signup', { body: { name: 'Journey Buyer', email, password: 'secret12', programType: 'UG', department: 'CSE', year: '1st Year' } });
  assert.equal(signup.status, 201);
  const otp = sent.at(-1).html.match(/letter-spacing: 4px;">(\d{6})</)[1];
  assert.equal((await app.call('POST', '/api/auth/login', { body: { email, password: 'secret12' } })).status, 403, 'unverified accounts cannot log in');
  // duplicate while unverified
  const dup = await app.call('POST', '/api/auth/signup', { body: { name: 'Journey Buyer', email, password: 'secret12', programType: 'UG', department: 'CSE', year: '1st Year' } });
  assert.equal(dup.status, 409); assert.equal(dup.json.needsVerification, true);
  // verify, login
  assert.equal((await app.call('POST', '/api/auth/verify-otp', { body: { email, otp } })).status, 200);
  const login = await app.call('POST', '/api/auth/login', { body: { email, password: 'secret12' } });
  assert.equal(login.status, 200);
  assert.equal('password' in login.json.user && 'emailOTP' in login.json.user, false);
  const token = login.json.token;
  // verified duplicate
  assert.equal((await app.call('POST', '/api/auth/signup', { body: { name: 'x', email, password: 'secret12', programType: 'UG', department: 'CSE', year: '1st Year' } })).status, 409);

  // browse + detail (pending hidden from the list but readable by id)
  const list = await app.call('GET', '/api/products');
  assert.deepEqual(list.json.map((p) => p.title), ['Journey Book']);
  assert.equal('sellerEmail' in list.json[0], false);
  const detail = await app.call('GET', `/api/products/${approved._id}`);
  assert.equal(detail.json.title, 'Journey Book');
  assert.equal((await app.call('GET', `/api/products/${pending._id}`)).status, 200);

  // book -> view -> list -> cancel
  const book = await app.call('POST', '/api/bookings/create', { token, body: { products: [{ productId: String(approved._id), quantity: 1 }] } });
  assert.equal(book.status, 201);
  assert.equal(book.json.booking.totalPrice, 120);
  assert.equal((await app.call('GET', `/api/products/${approved._id}`)).json.isBooked, true);
  assert.equal((await app.call('GET', `/api/bookings/${book.json.bookingId}`, { token })).json.products[0].title, 'Journey Book');
  assert.equal((await app.call('GET', '/api/bookings/my-bookings', { token })).json.length, 1);
  assert.equal((await app.call('PUT', `/api/bookings/${book.json.bookingId}/cancel`, { token })).status, 200);
  assert.equal((await app.call('GET', `/api/products/${approved._id}`)).json.isBooked, false);
  await tick();

  // admin
  const admin = seedUser({ name: 'Boss', email: 'boss@brainwareuniversity.ac.in', role: 'admin' });
  const at = tok(admin);
  assert.equal((await app.call('GET', '/api/admin/products/pending', { token })).status, 403);
  const queue = await app.call('GET', '/api/admin/products/pending', { token: at });
  assert.deepEqual(queue.json.map((p) => p.title), ['Needs Review']);
  assert.equal(queue.json[0].sellerId.email, 'journey.seller@brainwareuniversity.ac.in', 'admin UI reads sellerId.email');
  assert.equal((await app.call('PUT', `/api/admin/products/${pending._id}/status`, { token: at, body: { status: 'approved' } })).status, 200);
  assert.equal(row(Product, pending._id).status, 'approved');
  assert.equal((await app.call('GET', '/api/products')).json.length, 2, 'approved product is now public');
  assert.equal((await app.call('PUT', `/api/admin/products/${pending._id}/status`, { token: at, body: { status: 'rejected' } })).status, 200);
  assert.equal((await app.call('GET', '/api/products')).json.length, 1);
  await tick();
});

test('SCENARIO delete/book race: a product booked right after the seller\'s lookup is soft-deleted AND the buyer is notified', async () => {
  const sent = h.stubMail();
  const seller = seedUser({ email: 'race.seller@brainwareuniversity.ac.in' });
  const buyer = seedUser({ email: 'race.buyer@brainwareuniversity.ac.in', name: 'Race Buyer' });
  const p = seedProduct({ sellerId: seller._id, isBooked: false });
  // The booking is committed between the controller's first booking lookup and its delete attempt.
  const real = Booking.collection.findOne;
  let lookups = 0;
  mock.method(Booking.collection, 'findOne', async (f, o) => {
    lookups++;
    if (lookups === 1) {                                        // first lookup: nothing yet ...
      row(Product, p._id).isBooked = true;                      // ... then the buyer's booking lands
      db.store.bookings.push({ _id: oid(), buyerId: buyer._id, buyerName: buyer.name, buyerEmail: buyer.email, status: 'Booked', totalPrice: 1,
        products: [{ productId: p._id, title: p.title, quantity: 1, price: 1, sellerName: 'S', sellerEmail: 's@x.in', imageUrl: ['u'] }] });
      return null;
    }
    return real(f, o);
  });
  const r = await app.call('DELETE', `/api/products/${p._id}`, { token: tok(seller) });
  assert.equal(r.status, 200);
  assert.equal(r.json.deletionType, 'soft', 'a booked product must never be hard-deleted');
  assert.equal(row(Product, p._id).isDeleted, true);
  assert.equal(db.store.products.length, 1, 'the product document still exists (the booking references it)');
  await tick();
  assert.ok(sent.some((m) => m.to === 'race.buyer@brainwareuniversity.ac.in'), 'the buyer must be told their item was removed');
});
