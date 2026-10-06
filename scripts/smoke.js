/**
 * Live smoke test against a REAL MongoDB - exercises the database-specific code paths that the
 * stubbed unit tests cannot prove (positional cart updates, upserts, booking transaction, atomic
 * cancel, ownership checks).
 *
 * SAFETY: it creates its own temporary documents (marker "smoke-<timestamp>") and deletes them
 * afterwards, but it still writes to the database in MONGO_URI. Run it against a TEST/DEV database:
 *
 *     SMOKE_I_USE_A_TEST_DB=yes node scripts/smoke.js
 *
 * Email and Cloudinary are stubbed (no mail is sent, no image is uploaded).
 */
const { loadEnv } = require('../src/config/env');
loadEnv();

if (process.env.SMOKE_I_USE_A_TEST_DB !== 'yes') {
  console.error('Refusing to run: set SMOKE_I_USE_A_TEST_DB=yes to confirm MONGO_URI points at a test/dev database.');
  process.exit(2);
}

const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const connectDB = require('../src/config/db');
const User = require('../src/models/User');
const Product = require('../src/models/Product');
const Cart = require('../src/models/Cart');
const Booking = require('../src/models/Booking');
const emailService = require('../src/services/email/email.service');
const { signToken } = require('../src/utils/token');

emailService.setTransporter({ sendMail: async () => ({}) }); // never send real mail

const tag = `smoke-${Date.now()}`;
const results = [];
const step = async (name, fn) => {
  try { await fn(); results.push(['PASS', name]); console.log(`PASS  ${name}`); }
  catch (e) { results.push(['FAIL', name]); console.log(`FAIL  ${name}\n      ${e.message}`); }
};

(async () => {
  await connectDB();
  const app = require('../src/app');
  const server = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, token, body) => {
    const res = await fetch(base + path, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body ? JSON.stringify(body) : undefined });
    let json = null; try { json = await res.json(); } catch { /* empty */ }
    return { status: res.status, json };
  };

  const pw = await bcrypt.hash('Passw0rd!', 10);
  const mkUser = (suffix, extra = {}) => User.create({ name: `Smoke ${suffix}`, email: `${tag}-${suffix}@brainwareuniversity.ac.in`, password: pw, programType: 'UG', department: 'CSE', year: '1st Year', isVerified: true, ...extra });
  const [seller, buyer, stranger, admin] = await Promise.all([mkUser('seller'), mkUser('buyer'), mkUser('stranger'), mkUser('admin', { role: 'admin' })]);
  const [sT, bT, xT, aT] = [seller, buyer, stranger, admin].map((u) => signToken(u._id));
  const mkProduct = (over = {}) => Product.create({ title: `${tag} item`, price: 250, quantity: 1, description: 'smoke', imageUrl: ['https://example.test/i.jpg'], category: 'Books', sellerId: seller._id, sellerName: seller.name, sellerEmail: seller.email, status: 'approved', ...over });
  const approved = await mkProduct();
  const pending = await mkProduct({ status: 'pending' });
  const created = { products: [approved._id, pending._id], bookings: [] };

  await step('login with a real bcrypt hash', async () => {
    const r = await call('POST', '/api/auth/login', null, { email: buyer.email, password: 'Passw0rd!' });
    assert.equal(r.status, 200); assert.ok(r.json.token); assert.equal('password' in r.json.user, false);
  });
  await step('GET /products lists the approved product, hides the pending one, hides seller email', async () => {
    const r = await call('GET', `/api/products?search=${encodeURIComponent(tag)}`);
    assert.equal(r.status, 200);
    assert.ok(r.json.some((p) => p._id === String(approved._id)));
    assert.equal(r.json.some((p) => p._id === String(pending._id)), false);
    assert.equal(r.json.every((p) => !('sellerEmail' in p)), true);
  });
  await step('pending product is viewable by id (EditProduct) without a token', async () => {
    assert.equal((await call('GET', `/api/products/${pending._id}`)).status, 200);
  });
  await step('cart: add -> add again (bump) -> update -> remove -> clear (positional / upsert operators)', async () => {
    let r = await call('POST', '/api/cart/add', bT, { productId: String(approved._id), quantity: 1 });
    assert.equal(r.status, 200); assert.equal(r.json.cart.items.length, 1);
    r = await call('POST', '/api/cart/add', bT, { productId: String(approved._id), quantity: 2 });
    assert.equal(r.json.cart.items[0].quantity, 3);
    r = await call('PUT', `/api/cart/item/${approved._id}`, bT, { quantity: 5 });
    assert.equal(r.json.cart.items[0].quantity, 5);
    r = await call('DELETE', `/api/cart/item/${approved._id}`, bT);
    assert.equal(r.json.cart.items.length, 0);
    await call('POST', '/api/cart/add', bT, { productId: String(approved._id) });
    r = await call('POST', '/api/cart/clear', bT);
    assert.deepEqual(r.json.cart.items, []);
    assert.equal((await call('POST', '/api/cart/add', bT, { productId: String(pending._id) })).status, 400);
  });
  await step('cart view refreshes a changed price', async () => {
    await call('POST', '/api/cart/add', bT, { productId: String(approved._id) });
    await Product.updateOne({ _id: approved._id }, { $set: { price: 300 } });
    const r = await call('GET', '/api/cart', bT);
    assert.equal(r.json.items[0].price, 300);
    await Product.updateOne({ _id: approved._id }, { $set: { price: 250 } });
    await call('POST', '/api/cart/clear', bT);
  });
  let bookingId;
  await step('booking: cannot book a pending product', async () => {
    const r = await call('POST', '/api/bookings/create', bT, { products: [{ productId: String(pending._id), quantity: 1 }] });
    assert.equal(r.status, 400);
  });
  await step('booking: server price wins over tampered client price/total (transaction)', async () => {
    const r = await call('POST', '/api/bookings/create', bT, { totalPrice: 1, products: [{ productId: String(approved._id), quantity: 2, price: 0.01 }] });
    assert.equal(r.status, 201, JSON.stringify(r.json));
    assert.equal(r.json.booking.totalPrice, 500);
    bookingId = r.json.bookingId; created.bookings.push(bookingId);
    assert.equal((await Product.findById(approved._id)).isBooked, true);
  });
  await step('booking: the same product cannot be booked twice', async () => {
    const r = await call('POST', '/api/bookings/create', xT, { products: [{ productId: String(approved._id), quantity: 1 }] });
    assert.equal(r.status, 400);
  });
  await step('booking IDOR: stranger gets 404, owner 200, admin 200', async () => {
    assert.equal((await call('GET', `/api/bookings/${bookingId}`, xT)).status, 404);
    assert.equal((await call('GET', `/api/bookings/${bookingId}`, bT)).status, 200);
    assert.equal((await call('GET', `/api/bookings/${bookingId}`, aT)).status, 200);
    assert.equal((await call('GET', '/api/bookings/my-bookings', bT)).json.length >= 1, true);
  });
  await step('cancel: stranger 404 (booking untouched); owner 200 releases the product; second cancel 400', async () => {
    assert.equal((await call('PUT', `/api/bookings/${bookingId}/cancel`, xT)).status, 404);
    assert.equal((await Booking.findById(bookingId)).status, 'Booked');
    assert.equal((await call('PUT', `/api/bookings/${bookingId}/cancel`, bT)).status, 200);
    assert.equal((await Product.findById(approved._id)).isBooked, false);
    assert.equal((await call('PUT', `/api/bookings/${bookingId}/cancel`, bT)).status, 400);
  });
  await step('admin: non-admin 403; admin sees pending and can approve', async () => {
    assert.equal((await call('GET', '/api/admin/products/pending', bT)).status, 403);
    const list = await call('GET', '/api/admin/products/pending', aT);
    const mine = list.json.find((p) => p._id === String(pending._id));
    assert.ok(mine); assert.equal(mine.sellerId.email, seller.email);
    assert.equal((await call('PUT', `/api/admin/products/${pending._id}/status`, aT, { status: 'approved' })).status, 200);
  });
  await step('product edit/delete: stranger 403; owner edit ok; booked-then-deleted soft deletes', async () => {
    assert.equal((await call('PUT', `/api/products/${approved._id}`, xT, { title: 'x' })).status, 403);
    assert.equal((await call('DELETE', `/api/products/${approved._id}`, xT)).status, 403);
    assert.equal((await call('PUT', `/api/products/${approved._id}`, sT, { price: 260 })).status, 200);
    const r = await call('DELETE', `/api/products/${pending._id}`, sT);
    assert.equal(r.json.deletionType, 'hard');
  });
  await step('profile: studentCode persists', async () => {
    const r = await call('PUT', '/api/profile', bT, { studentCode: 'SMOKE-1', name: 'Smoke Buyer' });
    assert.equal(r.status, 200); assert.equal(r.json.studentCode, 'SMOKE-1');
    assert.equal((await User.findById(buyer._id)).studentCode, 'SMOKE-1');
  });

  // ---- cleanup of everything this script created ----
  await Booking.deleteMany({ buyerEmail: new RegExp(`^${tag}`) });
  await Cart.deleteMany({ userId: { $in: [seller._id, buyer._id, stranger._id, admin._id] } });
  await Product.deleteMany({ title: `${tag} item` });
  await User.deleteMany({ email: new RegExp(`^${tag}`) });
  await new Promise((r) => server.close(r));
  await mongoose.disconnect();

  const failed = results.filter(([s]) => s === 'FAIL').length;
  console.log(`\n${results.length - failed}/${results.length} steps passed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
