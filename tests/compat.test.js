/**
 * Database-compatibility of the APPLICATION LOGIC: documents shaped like the legacy schema
 * (fields missing: isDeleted, isBooked, sellerName/sellerEmail, studentCode, imageUrl, cart seller fields)
 * must keep working without any migration. Runs on the simulated driver (see fakedb.js), whose `$ne`/`$exists`
 * semantics mirror MongoDB's (a missing field does NOT match `{ field: false }`).
 */
const h = require('./helpers');
const { test, afterEach, after, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { attach } = require('./fakedb');
const { signToken } = require('../src/utils/token');
const Cart = require('../src/models/Cart');

const { mock, oid, makeUser, User, Product, Booking } = h;
let app, db;
before(async () => { app = await h.startApp(); });
after(async () => { await app.close(); });
beforeEach(() => { db = attach([User, Product, Booking, Cart]); });
afterEach(() => mock.restoreAll());
const tick = () => new Promise((r) => setTimeout(r, 60));

const seedUser = (over = {}) => { const d = db.seed(User, makeUser(over)); return d; };
// Raw legacy-style documents (bypass the current schema defaults on purpose).
const legacyProduct = (over = {}) => { const d = { _id: oid(), title: 'Legacy Book', price: 80, quantity: 1, description: 'old', imageUrl: ['http://i/1.jpg'], category: 'Books', status: 'approved', postDate: new Date(), ...over }; db.store.products.push(d); return d; };
const row = (c, id) => db.store[c].find((d) => String(d._id) === String(id));

test('legacy products (no isDeleted / isBooked / seller snapshot) are listed, searchable, viewable and editable', async () => {
  const seller = seedUser({ email: 'old.seller@brainwareuniversity.ac.in' });
  const p = legacyProduct({ sellerId: seller._id });
  assert.equal('isDeleted' in p, false);
  const list = await app.call('GET', '/api/products?search=legacy&category=books');
  assert.deepEqual(list.json.map((x) => x._id), [String(p._id)], 'a missing isDeleted field must not hide the product');
  assert.equal((await app.call('GET', `/api/products/${p._id}`)).json.title, 'Legacy Book');
  assert.equal((await app.call('GET', '/api/products/category/Books')).json.length, 1);
  const edit = await app.call('PUT', `/api/products/${p._id}`, { token: signToken(seller._id), body: { price: 90 } });
  assert.equal(edit.status, 200, JSON.stringify(edit.json));     // save() must not fail on missing sellerName/sellerEmail
  assert.equal(row('products', p._id).price, 90);
  const mine = await app.call('GET', '/api/products/my-products', { token: signToken(seller._id) });
  assert.equal(mine.json.length, 1);
});

test('legacy product can be booked, cancelled, and soft/hard deleted', async () => {
  h.stubMail();
  const seller = seedUser({ email: 'old.seller@brainwareuniversity.ac.in' }); const buyer = seedUser();
  const p = legacyProduct({ sellerId: seller._id });
  const b = await app.call('POST', '/api/bookings/create', { token: signToken(buyer._id), body: { products: [{ productId: String(p._id), quantity: 1 }] } });
  assert.equal(b.status, 201, JSON.stringify(b.json));
  assert.equal(b.json.booking.products[0].sellerEmail, 'old.seller@brainwareuniversity.ac.in');   // from the live seller, no snapshot needed
  assert.equal((await app.call('PUT', `/api/bookings/${b.json.bookingId}/cancel`, { token: signToken(buyer._id) })).status, 200);
  const del = await app.call('DELETE', `/api/products/${p._id}`, { token: signToken(seller._id) });
  assert.equal(del.json.deletionType, 'hard');        // isBooked missing/false and no active booking
  assert.equal(db.store.products.length, 0);
  await tick();
});

test('legacy BOOKINGS (no imageUrl / seller fields) can still be read and cancelled', async () => {
  h.stubMail();
  const buyer = seedUser(); const p = legacyProduct({ sellerId: oid(), isBooked: true });
  const bk = { _id: oid(), buyerId: buyer._id, buyerName: 'Old', buyerEmail: buyer.email, status: 'Booked', bookingDate: new Date(), totalPrice: 80,
    products: [{ productId: p._id, title: 'Legacy Book', quantity: 1, price: 80 }] };            // no imageUrl, no sellerName/sellerEmail
  db.store.bookings.push(bk);
  const t = signToken(buyer._id);
  const get = await app.call('GET', `/api/bookings/${bk._id}`, { token: t });
  assert.equal(get.status, 200);
  assert.equal(String(get.json.products[0].productId), String(p._id));
  const cancel = await app.call('PUT', `/api/bookings/${bk._id}/cancel`, { token: t });
  assert.equal(cancel.status, 200, JSON.stringify(cancel.json));
  assert.equal(row('bookings', bk._id).status, 'Cancelled');
  assert.equal(row('products', p._id).isBooked, false);
  await tick();
});

test('legacy CARTS (items without seller fields) can be read, updated and cleared; missing products are flagged, not dropped', async () => {
  const buyer = seedUser(); const t = signToken(buyer._id);
  const live = legacyProduct({ price: 80 }); const gone = oid();
  db.store.carts.push({ _id: oid(), userId: buyer._id, items: [
    { productId: live._id, title: 'stale', price: 1, quantity: 2, imageUrl: [] },
    { productId: gone, title: 'deleted long ago', price: 5, quantity: 1, imageUrl: [] },
  ] });
  const view = await app.call('GET', '/api/cart', { token: t });
  assert.equal(view.status, 200);
  assert.equal(view.json.items.length, 2);
  assert.equal(view.json.items[0].price, 80, 'live price replaces the stale snapshot');
  assert.equal(view.json.items[1].unavailable, true);
  const upd = await app.call('PUT', `/api/cart/item/${live._id}`, { token: t, body: { quantity: 3 } });
  assert.equal(upd.status, 200);
  assert.equal(row('carts', db.store.carts[0]._id).items[0].quantity, 3);
  assert.equal((await app.call('DELETE', `/api/cart/item/${gone}`, { token: t })).status, 200);
  assert.equal((await app.call('POST', '/api/cart/clear', { token: t })).status, 200);
});

test('legacy USERS (no studentCode / phone / contactPreference) log in, update profile and keep every field the frontend reads', async () => {
  const bcrypt = require('bcryptjs');
  const u = { _id: oid(), name: 'Legacy User', email: 'legacy.user@brainwareuniversity.ac.in', password: await bcrypt.hash('secret12', 4), isVerified: true,
    programType: 'UG', department: 'CSE', year: '2nd Year', role: 'student', joinDate: new Date() };
  db.store.users.push(u);
  const login = await app.call('POST', '/api/auth/login', { body: { email: u.email, password: 'secret12' } });
  assert.equal(login.status, 200);
  assert.equal(login.json.user.studentCode, undefined);
  assert.equal(login.json.user.contactPreference, 'both', 'schema default applies on read');
  const t = login.json.token;
  assert.equal((await app.call('GET', '/api/cart', { token: t })).status, 200);
  const prof = await app.call('PUT', '/api/profile', { token: t, body: { studentCode: 'LEG-1', department: 'IT' } });
  assert.equal(prof.status, 200);
  assert.equal(row('users', u._id).studentCode, 'LEG-1');
});

test('legacy PENDING product (no seller snapshot, no isDeleted) appears in the admin queue and can be approved', async () => {
  h.stubMail();
  const seller = seedUser({ email: 'old.seller@brainwareuniversity.ac.in' });
  const admin = seedUser({ email: 'adm@brainwareuniversity.ac.in', role: 'admin' });
  const p = legacyProduct({ status: 'pending', sellerId: seller._id });
  const at = signToken(admin._id);
  const q = await app.call('GET', '/api/admin/products/pending', { token: at });
  assert.equal(q.json.length, 1);
  assert.equal(q.json[0].sellerId.email, 'old.seller@brainwareuniversity.ac.in');
  assert.equal((await app.call('PUT', `/api/admin/products/${p._id}/status`, { token: at, body: { status: 'approved' } })).status, 200);
  assert.equal(row('products', p._id).status, 'approved');
  await tick();
});

test('soft-deleted products stay hidden everywhere; the isDeleted:true flag is honoured', async () => {
  const seller = seedUser(); const buyer = seedUser({ email: 'b2@brainwareuniversity.ac.in' });
  const p = legacyProduct({ sellerId: seller._id, isDeleted: true });
  assert.deepEqual((await app.call('GET', '/api/products')).json, []);
  assert.equal((await app.call('GET', `/api/products/${p._id}`)).status, 404);
  assert.equal((await app.call('POST', '/api/cart/add', { token: signToken(buyer._id), body: { productId: String(p._id) } })).status, 400);
  assert.equal((await app.call('POST', '/api/bookings/create', { token: signToken(buyer._id), body: { products: [{ productId: String(p._id), quantity: 1 }] } })).status, 400);
  assert.equal((await app.call('PUT', `/api/products/${p._id}`, { token: signToken(seller._id), body: { price: 1 } })).status, 404);
});

test('legacy booking without buyerId cannot cause a 500: owner check fails closed with 404', async () => {
  const user = seedUser();
  const bk = { _id: oid(), buyerName: 'x', status: 'Booked', totalPrice: 1, products: [] };       // buyerId missing
  db.store.bookings.push(bk);
  const r = await app.call('GET', `/api/bookings/${bk._id}`, { token: signToken(user._id) });
  assert.equal(r.status, 404);
  assert.deepEqual(r.json, { message: 'Booking not found.' });
});
