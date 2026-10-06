/**
 * Wire-level tests: the REAL controllers + REAL Mongoose models run, and only the MongoDB driver's
 * collection methods are intercepted. What is asserted is therefore the exact command Mongoose would
 * send to MongoDB (casting, operators, defaults, timestamps) - which stubbing at the model level cannot show.
 * Not covered (needs a real server): execution semantics such as atomicity and transactions.
 */
const h = require('./helpers');
const { test, afterEach, after, before } = require('node:test');
const assert = require('node:assert/strict');
const Cart = require('../src/models/Cart');
const bcrypt = require('bcryptjs');
const { hashOtp } = require('../src/utils/otp');
const { hashToken } = require('../src/utils/token');

const { mock, mongoose, oid, makeUser, makeProduct, makeBooking, authAs, User, Product, Booking } = h;
const { ObjectId } = mongoose.Types;
let app;
before(async () => { app = await h.startApp(); });
after(async () => { await app.close(); });
afterEach(() => mock.restoreAll());

const tick = () => new Promise((r) => setTimeout(r, 50));

/** Intercept driver-level collection methods; every call is recorded in `log`. */
const wire = (log, spec) => {
  for (const [Model, ops] of spec) {
    for (const [name, impl] of Object.entries(ops)) {
      mock.method(Model.collection, name, async (...args) => { log.push({ coll: Model.collection.name, op: name, args }); return impl(...args); });
    }
  }
  return log;
};
const cmds = (log, coll, op) => log.filter((c) => c.coll === coll && c.op === op);
const cursor = (docs) => ({ toArray: async () => docs });

/** MongoDB rejects an update that touches the same path twice (or a parent and its child). */
const pathConflicts = (update) => {
  const paths = [];
  for (const [op, body] of Object.entries(update)) if (op.startsWith('$')) for (const k of Object.keys(body)) paths.push([op, k.replace(/\.\$\./g, '.')]);
  const out = [];
  for (let i = 0; i < paths.length; i++) for (let j = i + 1; j < paths.length; j++) {
    const [oa, a] = paths[i], [ob, b] = paths[j];
    if (a === b || a.startsWith(`${b}.`) || b.startsWith(`${a}.`)) out.push(`${oa}:${a} <-> ${ob}:${b}`);
  }
  return out;
};
const isOid = (v) => v instanceof ObjectId;
// Mongoose's `timestamps` option adds `updatedAt` to every $set; anything ELSE is unintended.
const setOf = (update) => { const { updatedAt, ...rest } = update.$set; assert.ok(updatedAt instanceof Date, 'timestamps add updatedAt'); return rest; };

const sellerDoc = (extra = {}) => ({ _id: oid(), name: 'Seller One', email: 'seller1@brainwareuniversity.ac.in', ...extra });

/* ---------------------------- CART ---------------------------- */

test('cart add (new item): upsert-if-missing, then ONE $push with ObjectId-cast fields and no conflicting paths', async () => {
  const me = makeUser(); const token = authAs(me);
  const p = makeProduct(); const log = [];
  let n = 0;
  wire(log, [
    [Product, { findOne: async () => p.toObject() }],
    [User, { find: () => cursor([]) }],                                    // seller account no longer exists -> snapshot fallback
    [Cart, {
      updateOne: async () => ({ acknowledged: true, matchedCount: 0, modifiedCount: 0, upsertedCount: 1 }),
      findOneAndUpdate: async () => (++n === 1 ? null : { userId: me._id, items: [{ productId: p._id, title: p.title, price: p.price, quantity: 2, imageUrl: p.imageUrl }] }),
    }],
  ]);
  mock.method(Product.collection, 'find', () => cursor([p.toObject()]));
  const r = await app.call('POST', '/api/cart/add', { token, body: { productId: String(p._id), quantity: 2 } });
  assert.equal(r.status, 200);
  assert.equal(r.json.message, 'Added to cart');

  const [ensure] = cmds(log, 'carts', 'updateOne');
  assert.ok(isOid(ensure.args[0].userId));
  assert.deepEqual(ensure.args[1].$setOnInsert.items, []);
  assert.deepEqual(pathConflicts(ensure.args[1]), []);
  assert.equal(ensure.args[2].upsert, true);

  const [bump, push] = cmds(log, 'carts', 'findOneAndUpdate');
  assert.ok(isOid(bump.args[0]['items.productId']));                       // string id was cast to ObjectId
  assert.equal(bump.args[1].$inc['items.$.quantity'], 2);
  assert.deepEqual(pathConflicts(bump.args[1]), []);

  assert.ok(isOid(push.args[0]['items.productId'].$ne));
  const item = push.args[1].$push.items;
  assert.ok(isOid(item.productId));
  assert.equal(item.quantity, 2);
  assert.equal(item.sellerName, 'Seller');                                  // snapshot fallback
  assert.ok(!('sellerId' in item) || item.sellerId !== null, 'must not store sellerId: null');
  assert.deepEqual(pathConflicts(push.args[1]), []);
});

test('cart add (existing item): a single positional $inc, no push', async () => {
  const me = makeUser(); const token = authAs(me);
  const p = makeProduct(); const log = [];
  wire(log, [
    [Product, { findOne: async () => p.toObject() }],
    [User, { find: () => cursor([sellerDoc({ _id: p.sellerId })]) }],
    [Cart, {
      updateOne: async () => ({ acknowledged: true, matchedCount: 1, modifiedCount: 0 }),
      findOneAndUpdate: async () => ({ userId: me._id, items: [{ productId: p._id, title: p.title, price: p.price, quantity: 3, imageUrl: p.imageUrl }] }),
    }],
  ]);
  mock.method(Product.collection, 'find', () => cursor([p.toObject()]));
  const r = await app.call('POST', '/api/cart/add', { token, body: { productId: String(p._id) } });
  assert.equal(r.status, 200);
  assert.equal(cmds(log, 'carts', 'findOneAndUpdate').length, 1);
  assert.equal(cmds(log, 'carts', 'findOneAndUpdate')[0].args[1].$inc['items.$.quantity'], 1);   // default quantity 1
});

test('cart update/remove/clear/get: $set positional, $pull casts the string id to ObjectId, upsert has no conflicts', async () => {
  const me = makeUser(); const token = authAs(me); const log = [];
  const id = String(oid());
  wire(log, [
    [Product, { find: () => cursor([]) }],
    [Cart, { findOneAndUpdate: async () => ({ userId: me._id, items: [] }) }],
  ]);
  await app.call('PUT', `/api/cart/item/${id}`, { token, body: { quantity: 4 } });
  await app.call('PUT', `/api/cart/item/${id}`, { token, body: { quantity: 0 } });
  await app.call('DELETE', `/api/cart/item/${id}`, { token });
  await app.call('POST', '/api/cart/clear', { token });
  await app.call('GET', '/api/cart', { token });
  const c = cmds(log, 'carts', 'findOneAndUpdate');
  assert.equal(c.length, 5);
  assert.equal(c[0].args[1].$set['items.$.quantity'], 4);
  assert.ok(isOid(c[0].args[0]['items.productId']));
  assert.ok(isOid(c[1].args[1].$pull.items.productId), 'update-to-zero $pull must be cast to ObjectId');
  assert.ok(isOid(c[2].args[1].$pull.items.productId), 'remove $pull must be cast to ObjectId');
  assert.deepEqual(c[3].args[1].$set.items, []);
  assert.equal(c[4].args[2].upsert, true);                                  // getCart upsert
  assert.deepEqual(c[4].args[1].$setOnInsert.items, []);
  for (const x of c) assert.deepEqual(pathConflicts(x.args[1]), [], JSON.stringify(x.args[1]));
});

/* ---------------------------- BOOKING ---------------------------- */

const withTransactions = (cap) => mock.method(mongoose, 'startSession', async () => ({
  id: 'fake-session', inTransaction: () => true, transaction: { state: 'TRANSACTION_IN_PROGRESS' },
  withTransaction: async (fn) => { cap.tx++; return fn(); }, endSession: async () => {},
}));

test('booking create: product query + per-product conditional lock + booking insert are exactly the intended commands', async () => {
  const buyer = makeUser(); const token = authAs(buyer); h.stubMail();
  const seller = sellerDoc();
  const p = makeProduct({ price: 250, sellerId: seller._id, sellerName: 'Snap', sellerEmail: 'snap@x.in' });
  const log = []; const cap = { tx: 0 };
  withTransactions(cap);
  wire(log, [
    [Product, { find: () => cursor([p.toObject()]), updateOne: async () => ({ acknowledged: true, matchedCount: 1, modifiedCount: 1 }) }],
    [User, { find: () => cursor([seller]) }],
    [Booking, { insertOne: async (doc) => ({ acknowledged: true, insertedId: doc._id }) }],
  ]);
  const r = await app.call('POST', '/api/bookings/create', { token, body: { totalPrice: 1, products: [{ productId: String(p._id), quantity: 2, price: 0.01, sellerEmail: 'evil@x.in' }] } });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  assert.equal(cap.tx, 1);

  const [find] = cmds(log, 'products', 'find');
  assert.ok(isOid(find.args[0]._id.$in[0]));
  assert.deepEqual(find.args[0].isDeleted, { $ne: true });

  const [lock] = cmds(log, 'products', 'updateOne');
  assert.ok(isOid(lock.args[0]._id));
  assert.equal(lock.args[0].status, 'approved');
  assert.equal(lock.args[0].price, 250);                                    // lock is conditional on the price used
  assert.deepEqual(lock.args[0].isBooked, { $ne: true });
  assert.deepEqual(setOf(lock.args[1]), { isBooked: true });
  assert.ok(lock.args[2].session, 'lock must run inside the transaction session');

  const [ins] = cmds(log, 'bookings', 'insertOne');
  const doc = ins.args[0];
  assert.ok(isOid(doc.buyerId));
  assert.equal(doc.totalPrice, 500);
  assert.equal(doc.status, 'Booked');
  assert.ok(isOid(doc.products[0].productId));
  assert.ok(isOid(doc.products[0].sellerId));
  assert.equal(doc.products[0].price, 250);
  assert.equal(doc.products[0].sellerEmail, 'seller1@brainwareuniversity.ac.in');   // live seller account, not client/snapshot
  assert.ok(ins.args[1].session, 'booking insert must run inside the transaction session');
  await tick();
});

test('booking create: no booking is inserted when the lock matches nothing (409)', async () => {
  const token = authAs(makeUser()); const seller = sellerDoc();
  const p = makeProduct({ sellerId: seller._id }); const log = []; withTransactions({ tx: 0 });
  wire(log, [
    [Product, { find: () => cursor([p.toObject()]), updateOne: async () => ({ acknowledged: true, matchedCount: 0, modifiedCount: 0 }) }],
    [User, { find: () => cursor([seller]) }],
    [Booking, { insertOne: async () => { throw new Error('must not insert'); } }],
  ]);
  const r = await app.call('POST', '/api/bookings/create', { token, body: { products: [{ productId: String(p._id), quantity: 1 }] } });
  assert.equal(r.status, 409);
  assert.equal(cmds(log, 'bookings', 'insertOne').length, 0);
});

test('booking cancel + read: filters are cast and carry ownership; release uses $set', async () => {
  const me = makeUser(); const token = authAs(me); h.stubMail();
  const b = makeBooking({ buyerId: me._id }); const log = [];
  wire(log, [
    [Booking, { findOneAndUpdate: async () => ({ ...b.toObject(), status: 'Cancelled' }), findOne: async () => b.toObject() }],
    [Product, { updateMany: async () => ({ acknowledged: true, modifiedCount: 1 }) }],
  ]);
  assert.equal((await app.call('PUT', `/api/bookings/${b._id}/cancel`, { token })).status, 200);
  assert.equal((await app.call('GET', `/api/bookings/${b._id}`, { token })).status, 200);
  const [cancel] = cmds(log, 'bookings', 'findOneAndUpdate');
  assert.ok(isOid(cancel.args[0]._id) && isOid(cancel.args[0].buyerId));
  assert.deepEqual(cancel.args[0].status, { $in: ['Booked', 'Dispatched'] });
  assert.deepEqual(setOf(cancel.args[1]), { status: 'Cancelled' });
  const [rel] = cmds(log, 'products', 'updateMany');
  assert.ok(rel.args[0]._id.$in.every(isOid));
  assert.deepEqual(setOf(rel.args[1]), { isBooked: false });
  await tick();
});

/* ---------------------------- AUTH ---------------------------- */

test('verify-otp: $inc attempt counter filter + success $set/$unset have no conflicts and cast correctly', async () => {
  const hash = hashOtp('123456');
  const u = makeUser({ isVerified: false, emailOTP: hash, emailOTPExpires: new Date(Date.now() + 60000) });
  const log = [];
  wire(log, [[User, {
    findOne: async () => u.toObject(),
    findOneAndUpdate: async () => ({ ...u.toObject(), emailOTPAttempts: 1 }),
    updateOne: async () => ({ acknowledged: true, modifiedCount: 1 }),
  }]]);
  const r = await app.call('POST', '/api/auth/verify-otp', { body: { email: u.email, otp: '123456' } });
  assert.equal(r.status, 200);
  const [inc] = cmds(log, 'users', 'findOneAndUpdate');
  assert.equal(inc.args[0].emailOTP, hash);
  assert.equal(inc.args[1].$inc.emailOTPAttempts, 1);
  const [done] = cmds(log, 'users', 'updateOne');
  assert.equal(done.args[1].$set.isVerified, true);
  for (const k of ['emailOTP', 'emailOTPExpires', 'emailOTPAttempts', 'emailOTPLastSentAt']) assert.ok(k in done.args[1].$unset, k);
  assert.deepEqual(pathConflicts(done.args[1]), []);
});

test('resend-otp: cooldown claim casts dates; update stores only hashed OTP', async () => {
  h.stubMail();
  const u = makeUser({ isVerified: false, emailOTPLastSentAt: new Date(Date.now() - 120000) }); const log = [];
  wire(log, [[User, { findOne: async () => u.toObject(), findOneAndUpdate: async () => u.toObject() }]]);
  const r = await app.call('POST', '/api/auth/resend-otp', { body: { email: u.email } });
  assert.equal(r.status, 200);
  const [claim] = cmds(log, 'users', 'findOneAndUpdate');
  const or = claim.args[0].$or;
  assert.deepEqual(or[0], { emailOTPLastSentAt: { $exists: false } });
  assert.ok(or[1].emailOTPLastSentAt.$lte instanceof Date);
  const set = claim.args[1].$set;
  assert.match(set.emailOTP, /^[a-f0-9]{64}$/);
  assert.ok(set.emailOTPExpires instanceof Date && set.emailOTPLastSentAt instanceof Date);
  assert.equal(set.emailOTPAttempts, 0);
  assert.deepEqual(pathConflicts(claim.args[1]), []);
});

test('forgot + reset password: stored token is a hash, dates are Dates, reset is single-use and conflict-free', async () => {
  const sent = h.stubMail();
  const u = makeUser(); const log = [];
  wire(log, [[User, { findOne: async () => u.toObject(), updateOne: async () => ({ acknowledged: true, modifiedCount: 1 }) }]]);
  await app.call('POST', '/api/auth/forgot-password', { body: { email: u.email } });
  const token = sent[0].html.match(/reset-password\/([a-f0-9]{64})/)[1];
  const [store] = cmds(log, 'users', 'updateOne');
  assert.equal(store.args[1].$set.resetPasswordToken, hashToken(token));
  assert.ok(store.args[1].$set.resetPasswordExpires instanceof Date);
  const r = await app.call('POST', `/api/auth/reset-password/${token}`, { body: { password: 'brandnew1' } });
  assert.equal(r.status, 200);
  const reset = cmds(log, 'users', 'updateOne')[1];
  assert.equal(reset.args[0].resetPasswordToken, hashToken(token));          // matches only while the same token is stored
  assert.ok(await bcrypt.compare('brandnew1', reset.args[1].$set.password));
  assert.deepEqual(Object.keys(reset.args[1].$unset).sort(), ['resetPasswordExpires', 'resetPasswordToken']);
  assert.deepEqual(pathConflicts(reset.args[1]), []);
});

/* ---------------------------- PRODUCTS / ADMIN / PROFILE ---------------------------- */

test('product delete: hard delete is guarded on isBooked; soft delete $set has no conflicts', async () => {
  const me = makeUser(); const token = authAs(me); h.stubMail();
  const p = makeProduct({ sellerId: me._id }); const log = [];
  wire(log, [
    [Product, { findOne: async () => p.toObject(), deleteOne: async () => ({ acknowledged: true, deletedCount: 0 }), updateOne: async () => ({ acknowledged: true, modifiedCount: 1 }) }],
    [Booking, { findOne: async () => null }],
  ]);
  const r = await app.call('DELETE', `/api/products/${p._id}`, { token });
  assert.equal(r.json.deletionType, 'soft');                                   // deletedCount 0 -> falls back to soft delete
  const [del] = cmds(log, 'products', 'deleteOne');
  assert.deepEqual(del.args[0].isBooked, { $ne: true });
  const [soft] = cmds(log, 'products', 'updateOne');
  assert.equal(soft.args[1].$set.isDeleted, true);
  assert.ok(soft.args[1].$set.deletedAt instanceof Date);
  assert.deepEqual(pathConflicts(soft.args[1]), []);
  const [bk] = cmds(log, 'bookings', 'findOne');
  assert.ok(isOid(bk.args[0]['products.productId']));
  assert.deepEqual(bk.args[0].status, { $ne: 'Cancelled' });
  await tick();
});

test('admin status + pending list: queries exclude deleted; status update is a plain $set', async () => {
  const admin = makeUser({ role: 'admin' }); const token = authAs(admin); h.stubMail();
  const p = makeProduct({ status: 'approved' }); const log = [];
  wire(log, [
    [Product, { findOneAndUpdate: async () => p.toObject(), find: () => cursor([]) }],
    [User, { find: () => cursor([]) }],
  ]);
  assert.equal((await app.call('GET', '/api/admin/products/pending', { token })).status, 200);
  assert.equal((await app.call('PUT', `/api/admin/products/${p._id}/status`, { token, body: { status: 'approved' } })).status, 200);
  const [pending] = cmds(log, 'products', 'find');
  assert.equal(pending.args[0].status, 'pending');
  assert.deepEqual(pending.args[0].isDeleted, { $ne: true });
  const [upd] = cmds(log, 'products', 'findOneAndUpdate');
  assert.ok(isOid(upd.args[0]._id));
  assert.equal(upd.args[1].$set.status, 'approved');
  await tick();
});

test('profile + contact updates: only whitelisted $set fields are ever written', async () => {
  const me = makeUser(); const token = authAs(me); const log = [];
  wire(log, [[User, { findOneAndUpdate: async () => me.toObject() }]]);
  await app.call('PUT', '/api/profile', { token, body: { name: 'N', studentCode: 'S1', role: 'admin', password: 'x', avatar: 'http://evil/x.gif', isVerified: false, email: 'e@x.in' } });
  await app.call('PUT', '/api/users/contact', { token, body: { phoneNumber: '9876543210', contactPreference: 'call', role: 'admin' } });
  const [prof, contact] = cmds(log, 'users', 'findOneAndUpdate');
  const written = (u) => Object.keys(u.$set || {}).filter((k) => k !== 'updatedAt').sort();
  assert.deepEqual(written(prof.args[1]), ['name', 'studentCode']);
  assert.deepEqual(written(contact.args[1]), ['contactPreference', 'phoneNumber']);
});
