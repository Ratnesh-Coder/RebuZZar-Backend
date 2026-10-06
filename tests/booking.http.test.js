const h = require('./helpers');
const { test, afterEach, after, before } = require('node:test');
const assert = require('node:assert/strict');

const { mock, chain, oid, mongoose, makeUser, makeBooking, authAs, Product, Booking } = h;
let app;
before(async () => { app = await h.startApp(); });
after(async () => { await app.close(); });
afterEach(() => mock.restoreAll());

const tick = () => new Promise((r) => setTimeout(r, 60));

/** A product as returned by Product.find().populate('sellerId'). */
const dbProduct = (over = {}) => {
  const seller = { _id: oid(), name: 'Seller One', email: 'seller1@brainwareuniversity.ac.in' };
  return {
    _id: oid(), title: 'Calculator', price: 250, imageUrl: ['https://img/1.jpg'], status: 'approved',
    isBooked: false, isDeleted: false, sellerId: seller, sellerName: seller.name, sellerEmail: seller.email,
    populated: () => undefined, ...over,
  };
};

/** Stubs the DB layer for createBooking. Returns captured calls. */
const stubDb = (products, { lockResult = { modifiedCount: 1 }, txUnsupported = false } = {}) => {
  const cap = { created: [], locks: [], released: [], sessions: 0 };
  mock.method(Product, 'find', () => chain(products));
  mock.method(mongoose, 'startSession', async () => {
    cap.sessions++;
    return {
      withTransaction: async (fn) => {
        if (txUnsupported) throw Object.assign(new Error('Transaction numbers are only allowed on a replica set member or mongos'), { code: 20 });
        return fn();
      },
      endSession: async () => {},
    };
  });
  mock.method(Product, 'updateOne', async (filter, update, opts) => { cap.locks.push({ filter, update, opts }); return typeof lockResult === 'function' ? lockResult(cap.locks.length) : lockResult; });
  mock.method(Product, 'updateMany', async (filter, update) => { cap.released.push({ filter, update }); return {}; });
  mock.method(Booking, 'create', async (docs, opts) => { cap.created.push({ doc: docs[0], opts }); return [new Booking(docs[0])]; });
  return cap;
};

const create = (token, body) => app.call('POST', '/api/bookings/create', { token, body });

/* ---------------- creation: server-authoritative ---------------- */

test('booking: price and total come from the DATABASE; client price/totalPrice/seller/title are ignored', async () => {
  const buyer = makeUser(); const token = authAs(buyer); const sent = h.stubMail();
  const p = dbProduct({ price: 250 });
  const cap = stubDb([p]);
  const r = await create(token, {
    totalPrice: 1,                                                          // tampered total
    products: [{ productId: String(p._id), quantity: 2, price: 0.01, title: 'FREE', imageUrl: ['evil'], sellerId: String(oid()), sellerName: 'evil', sellerEmail: 'evil@x.in' }],
  });
  assert.equal(r.status, 201);
  assert.equal(r.json.message, 'Booking successful!');
  assert.equal(String(r.json.bookingId), String(r.json.booking._id));
  assert.equal(r.json.booking.totalPrice, 500);                             // 250 x 2, not 1
  const line = r.json.booking.products[0];
  assert.equal(line.price, 250);
  assert.equal(line.title, 'Calculator');
  assert.deepEqual(line.imageUrl, ['https://img/1.jpg']);
  assert.equal(line.sellerEmail, 'seller1@brainwareuniversity.ac.in');      // from the seller account, not the client
  assert.equal(line.sellerName, 'Seller One');
  assert.equal(line.quantity, 2);
  assert.equal(String(line.productId), String(p._id));
  assert.equal(typeof line.productId, 'string');                             // flat snapshot (not populated), as the frontend expects
  assert.equal(r.json.booking.status, 'Booked');
  assert.equal(String(cap.created[0].doc.buyerId), String(buyer._id));
  assert.ok(cap.created[0].opts.session);                                    // created inside the transaction
  await tick();
  assert.deepEqual(sent.map((m) => m.to).sort(), [buyer.email, p.sellerEmail, process.env.ADMIN_EMAIL].sort());
});

test('booking: total is the exact sum over several products with correct rounding', async () => {
  const token = authAs(makeUser()); h.stubMail();
  const a = dbProduct({ price: 0.1 }); const b = dbProduct({ price: 0.2 }); const c = dbProduct({ price: 19.99 });
  stubDb([a, b, c]);
  const r = await create(token, { products: [{ productId: String(a._id), quantity: 3 }, { productId: String(b._id), quantity: 1 }, { productId: String(c._id), quantity: 2 }] });
  assert.equal(r.status, 201);
  assert.equal(r.json.booking.totalPrice, 40.48);                            // 0.3 + 0.2 + 39.98
});

test('booking: each product is locked with a conditional update on approved/not-deleted/not-booked AND the priced amount', async () => {
  const token = authAs(makeUser()); h.stubMail();
  const p = dbProduct({ price: 250 });
  const cap = stubDb([p]);
  await create(token, { products: [{ productId: String(p._id), quantity: 1 }] });
  const { filter, update } = cap.locks[0];
  assert.equal(filter.status, 'approved');
  assert.deepEqual(filter.isBooked, { $ne: true });
  assert.deepEqual(filter.isDeleted, { $ne: true });
  assert.equal(filter.price, 250);                                           // a price edit in between makes the lock fail
  assert.deepEqual(update, { $set: { isBooked: true } });
});

test('booking: pending / rejected / deleted / unknown products cannot be booked (approval cannot be bypassed)', async () => {
  const token = authAs(makeUser());
  for (const prod of [dbProduct({ status: 'pending' }), dbProduct({ status: 'rejected' })]) {
    const cap = stubDb([prod]);
    const r = await create(token, { products: [{ productId: String(prod._id), quantity: 1 }] });
    assert.equal(r.status, 400, prod.status);
    assert.equal(r.json.message, 'One or more products are no longer available.');
    assert.equal(cap.created.length + cap.locks.length, 0);
    mock.restoreAll(); authAs(makeUser());
  }
  // deleted or non-existent: the (isDeleted != true) query simply does not return it
  const ghost = oid();
  const cap = stubDb([]);
  const r = await create(token, { products: [{ productId: String(ghost), quantity: 1 }] });
  assert.equal(r.status, 400);
  assert.equal(cap.created.length, 0);
});

test('booking: already-booked product -> 400 with the existing message; nothing written', async () => {
  const token = authAs(makeUser());
  const p = dbProduct({ isBooked: true });
  const cap = stubDb([p]);
  const r = await create(token, { products: [{ productId: String(p._id), quantity: 1 }] });
  assert.equal(r.status, 400);
  assert.equal(r.json.message, 'One or more products already booked.');
  assert.equal(cap.created.length + cap.locks.length, 0);
});

test('booking: lost race (lock matches nothing) -> 409, booking creation never reached; mixed batch is all-or-nothing', async () => {
  const token = authAs(makeUser());
  const a = dbProduct(); const b = dbProduct();
  const cap = stubDb([a, b], { lockResult: (n) => ({ modifiedCount: n === 2 ? 0 : 1 }) });   // second product lost
  const r = await create(token, { products: [{ productId: String(a._id), quantity: 1 }, { productId: String(b._id), quantity: 1 }] });
  assert.equal(r.status, 409);
  assert.equal(typeof r.json.message, 'string');
  assert.equal(cap.created.length, 0);                                       // thrown inside the transaction => rolled back by MongoDB
});

test('booking: standalone MongoDB (no transactions) -> same checks without a session, locks released on failure', async () => {
  const token = authAs(makeUser()); h.stubMail();
  const a = dbProduct(); const b = dbProduct();
  const ok = stubDb([a], { txUnsupported: true });
  const r1 = await create(token, { products: [{ productId: String(a._id), quantity: 1 }] });
  assert.equal(r1.status, 201);
  assert.equal(ok.created[0].opts.session, undefined);
  mock.restoreAll(); authAs(makeUser());
  const bad = stubDb([a, b], { txUnsupported: true, lockResult: (n) => ({ modifiedCount: n === 2 ? 0 : 1 }) });
  const r2 = await create(token, { products: [{ productId: String(a._id), quantity: 1 }, { productId: String(b._id), quantity: 1 }] });
  assert.equal(r2.status, 409);
  assert.equal(bad.created.length, 0);
  assert.equal(bad.released.length, 1);                                      // the first product's lock was given back
  assert.deepEqual(bad.released[0].update, { $set: { isBooked: false } });
});

test('booking: tampered / invalid quantity, duplicates, bad ids, operator injection, empty -> 400; unauthenticated -> 401', async () => {
  const token = authAs(makeUser());
  const p = dbProduct(); const cap = stubDb([p]); const id = String(p._id);
  const bodies = [
    { products: [{ productId: id, quantity: 0 }] },
    { products: [{ productId: id, quantity: -1 }] },
    { products: [{ productId: id, quantity: 2.5 }] },
    { products: [{ productId: id, quantity: 'lots' }] },
    { products: [{ productId: id, quantity: 100000 }] },
    { products: [{ productId: id, quantity: { $gt: 0 } }] },
    { products: [{ productId: id, quantity: 1 }, { productId: id, quantity: 1 }] },
    { products: [{ productId: 'nope', quantity: 1 }] },
    { products: [{ productId: { $ne: null }, quantity: 1 }] },
    { products: [] }, { products: 'x' }, {}, { totalPrice: 100 },
    { products: Array.from({ length: 21 }, () => ({ productId: String(oid()), quantity: 1 })) },
  ];
  for (const body of bodies) assert.equal((await create(token, body)).status, 400, JSON.stringify(body).slice(0, 80));
  assert.equal(cap.created.length + cap.locks.length, 0);
  assert.equal((await app.call('POST', '/api/bookings/create', { body: { products: [{ productId: id }] } })).status, 401);
});

test('booking: a mail failure never fails or rolls back a committed booking', async () => {
  const token = authAs(makeUser()); h.stubMail({ fail: true });
  const p = dbProduct();
  const cap = stubDb([p]);
  const r = await create(token, { products: [{ productId: String(p._id), quantity: 1 }] });
  assert.equal(r.status, 201);
  assert.equal(cap.created.length, 1);
  assert.equal(cap.released.length, 0);
  await tick();
});

test('booking: seller info missing everywhere -> 500 with the previous message', async () => {
  const token = authAs(makeUser());
  const p = dbProduct({ sellerId: null, sellerName: undefined, sellerEmail: undefined });
  stubDb([p]);
  const r = await create(token, { products: [{ productId: String(p._id), quantity: 1 }] });
  assert.equal(r.status, 500);
  assert.equal(r.json.message, 'Seller information missing for one or more products.');
});

test('booking: seller account gone -> falls back to the stored seller snapshot', async () => {
  const token = authAs(makeUser()); h.stubMail();
  const p = dbProduct({ sellerId: null, sellerName: 'Snap Name', sellerEmail: 'snap@brainwareuniversity.ac.in', populated: () => oid() });
  stubDb([p]);
  const r = await create(token, { products: [{ productId: String(p._id), quantity: 1 }] });
  assert.equal(r.status, 201);
  assert.equal(r.json.booking.products[0].sellerEmail, 'snap@brainwareuniversity.ac.in');
});

test('booking: self-purchase is still allowed (existing behaviour preserved, flagged as a product decision)', async () => {
  const me = makeUser(); const token = authAs(me); h.stubMail();
  const p = dbProduct({ sellerId: { _id: me._id, name: me.name, email: me.email } });
  stubDb([p]);
  assert.equal((await create(token, { products: [{ productId: String(p._id), quantity: 1 }] })).status, 201);
});

/* ---------------- read: ownership / IDOR ---------------- */

test('GET /bookings/:id: owner 200 (flat snapshot); other user 404 (indistinguishable from missing); admin 200; bad id 404; no token 401', async () => {
  const owner = makeUser(); const booking = makeBooking({ buyerId: owner._id });
  mock.method(Booking, 'findById', () => chain(booking));

  let token = authAs(owner);
  const own = await app.call('GET', `/api/bookings/${booking._id}`, { token });
  assert.equal(own.status, 200);
  assert.equal(String(own.json._id), String(booking._id));
  assert.equal(typeof own.json.products[0].productId, 'string');
  assert.ok(Array.isArray(own.json.products[0].imageUrl));
  for (const k of ['totalPrice', 'status', 'bookingDate']) assert.ok(k in own.json, k);

  mock.restoreAll();
  mock.method(Booking, 'findById', () => chain(booking));
  token = authAs(makeUser({ email: 'attacker@brainwareuniversity.ac.in' }));      // different authenticated user
  const idor = await app.call('GET', `/api/bookings/${booking._id}`, { token });
  assert.equal(idor.status, 404);
  assert.equal(idor.json.message, 'Booking not found.');
  assert.equal('products' in idor.json, false);                                     // nothing leaked
  mock.restoreAll();
  mock.method(Booking, 'findById', () => chain(null));
  token = authAs(makeUser());
  const missing = await app.call('GET', `/api/bookings/${oid()}`, { token });
  assert.deepEqual(missing.json, idor.json);                                        // same response => no existence oracle
  assert.equal(missing.status, idor.status);

  mock.restoreAll();
  mock.method(Booking, 'findById', () => chain(booking));
  token = authAs(makeUser({ role: 'admin', email: 'admin@brainwareuniversity.ac.in' }));
  assert.equal((await app.call('GET', `/api/bookings/${booking._id}`, { token })).status, 200);

  assert.equal((await app.call('GET', '/api/bookings/not-an-id', { token })).status, 404);
  assert.equal((await app.call('GET', `/api/bookings/${booking._id}`)).status, 401);
});

test('GET /bookings/my-bookings: scoped to the caller, flat snapshots, newest first', async () => {
  const me = makeUser(); const token = authAs(me);
  let filter, sorted;
  mock.method(Booking, 'find', (f) => { filter = f; const c = chain([makeBooking({ buyerId: me._id })]); c.sort = (s) => { sorted = s; return c; }; return c; });
  const r = await app.call('GET', '/api/bookings/my-bookings', { token });
  assert.equal(r.status, 200);
  assert.equal(String(filter.buyerId), String(me._id));
  assert.deepEqual(sorted, { bookingDate: -1 });
  assert.equal(typeof r.json[0].products[0].productId, 'string');
  assert.equal((await app.call('GET', '/api/bookings/my-bookings')).status, 401);
});

/* ---------------- cancel ---------------- */

test('cancel: owner only, atomic transition from Booked/Dispatched, products released, mails after the response', async () => {
  const me = makeUser(); const token = authAs(me); const sent = h.stubMail();
  const booking = makeBooking({ buyerId: me._id, status: 'Cancelled' });
  let filter, update;
  mock.method(Booking, 'findOneAndUpdate', (f, u) => { filter = f; update = u; return chain(booking); });
  let release;
  mock.method(Product, 'updateMany', async (f, u) => { release = { f, u }; return {}; });
  const r = await app.call('PUT', `/api/bookings/${booking._id}/cancel`, { token });
  assert.equal(r.status, 200);
  assert.equal(r.json.message, 'Booking cancelled successfully.');
  assert.equal(String(filter.buyerId), String(me._id));                       // ownership is part of the atomic filter
  assert.deepEqual(filter.status, { $in: ['Booked', 'Dispatched'] });
  assert.deepEqual(update, { $set: { status: 'Cancelled' } });
  assert.deepEqual(release.u, { $set: { isBooked: false } });
  assert.equal(release.f._id.$in.length, 1);
  await tick();
  assert.deepEqual(sent.map((m) => m.to).sort(), [me.email, 's@x.in', process.env.ADMIN_EMAIL].sort());
});

test('cancel: someone else\'s booking -> 404 (no existence leak), nothing modified; own booking in a final state -> 400', async () => {
  const attacker = makeUser(); const token = authAs(attacker);
  const release = mock.method(Product, 'updateMany', async () => ({}));
  mock.method(Booking, 'findOneAndUpdate', () => chain(null));                // filter (buyerId) does not match
  mock.method(Booking, 'exists', async () => null);
  const r = await app.call('PUT', `/api/bookings/${oid()}/cancel`, { token });
  assert.equal(r.status, 404);
  assert.equal(r.json.message, 'Booking not found.');
  assert.equal(release.mock.callCount(), 0);                                   // products of other people's orders are never released
  Booking.exists.mock.restore();
  mock.method(Booking, 'exists', async () => ({ _id: 1 }));                    // exists and is mine, but Cancelled/Delivered
  const r2 = await app.call('PUT', `/api/bookings/${oid()}/cancel`, { token });
  assert.equal(r2.status, 400);
  assert.equal(r2.json.message, 'Cannot cancel this booking.');
  assert.equal((await app.call('PUT', '/api/bookings/zzz/cancel', { token })).status, 404);
  assert.equal((await app.call('PUT', `/api/bookings/${oid()}/cancel`)).status, 401);
});

test('cancel: mail failure never fails the cancellation', async () => {
  const me = makeUser(); const token = authAs(me); h.stubMail({ fail: true });
  mock.method(Booking, 'findOneAndUpdate', () => chain(makeBooking({ buyerId: me._id, status: 'Cancelled' })));
  mock.method(Product, 'updateMany', async () => ({}));
  assert.equal((await app.call('PUT', `/api/bookings/${oid()}/cancel`, { token })).status, 200);
  await tick();
});
