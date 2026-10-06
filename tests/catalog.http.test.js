const h = require('./helpers');
const { test, afterEach, after, before } = require('node:test');
const assert = require('node:assert/strict');
const cloudinary = require('../src/config/cloudinary');
const Cart = require('../src/models/Cart');

const { mock, chain, oid, makeUser, makeProduct, makeBooking, authAs, User, Product, Booking } = h;
let app;
before(async () => { app = await h.startApp(); });
after(async () => { await app.close(); });
afterEach(() => mock.restoreAll());

const tick = () => new Promise((r) => setTimeout(r, 60)); // let post-response notifications finish
const PNG = Buffer.concat([Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex'), Buffer.alloc(64)]);

const stubCloudinary = () => {
  const calls = { uploaded: 0, destroyed: [] };
  mock.method(cloudinary.uploader, 'upload_stream', (opts, cb) => ({
    end: () => setImmediate(() => { calls.uploaded++; cb(null, { secure_url: `https://res.cloudinary.test/${calls.uploaded}.png`, public_id: `bw/${calls.uploaded}` }); }),
  }));
  mock.method(cloudinary.uploader, 'destroy', async (id) => { calls.destroyed.push(id); return {}; });
  return calls;
};

const multipart = async (method, path, fd, token) => {
  const res = await fetch(app.base + path, { method, headers: token ? { authorization: `Bearer ${token}` } : {}, body: fd });
  let json = null; try { json = await res.json(); } catch { /* none */ }
  return { status: res.status, json };
};
const productForm = (over = {}, files = [['a.png', 'image/png', PNG]]) => {
  const fd = new FormData();
  const f = { title: 'Calculator', price: '250', quantity: '1', description: 'Scientific', category: 'Electronics', ...over };
  for (const [k, v] of Object.entries(f)) if (v !== undefined) fd.append(k, v);
  for (const [name, type, buf] of files) fd.append('images', new Blob([buf], { type }), name);
  return fd;
};

/* ---------------- products: public reads ---------------- */

test('GET /products: only approved + not deleted; regex input is escaped (no crash, no ReDoS)', async () => {
  let filter;
  mock.method(Product, 'find', (f) => { filter = f; return chain([makeProduct()]); });
  const r = await app.call('GET', '/api/products?search=' + encodeURIComponent('(a+)+$[') + '&category=' + encodeURIComponent('C++ (new)'));
  assert.equal(r.status, 200);
  assert.equal(filter.status, 'approved');
  assert.deepEqual(filter.isDeleted, { $ne: true });
  assert.equal(filter.title.$regex, '\\(a\\+\\)\\+\\$\\[');            // literal, not a pattern
  assert.equal(filter.category.source, '^C\\+\\+ \\(new\\)$');
  assert.doesNotThrow(() => new RegExp(filter.title.$regex, 'i'));
});

test('GET /products: repeated/array query params cannot become operators', async () => {
  let filter;
  mock.method(Product, 'find', (f) => { filter = f; return chain([]); });
  const r = await app.call('GET', '/api/products?search=a&search=b&category[$ne]=x');
  assert.equal(r.status, 200);
  assert.equal(filter.title.$regex, 'a');
  assert.equal(filter.category, undefined);                              // "category[$ne]" is just an unknown flat key
});

test('product JSON never exposes seller PII (sellerEmail/sellerName), keeps sellerId as a string', async () => {
  const p = makeProduct();
  mock.method(Product, 'find', () => chain([p]));
  mock.method(Product, 'findOne', () => chain(p));
  const list = await app.call('GET', '/api/products');
  const detail = await app.call('GET', `/api/products/${p._id}`);
  for (const body of [list.json[0], detail.json]) {
    assert.equal('sellerEmail' in body, false);
    assert.equal('sellerName' in body, false);
    assert.equal(typeof body.sellerId, 'string');                       // EditProduct compares String(product.sellerId)
    for (const k of ['_id', 'title', 'price', 'quantity', 'description', 'imageUrl', 'category', 'status', 'isBooked']) assert.ok(k in body, k);
  }
});

test('GET /products/:id: public, works for pending/rejected (EditProduct), 404 for missing/deleted/invalid id', async () => {
  const pending = makeProduct({ status: 'pending' });
  let filter;
  mock.method(Product, 'findOne', (f) => { filter = f; return chain(pending); });
  const ok = await app.call('GET', `/api/products/${pending._id}`);                    // no token
  assert.equal(ok.status, 200);
  assert.equal(ok.json.status, 'pending');
  assert.equal(filter.status, undefined);                                              // NOT limited to approved
  assert.deepEqual(filter.isDeleted, { $ne: true });
  mock.restoreAll();
  mock.method(Product, 'findOne', () => chain(null));
  assert.equal((await app.call('GET', `/api/products/${oid()}`)).status, 404);
  const bad = await app.call('GET', '/api/products/not-an-id');
  assert.equal(bad.status, 404);
  assert.equal(bad.json.message, 'Product not found.');                                // controlled, no CastError
});

test('GET /products/category/:c: approved, not deleted, limit 11', async () => {
  let filter, lim;
  mock.method(Product, 'find', (f) => { filter = f; const c = chain([]); c.limit = (n) => { lim = n; return c; }; return c; });
  assert.equal((await app.call('GET', '/api/products/category/Lab%20Equipment')).status, 200);
  assert.equal(filter.category, 'Lab Equipment');
  assert.equal(filter.status, 'approved');
  assert.equal(lim, 11);
});

test('GET /products/my-products: requires auth; scoped to the caller', async () => {
  assert.equal((await app.call('GET', '/api/products/my-products')).status, 401);
  const me = makeUser();
  const token = authAs(me);
  let filter;
  mock.method(Product, 'find', (f) => { filter = f; return chain([]); });
  assert.equal((await app.call('GET', '/api/products/my-products', { token })).status, 200);
  assert.equal(String(filter.sellerId), String(me._id));
  assert.deepEqual(filter.isDeleted, { $ne: true });
});

/* ---------------- products: create (multipart + upload hardening) ---------------- */

test('POST /products: valid -> 201, images hosted, seller+admin mails sent AFTER the response', async () => {
  const me = makeUser(); const token = authAs(me);
  const calls = stubCloudinary(); const sent = h.stubMail();
  let created;
  mock.method(Product, 'create', async (doc) => { created = doc; return makeProduct({ ...doc, sellerId: me._id }); });
  const r = await multipart('POST', '/api/products', productForm(), token);
  assert.equal(r.status, 201);
  assert.equal(created.price, 250);
  assert.equal(created.quantity, 1);
  assert.deepEqual(created.imageUrl, ['https://res.cloudinary.test/1.png']);
  assert.equal(String(created.sellerId), String(me._id));
  assert.equal(created.sellerEmail, me.email);
  assert.equal('sellerEmail' in r.json, false);
  await tick();
  assert.deepEqual(sent.map((m) => m.to).sort(), [process.env.ADMIN_EMAIL, me.email].sort());
});

test('POST /products: mail failure does NOT turn a saved product into a 500', async () => {
  const me = makeUser(); const token = authAs(me);
  stubCloudinary(); h.stubMail({ fail: true });
  mock.method(Product, 'create', async (doc) => makeProduct({ ...doc, sellerId: me._id }));
  const r = await multipart('POST', '/api/products', productForm(), token);
  assert.equal(r.status, 201);
});

test('POST /products: invalid fields -> 400 and the already-uploaded images are cleaned up', async () => {
  const me = makeUser(); const token = authAs(me);
  const calls = stubCloudinary();
  const create = mock.method(Product, 'create', async () => { throw new Error('must not be called'); });
  for (const over of [{ price: '-1' }, { price: 'abc' }, { price: '0' }, { quantity: '0' }, { quantity: '1.5' }, { title: '   ' }, { description: undefined }]) {
    calls.destroyed.length = 0;
    const r = await multipart('POST', '/api/products', productForm(over), token);
    assert.equal(r.status, 400, JSON.stringify(over));
    assert.equal(typeof r.json.message, 'string');
    assert.equal(calls.destroyed.length, 1, 'uploaded image must be removed again');
  }
  assert.equal(create.mock.callCount(), 0);
});

test('POST /products: upload security - spoofed type, wrong extension, oversize, no image, too many', async () => {
  const me = makeUser(); const token = authAs(me);
  const calls = stubCloudinary();
  mock.method(Product, 'create', async (doc) => makeProduct(doc));
  // 1) PHP/text content disguised as image/png + .png  -> rejected by magic-byte check, never uploaded
  let r = await multipart('POST', '/api/products', productForm({}, [['evil.png', 'image/png', Buffer.from('<?php system($_GET[0]); ?>')]]), token);
  assert.equal(r.status, 400); assert.equal(r.json.message, 'Invalid image format'); assert.equal(calls.uploaded, 0);
  // 2) Windows executable renamed to .jpg
  r = await multipart('POST', '/api/products', productForm({}, [['a.jpg', 'image/jpeg', Buffer.concat([Buffer.from('4d5a9000030000000400000000', 'hex'), Buffer.alloc(64)])]]), token);
  assert.equal(r.status, 400); assert.equal(calls.uploaded, 0);
  // 3) SVG (scriptable) is not an allowed type even with an image/* mime
  r = await multipart('POST', '/api/products', productForm({}, [['a.svg', 'image/svg+xml', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>')]]), token);
  assert.equal(r.status, 400); assert.equal(r.json.message, 'Invalid image format');
  // 4) non-image mime
  r = await multipart('POST', '/api/products', productForm({}, [['a.png', 'application/pdf', PNG]]), token);
  assert.equal(r.status, 400); assert.equal(r.json.message, 'Only image files allowed');
  // 5) > 5 MB
  r = await multipart('POST', '/api/products', productForm({}, [['big.png', 'image/png', Buffer.concat([PNG, Buffer.alloc(5 * 1024 * 1024)])]]), token);
  assert.equal(r.status, 413); assert.equal(r.json.message, 'File too large. Maximum size is 5MB.');
  // 6) no image
  r = await multipart('POST', '/api/products', productForm({}, []), token);
  assert.equal(r.status, 400); assert.equal(r.json.message, 'At least one image is required');
  // 7) 6 images
  r = await multipart('POST', '/api/products', productForm({}, Array.from({ length: 6 }, (_, i) => [`${i}.png`, 'image/png', PNG])), token);
  assert.equal(r.status, 400);
  assert.equal(calls.uploaded, 0, 'nothing invalid may ever reach Cloudinary');
  // 8) unauthenticated
  assert.equal((await multipart('POST', '/api/products', productForm())).status, 401);
});

test('POST /products: a genuine PNG/WebP/JPEG is accepted (no false rejection)', async () => {
  const me = makeUser(); const token = authAs(me);
  stubCloudinary(); h.stubMail();
  mock.method(Product, 'create', async (doc) => makeProduct({ ...doc, sellerId: me._id }));
  const jpeg = Buffer.concat([Buffer.from('ffd8ffe000104a46494600010100000100010000', 'hex'), Buffer.alloc(64), Buffer.from('ffd9', 'hex')]);
  const webp = Buffer.concat([Buffer.from('52494646', 'hex'), Buffer.from([0x24, 0, 0, 0]), Buffer.from('57454250565038204', 'hex').subarray(0, 8), Buffer.alloc(40)]);
  const r = await multipart('POST', '/api/products', productForm({}, [['a.png', 'image/png', PNG], ['b.jpg', 'image/jpeg', jpeg], ['c.webp', 'image/webp', webp]]), token);
  assert.equal(r.status, 201, JSON.stringify(r.json));
});

/* ---------------- products: update / delete authorization ---------------- */

test('PUT /products/:id: owner only; validation; no re-moderation; 404s', async () => {
  const me = makeUser(); const token = authAs(me);
  const own = makeProduct({ sellerId: me._id, status: 'approved' });
  mock.method(Product, 'findOne', () => chain(own));
  mock.method(own, 'save', async () => own);
  const ok = await app.call('PUT', `/api/products/${own._id}`, { token, body: { title: 'New', price: 99, quantity: 3, description: 'd', category: 'Books' } });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.message, 'Product updated successfully.');
  assert.equal(ok.json.product.title, 'New');
  assert.equal(ok.json.product.quantity, 3);
  assert.equal(ok.json.product.status, 'approved');                   // unchanged: no automatic re-moderation
  assert.equal('sellerEmail' in ok.json.product, false);
  assert.equal((await app.call('PUT', `/api/products/${own._id}`, { token, body: { price: -5 } })).status, 400);
  assert.equal((await app.call('PUT', `/api/products/${own._id}`, { token, body: { price: { $gt: 0 } } })).status, 400);
  const ignored = await app.call('PUT', `/api/products/${own._id}`, { token, body: { title: 'T2', status: 'approved', sellerId: String(oid()), isBooked: true } });
  assert.equal(ignored.status, 200);
  assert.equal(String(own.sellerId), String(me._id));                   // ownership/status fields cannot be changed through this route
  assert.equal(own.isBooked, false);
  assert.equal((await app.call('PUT', '/api/products/xyz', { token, body: {} })).status, 404);
  assert.equal((await app.call('PUT', `/api/products/${own._id}`, { body: {} })).status, 401);
  mock.restoreAll();
  authAs(me);
  mock.method(Product, 'findOne', () => chain(null));
  assert.equal((await app.call('PUT', `/api/products/${oid()}`, { token, body: { title: 'x' } })).status, 404);
});

test('PUT/DELETE /products/:id by another user -> 403 { message }, nothing modified', async () => {
  const attacker = makeUser(); const token = authAs(attacker);
  const victim = makeProduct();                                          // owned by someone else
  mock.method(Product, 'findOne', () => chain(victim));
  const save = mock.method(victim, 'save', async () => victim);
  const del = mock.method(Product, 'deleteOne', async () => ({ deletedCount: 1 }));
  const upd = mock.method(Product, 'updateOne', async () => ({}));
  mock.method(Booking, 'findOne', () => chain(null));
  const put = await app.call('PUT', `/api/products/${victim._id}`, { token, body: { title: 'hacked' } });
  const dl = await app.call('DELETE', `/api/products/${victim._id}`, { token });
  assert.equal(put.status, 403);
  assert.equal(dl.status, 403);
  assert.equal(typeof dl.json.message, 'string');                        // previously { error: { code, message } }
  assert.equal(dl.json.error, undefined);
  assert.equal(save.mock.callCount() + del.mock.callCount() + upd.mock.callCount(), 0);
});

test('DELETE /products/:id: never booked -> hard delete; seller+admin notified after response', async () => {
  const me = makeUser(); const token = authAs(me); const sent = h.stubMail();
  const p = makeProduct({ sellerId: me._id });
  mock.method(Product, 'findOne', () => chain(p));
  mock.method(Booking, 'findOne', () => chain(null));
  let delFilter;
  mock.method(Product, 'deleteOne', async (f) => { delFilter = f; return { deletedCount: 1 }; });
  const r = await app.call('DELETE', `/api/products/${p._id}`, { token });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { message: 'Product deleted successfully.', deletionType: 'hard' });
  assert.deepEqual(delFilter.isBooked, { $ne: true });                    // atomic guard against a concurrent booking
  await tick();
  assert.equal(sent.length, 2);
});

test('DELETE /products/:id: booked -> soft delete (buyer+seller+admin mails); race (deletedCount 0) -> soft delete', async () => {
  const me = makeUser(); const token = authAs(me); let sent = h.stubMail();
  const p = makeProduct({ sellerId: me._id, isBooked: true });
  const buyer = makeUser({ email: 'buyer@brainwareuniversity.ac.in', name: 'Buyer' });
  const booking = makeBooking(); booking.buyerId = buyer;
  mock.method(Product, 'findOne', () => chain(p));
  mock.method(Booking, 'findOne', () => chain(booking));
  const del = mock.method(Product, 'deleteOne', async () => ({ deletedCount: 1 }));
  let upd;
  mock.method(Product, 'updateOne', async (f, u) => { upd = u; return {}; });
  const r = await app.call('DELETE', `/api/products/${p._id}`, { token });
  assert.equal(r.status, 200);
  assert.equal(r.json.deletionType, 'soft');
  assert.equal(del.mock.callCount(), 0);
  assert.equal(upd.$set.isDeleted, true);
  await tick();
  assert.deepEqual(sent.map((m) => m.to).sort(), [buyer.email, me.email, process.env.ADMIN_EMAIL].sort());
  // race: no booking found, but by the time of the delete someone booked it
  mock.restoreAll(); authAs(me); sent = h.stubMail();
  mock.method(Product, 'findOne', () => chain(makeProduct({ sellerId: me._id })));
  mock.method(Booking, 'findOne', () => chain(null));
  mock.method(Product, 'deleteOne', async () => ({ deletedCount: 0 }));
  let upd2; mock.method(Product, 'updateOne', async (f, u) => { upd2 = u; return {}; });
  const r2 = await app.call('DELETE', `/api/products/${oid()}`, { token });
  assert.equal(r2.json.deletionType, 'soft');
  assert.equal(upd2.$set.isDeleted, true);
});

test('DELETE /products/:id: mail failure does not fail the deletion; missing/deleted -> 404', async () => {
  const me = makeUser(); const token = authAs(me); h.stubMail({ fail: true });
  mock.method(Product, 'findOne', () => chain(makeProduct({ sellerId: me._id })));
  mock.method(Booking, 'findOne', () => chain(null));
  mock.method(Product, 'deleteOne', async () => ({ deletedCount: 1 }));
  assert.equal((await app.call('DELETE', `/api/products/${oid()}`, { token })).status, 200);
  mock.restoreAll(); authAs(me);
  mock.method(Product, 'findOne', () => chain(null));
  assert.equal((await app.call('DELETE', `/api/products/${oid()}`, { token })).status, 404);
  assert.equal((await app.call('DELETE', '/api/products/bad', { token })).status, 404);
});

/* ---------------- admin ---------------- */

test('admin routes: 401 without token, 403 for normal users (role read from the DB, not the client)', async () => {
  assert.equal((await app.call('GET', '/api/admin/products/pending')).status, 401);
  const student = makeUser(); const token = authAs(student);
  assert.equal((await app.call('GET', '/api/admin/products/pending', { token })).status, 403);
  assert.equal((await app.call('PUT', `/api/admin/products/${oid()}/status`, { token, body: { status: 'approved' } })).status, 403);
  assert.equal((await app.call('GET', '/api/admin/products/pending', { token, headers: { 'x-role': 'admin' } })).status, 403);
});

test('GET /admin/products/pending: excludes deleted, sellerId populated {name,email}, survives a missing seller', async () => {
  const admin = makeUser({ role: 'admin' }); const token = authAs(admin);
  const base = makeProduct({ status: 'pending' });
  // A populated product as Mongoose would return it: sellerId replaced by { _id, name, email }.
  const a = { sellerName: 'Snapshot', sellerEmail: 'snap@x.in', toJSON: () => ({ ...base.toJSON(), sellerId: { _id: oid(), name: 'Alice', email: 'alice@brainwareuniversity.ac.in' } }) };
  // A product whose seller account no longer exists: populate() yields null.
  const orphan = { sellerName: 'Gone Seller', sellerEmail: 'gone@brainwareuniversity.ac.in', toJSON: () => ({ ...base.toJSON(), sellerId: null }) };
  let filter;
  mock.method(Product, 'find', (f) => { filter = f; return chain([a, orphan]); });
  const r = await app.call('GET', '/api/admin/products/pending', { token });
  assert.equal(r.status, 200);
  assert.equal(filter.status, 'pending');
  assert.deepEqual(filter.isDeleted, { $ne: true });
  assert.equal(r.json[0].sellerId.name, 'Alice');
  assert.equal(r.json[1].sellerId.name, 'Gone Seller');                  // admin page would crash on null
  assert.equal(r.json[1].sellerId.email, 'gone@brainwareuniversity.ac.in');
});

test('PUT /admin/products/:id/status: approve/reject, seller mailed after; mail failure still 200; validation', async () => {
  const admin = makeUser({ role: 'admin' }); const token = authAs(admin); const sent = h.stubMail();
  const p = makeProduct({ status: 'approved' });
  let filter;
  mock.method(Product, 'findOneAndUpdate', (f) => { filter = f; return chain(p); });
  const ok = await app.call('PUT', `/api/admin/products/${p._id}/status`, { token, body: { status: 'approved' } });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.message, 'Product approved successfully.');
  assert.deepEqual(filter.isDeleted, { $ne: true });
  await tick();
  assert.equal(sent.length, 1);
  assert.match(sent[0].subject, /approved/i);
  h.stubMail({ fail: true });
  assert.equal((await app.call('PUT', `/api/admin/products/${p._id}/status`, { token, body: { status: 'rejected' } })).status, 200);
  for (const status of ['pending', 'hacked', 123, { $ne: 'x' }, undefined]) {
    assert.equal((await app.call('PUT', `/api/admin/products/${p._id}/status`, { token, body: { status } })).status, 400, String(JSON.stringify(status)));
  }
  assert.equal((await app.call('PUT', '/api/admin/products/bad/status', { token, body: { status: 'approved' } })).status, 404);
  mock.restoreAll(); authAs(admin);
  mock.method(Product, 'findOneAndUpdate', () => chain(null));
  assert.equal((await app.call('PUT', `/api/admin/products/${oid()}/status`, { token, body: { status: 'approved' } })).status, 404);
});

/* ---------------- profile / contact ---------------- */

test('PUT /profile: studentCode is saved and returned; no avatar override; no secrets in response', async () => {
  const me = makeUser(); const token = authAs(me);
  let upd;
  mock.method(User, 'findByIdAndUpdate', (id, u) => { upd = u; return chain(makeUser({ ...me.toObject(), ...u.$set, resetPasswordToken: 'x', emailOTP: 'y' })); });
  const r = await app.call('PUT', '/api/profile', { token, body: { name: 'New Name', studentCode: ' BWU/22/1 ', programType: 'PG', department: 'IT', year: '2nd Year', avatar: 'http://tracker.evil/p.gif', role: 'admin', email: 'x@y.z', password: 'p' } });
  assert.equal(r.status, 200);
  assert.deepEqual(Object.keys(upd.$set).sort(), ['department', 'name', 'programType', 'studentCode', 'year']);
  assert.equal(upd.$set.studentCode, 'BWU/22/1');
  assert.equal(r.json.studentCode, 'BWU/22/1');
  for (const k of ['password', 'emailOTP', 'resetPasswordToken']) assert.equal(k in r.json, false);
  assert.equal(r.json._id, String(me._id));                              // bare user object, as EditProfile expects
});

test('PUT /profile: invalid input -> 400', async () => {
  const token = authAs(makeUser());
  mock.method(User, 'findByIdAndUpdate', () => chain(makeUser()));
  for (const body of [{ programType: 'Wizard' }, { name: '   ' }, { name: { $ne: 1 } }, { studentCode: 5 }, { department: ['a'] }]) {
    assert.equal((await app.call('PUT', '/api/profile', { token, body })).status, 400, JSON.stringify(body));
  }
  assert.equal((await app.call('PUT', '/api/profile', { body: {} })).status, 401);
});

test('POST /profile/avatar: validated upload -> bare user; fake image rejected', async () => {
  const me = makeUser(); const token = authAs(me); stubCloudinary();
  let upd;
  mock.method(User, 'findByIdAndUpdate', (id, u) => { upd = u; return chain(makeUser({ ...me.toObject(), avatar: u.avatar })); });
  const fd = new FormData(); fd.append('avatar', new Blob([PNG], { type: 'image/png' }), 'me.png');
  const r = await multipart('POST', '/api/profile/avatar', fd, token);
  assert.equal(r.status, 200);
  assert.equal(r.json.avatar, 'https://res.cloudinary.test/1.png');
  assert.equal('password' in r.json, false);
  const bad = new FormData(); bad.append('avatar', new Blob([Buffer.from('not an image')], { type: 'image/png' }), 'me.png');
  assert.equal((await multipart('POST', '/api/profile/avatar', bad, token)).status, 400);
  assert.equal((await multipart('POST', '/api/profile/avatar', new FormData(), token)).status, 400);
});

test('PUT /users/contact: validation and success (response has no secrets)', async () => {
  const me = makeUser(); const token = authAs(me);
  let upd;
  mock.method(User, 'findByIdAndUpdate', (id, u) => { upd = u; return chain(makeUser({ ...me.toObject(), ...u.$set })); });
  const ok = await app.call('PUT', '/api/users/contact', { token, body: { phoneNumber: '98765-43210', contactPreference: 'whatsapp' } });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.message, 'Contact information updated successfully.');
  assert.equal(upd.$set.phoneNumber, '9876543210');
  assert.equal(ok.json.user.contactPreference, 'whatsapp');
  assert.equal('password' in ok.json.user, false);
  for (const body of [{}, { phoneNumber: '123' }, { phoneNumber: 9876543210 }, { phoneNumber: { $ne: 1 } }, { phoneNumber: '9876543210', contactPreference: 'carrier-pigeon' }]) {
    assert.equal((await app.call('PUT', '/api/users/contact', { token, body })).status, 400, JSON.stringify(body));
  }
  assert.equal((await app.call('PUT', '/api/users/contact', { body: {} })).status, 401);
});

/* ---------------- cart ---------------- */

const cartDoc = (items = []) => ({ toObject: () => ({ userId: String(oid()), items }) });

test('cart: unauthenticated -> 401 on every route (frontend relies on the 401)', async () => {
  const id = oid();
  for (const [m, p] of [['GET', '/api/cart'], ['POST', '/api/cart/add'], ['PUT', `/api/cart/item/${id}`], ['DELETE', `/api/cart/item/${id}`], ['POST', '/api/cart/clear']]) {
    const r = await app.call(m, p, m === 'GET' || m === 'DELETE' ? {} : { body: {} });
    assert.equal(r.status, 401, `${m} ${p}`);
  }
});

test('cart add: rejects invalid id/quantity, missing, unapproved, deleted and already-booked products', async () => {
  const token = authAs(makeUser());
  const write = mock.method(Cart, 'findOneAndUpdate', () => chain(cartDoc()));
  for (const body of [{ productId: 'x' }, { productId: { $ne: null } }, {}, { productId: String(oid()), quantity: 0 }, { productId: String(oid()), quantity: -2 }, { productId: String(oid()), quantity: 'a' }, { productId: String(oid()), quantity: 1.5 }]) {
    const r = await app.call('POST', '/api/cart/add', { token, body });
    assert.equal(r.status, 400, JSON.stringify(body));
  }
  const cases = [
    [null, 'Product not available.'],
    [makeProduct({ status: 'pending' }), 'Product not available.'],
    [makeProduct({ status: 'rejected' }), 'Product not available.'],
    [makeProduct({ isBooked: true }), 'Product is already booked.'],
  ];
  for (const [prod, msg] of cases) {
    mock.method(Product, 'findOne', () => chain(prod));
    const r = await app.call('POST', '/api/cart/add', { token, body: { productId: String(oid()) } });
    assert.equal(r.status, 400);
    assert.equal(r.json.message, msg);
    Product.findOne.mock.restore();
  }
  assert.equal(write.mock.callCount(), 0);
});

test('cart add: new item pushed with seller snapshot; existing item quantity bumped; response keeps { message, cart.items }', async () => {
  const token = authAs(makeUser());
  const p = makeProduct();
  p.sellerId = p.sellerId; // ObjectId (populate returns the same when seller is gone) -> falls back to snapshots
  mock.method(Product, 'findOne', () => chain(p));
  mock.method(Cart, 'updateOne', async () => ({}));
  const ops = [];
  const item = { productId: p._id, title: p.title, price: p.price, quantity: 1, imageUrl: p.imageUrl };
  mock.method(Cart, 'findOneAndUpdate', (f, u) => {
    ops.push(u);
    if (u.$inc) return chain(null);                                       // not in cart yet
    return chain(cartDoc([item]));
  });
  mock.method(Product, 'find', () => chain([p]));
  const r = await app.call('POST', '/api/cart/add', { token, body: { productId: String(p._id), quantity: 1 } });
  assert.equal(r.status, 200);
  assert.equal(r.json.message, 'Added to cart');
  assert.equal(r.json.cart.items.length, 1);
  const push = ops.find((o) => o.$push).$push.items;
  assert.equal(push.sellerName, 'Seller');                               // snapshot fallback
  assert.equal(push.sellerEmail, 'seller@brainwareuniversity.ac.in');
  assert.equal(push.quantity, 1);
});

test('cart view: refreshes live price/title/image; flags (never removes) unavailable items; tolerates legacy items without seller fields', async () => {
  const token = authAs(makeUser());
  const live = makeProduct({ price: 300, title: 'Live Title' });
  const gone = oid(); const booked = makeProduct({ isBooked: true }); const pending = makeProduct({ status: 'pending' }); const deleted = makeProduct({ isDeleted: true });
  const stale = (id, title = 'old') => ({ productId: id, title, price: 50, quantity: 2, imageUrl: [] });          // no sellerId/sellerName/sellerEmail
  mock.method(Cart, 'findOneAndUpdate', () => chain(cartDoc([stale(live._id), stale(gone), stale(booked._id), stale(pending._id), stale(deleted._id)])));
  mock.method(Product, 'find', () => chain([live, booked, pending, deleted]));
  const r = await app.call('GET', '/api/cart', { token });
  assert.equal(r.status, 200);
  const items = r.json.items;
  assert.equal(items.length, 5);                                          // nothing is silently dropped
  assert.equal(items[0].price, 300);
  assert.equal(items[0].title, 'Live Title');
  assert.equal(items[0].quantity, 2);
  assert.equal(items[0].unavailable, undefined);
  assert.deepEqual(items.slice(1).map((i) => i.unavailable), [true, true, true, true]);
});

test('cart update/remove/clear: contract preserved, validation added, qty<=0 removes', async () => {
  const token = authAs(makeUser());
  const id = String(oid());
  const updates = [];
  mock.method(Cart, 'findOneAndUpdate', (f, u) => { updates.push(u); return chain(cartDoc([])); });
  mock.method(Product, 'find', () => chain([]));
  const up = await app.call('PUT', `/api/cart/item/${id}`, { token, body: { quantity: 3 } });
  assert.equal(up.status, 200); assert.ok(Array.isArray(up.json.cart.items));
  assert.equal(updates[0].$set['items.$.quantity'], 3);
  await app.call('PUT', `/api/cart/item/${id}`, { token, body: { quantity: 0 } });
  assert.ok(updates[1].$pull);                                            // removed
  for (const quantity of ['abc', 1.5, 5000, null, { $gt: 1 }]) {
    assert.equal((await app.call('PUT', `/api/cart/item/${id}`, { token, body: { quantity } })).status, 400, String(JSON.stringify(quantity)));
  }
  assert.equal((await app.call('PUT', '/api/cart/item/zzz', { token, body: { quantity: 1 } })).status, 400);
  assert.equal((await app.call('DELETE', '/api/cart/item/zzz', { token })).status, 400);
  const rm = await app.call('DELETE', `/api/cart/item/${id}`, { token });
  assert.equal(rm.status, 200); assert.ok(Array.isArray(rm.json.cart.items));
  const clr = await app.call('POST', '/api/cart/clear', { token });
  assert.equal(clr.status, 200); assert.deepEqual(clr.json.cart.items, []);
  assert.deepEqual(updates[updates.length - 1].$set, { items: [] });
});

test('cart update: unknown item -> 404; no cart -> 404', async () => {
  const token = authAs(makeUser());
  mock.method(Cart, 'findOneAndUpdate', () => chain(null));
  mock.method(Cart, 'exists', async () => ({ _id: 1 }));
  const r = await app.call('PUT', `/api/cart/item/${oid()}`, { token, body: { quantity: 2 } });
  assert.equal(r.status, 404); assert.equal(r.json.message, 'Item not found.');
  Cart.exists.mock.restore();
  mock.method(Cart, 'exists', async () => null);
  assert.equal((await app.call('PUT', `/api/cart/item/${oid()}`, { token, body: { quantity: 2 } })).json.message, 'Cart not found.');
  assert.equal((await app.call('POST', '/api/cart/clear', { token })).status, 404);
});
