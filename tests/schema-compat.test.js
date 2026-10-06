/**
 * Schema-level tolerance: documents written by the legacy schema must still VALIDATE under the current
 * models (this is what protects any code path that uses .save()). No database needed.
 */
const h = require('./helpers');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const Cart = require('../src/models/Cart');
const { oid, User, Product, Booking } = h;

const errs = (doc) => { const e = doc.validateSync(); return e ? Object.keys(e.errors) : []; };

test('legacy Product (no sellerName/sellerEmail/isDeleted/isBooked/deletedAt) validates; defaults fill the gaps', () => {
  const p = new Product({ title: 't', price: 1, quantity: 1, description: 'd', imageUrl: ['u'], category: 'c', sellerId: oid() });
  assert.deepEqual(errs(p), []);
  assert.equal(p.isDeleted, false);
  assert.equal(p.isBooked, false);
});

test('legacy Cart items (no sellerId/sellerName/sellerEmail) validate', () => {
  const c = new Cart({ userId: oid(), items: [{ productId: oid(), title: 't', price: 5, quantity: 2 }] });
  assert.deepEqual(errs(c), []);
});

test('legacy User (no studentCode/phoneNumber/contactPreference/OTP counters) validates; studentCode is a real, persisted field', () => {
  const u = new User({ name: 'n', email: 'a@b.c', password: 'x', programType: 'UG', department: 'd', year: '1st Year' });
  assert.deepEqual(errs(u), []);
  assert.equal(u.contactPreference, 'both');
  const withCode = new User({ name: 'n', email: 'a@b.c', password: 'x', programType: 'UG', department: 'd', year: '1', studentCode: ' ABC ' });
  assert.equal(withCode.toObject().studentCode, 'ABC');
});

test('legacy Booking (items without imageUrl) validates', () => {
  const b = new Booking({
    buyerId: oid(), buyerName: 'n', buyerEmail: 'e@x.in', totalPrice: 1,
    products: [{ productId: oid(), title: 't', quantity: 1, price: 1, sellerName: 's', sellerEmail: 's@x.in' }],
  });
  assert.deepEqual(errs(b), []);
});

test('model JSON never contains secrets even if a controller forgets to serialize', () => {
  const u = new User({ name: 'n', email: 'a@b.c', password: 'HASH', programType: 'UG', department: 'd', year: '1', emailOTP: 'o', resetPasswordToken: 'r' });
  const json = JSON.parse(JSON.stringify(u));
  for (const k of ['password', 'emailOTP', 'resetPasswordToken', 'emailOTPExpires', 'resetPasswordExpires']) assert.equal(k in json, false, k);
  const p = JSON.parse(JSON.stringify(new Product({ title: 't', price: 1, quantity: 1, description: 'd', imageUrl: ['u'], category: 'c', sellerId: oid(), sellerEmail: 'x@y.z', sellerName: 'S' })));
  assert.equal('sellerEmail' in p || 'sellerName' in p, false);
});
