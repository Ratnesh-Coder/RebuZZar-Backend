// Test environment: fake, non-secret values. Must be set before the app is required.
Object.assign(process.env, {
  NODE_ENV: 'test',
  JWT_SECRET: 'test-secret-test-secret-test-secret-0123456789',
  JWT_EXPIRES_IN: '2h',
  FRONTEND_URL: 'http://frontend.test',
  CORS_ORIGIN: 'http://frontend.test',
  EMAIL_USER: 'sender@test.local',
  EMAIL_PASS: 'x',
  ADMIN_EMAIL: 'admin@test.local',
  GOOGLE_CLIENT_ID: 'test-client-id',
  GOOGLE_CLIENT_SECRET: 'test-client-secret',
  GOOGLE_CALLBACK_URL: 'http://backend.test/api/auth/google/callback',
  CLOUDINARY_CLOUD_NAME: 'test',
  CLOUDINARY_API_KEY: 'test',
  CLOUDINARY_API_SECRET: 'test',
});

const mongoose = require('mongoose');
const { mock } = require('node:test');
const User = require('../src/models/User');
const Product = require('../src/models/Product');
const Booking = require('../src/models/Booking');
const { signToken } = require('../src/utils/token');
const emailService = require('../src/services/email/email.service');

/** Thenable stand-in for a Mongoose query: supports the chain methods the code uses. */
const chain = (value) => {
  const c = {
    populate: () => c, select: () => c, sort: () => c, limit: () => c, lean: () => c,
    then: (res, rej) => Promise.resolve(value).then(res, rej),
    catch: (fn) => Promise.resolve(value).catch(fn),
  };
  return c;
};

const oid = () => new mongoose.Types.ObjectId();

const makeUser = (over = {}) => new User({
  name: 'Test User', email: 'user@brainwareuniversity.ac.in', password: 'hashed',
  programType: 'UG', department: 'CSE', year: '1st Year', isVerified: true, ...over,
});

const makeProduct = (over = {}) => new Product({
  title: 'Book', price: 100, quantity: 1, description: 'desc', imageUrl: ['http://img/1.jpg'], category: 'Books',
  sellerId: oid(), sellerName: 'Seller', sellerEmail: 'seller@brainwareuniversity.ac.in', status: 'approved', ...over,
});

const makeBooking = (over = {}) => new Booking({
  buyerId: oid(), buyerName: 'Buyer', buyerEmail: 'buyer@brainwareuniversity.ac.in', totalPrice: 100,
  products: [{ productId: oid(), title: 'Book', imageUrl: ['u'], quantity: 1, price: 100, sellerName: 'S', sellerEmail: 's@x.in' }],
  ...over,
});

/** Make the auth middleware resolve `user` for tokens issued to it. */
const authAs = (user) => {
  mock.method(User, 'findById', () => chain(user));
  return signToken(user._id);
};

/** Stub SMTP transport that records mails (or fails on demand). */
const stubMail = ({ fail = false } = {}) => {
  const sent = [];
  emailService.setTransporter({
    sendMail: async (m) => { if (fail) throw new Error('SMTP down'); sent.push(m); },
  });
  return sent;
};

const startApp = async () => {
  const app = require('../src/app');
  const server = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, { token, body, headers } = {}) => {
    const res = await fetch(base + path, {
      method,
      redirect: 'manual',
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let json = null;
    try { json = await res.json(); } catch { /* no body */ }
    return { status: res.status, json, headers: res.headers };
  };
  return { server, base, call, close: () => new Promise((r) => server.close(r)) };
};

module.exports = { mongoose, mock, chain, oid, makeUser, makeProduct, makeBooking, authAs, stubMail, startApp, User, Product, Booking };
