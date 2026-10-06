const h = require('./helpers');
const { test, afterEach, after, before } = require('node:test');
const assert = require('node:assert/strict');
const { mock, chain, User } = h;
let app;
before(async () => { app = await h.startApp(); });
after(async () => { await app.close(); });
afterEach(() => mock.restoreAll());

const signupBody = (over = {}) => ({
  name: 'New Student', email: 'new@brainwareuniversity.ac.in', password: 'secret1',
  programType: 'UG', department: 'CSE', year: '1st Year', ...over,
});

test('signup: validation (domain, missing fields, enum, weak password, operator injection)', async () => {
  mock.method(User, 'findOne', () => chain(null));
  const bad = [
    [signupBody({ email: 'x@gmail.com' }), 'Invalid email'],
    [signupBody({ name: '' }), 'All required fields are required.'],
    [signupBody({ programType: 'Hacker' }), 'Invalid program type.'],
    [signupBody({ password: '123' }), null],
    [signupBody({ email: { $ne: null } }), 'Invalid request payload.'],
    [signupBody({ password: { $gt: '' } }), null],
  ];
  for (const [body, msg] of bad) {
    const r = await app.call('POST', '/api/auth/signup', { body });
    assert.equal(r.status, 400, JSON.stringify(body));
    if (msg) assert.equal(r.json.message, msg);
  }
});

