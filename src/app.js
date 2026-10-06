const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const passport = require('passport');

const { getCorsOrigin } = require('./config/env');
require('./config/cloudinary');
require('./config/passport');

const sanitize = require('./middlewares/sanitize');
const { notFound, errorHandler } = require('./middlewares/errorHandler');

/**
 * Express app. It does NOT connect to the database or read .env: src/server.js does that
 * before requiring this file, which keeps the app importable (and testable) on its own.
 */
const app = express();

// Behind a reverse proxy (Render, Heroku, nginx ...) set TRUST_PROXY=1 so rate limiting
// and logs see the real client IP instead of the proxy's.
if (process.env.TRUST_PROXY) {
  const v = process.env.TRUST_PROXY;
  app.set('trust proxy', /^\d+$/.test(v) ? Number(v) : v === 'true' ? true : v);
}
app.disable('x-powered-by');

// Global middleware
app.use(helmet());
app.use(cors({ origin: getCorsOrigin() }));
app.use(express.json({ limit: '10kb' }));
app.use(sanitize);
app.use(passport.initialize());

// Routes
app.use('/api/auth', require('./routes/auth.routes'));
app.use('/api/products', require('./routes/product.routes'));
app.use('/api/bookings', require('./routes/booking.routes'));
app.use('/api/cart', require('./routes/cart.routes'));
app.use('/api/profile', require('./routes/profile.routes'));
app.use('/api/users', require('./routes/user.routes'));
app.use('/api/admin', require('./routes/admin.routes'));

// Unknown routes + central error handler (always `{ message }`)
app.use(notFound);
app.use(errorHandler);

module.exports = app;
