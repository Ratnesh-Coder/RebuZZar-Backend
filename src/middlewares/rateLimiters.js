const { rateLimit } = require('express-rate-limit');

/**
 * Factory so limits are explicit and testable. All limiters answer 429 with the
 * frontend-compatible `{ message }` body. Keyed by client IP; set TRUST_PROXY
 * (see app.js) when deployed behind a reverse proxy so the real IP is used.
 */
const createLimiter = ({ windowMs, max, message }) =>
  rateLimit({
    windowMs,
    limit: max,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    handler: (req, res) => res.status(429).json({ message }),
  });

const MINUTES = 60 * 1000;

module.exports = {
  createLimiter,
  // Legacy values (10 / 15 min) kept for login + forgot-password.
  loginLimiter: createLimiter({ windowMs: 15 * MINUTES, max: 10, message: 'Too many login attempts. Please try again in 15 minutes.' }),
  forgotPasswordLimiter: createLimiter({ windowMs: 15 * MINUTES, max: 10, message: 'Too many password reset requests. Please try again later.' }),
  // New: previously unprotected in both implementations.
  signupLimiter: createLimiter({ windowMs: 60 * MINUTES, max: 10, message: 'Too many sign-up attempts. Please try again later.' }),
  otpVerifyLimiter: createLimiter({ windowMs: 15 * MINUTES, max: 20, message: 'Too many verification attempts. Please try again later.' }),
  otpResendLimiter: createLimiter({ windowMs: 15 * MINUTES, max: 5, message: 'Too many OTP requests. Please try again later.' }),
  resetPasswordLimiter: createLimiter({ windowMs: 15 * MINUTES, max: 10, message: 'Too many password reset attempts. Please try again later.' }),
};
