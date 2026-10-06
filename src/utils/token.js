const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const DEFAULT_EXPIRES_IN = '7d';

/** Sign an auth JWT. Expiry comes from JWT_EXPIRES_IN (default 7d, the previous behaviour). */
const signToken = (userId) =>
  jwt.sign({ id: String(userId) }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: process.env.JWT_EXPIRES_IN || DEFAULT_EXPIRES_IN,
  });

/** Random password-reset token (sent to the user) and its SHA-256 hash (stored). */
const generateResetToken = () => {
  const token = crypto.randomBytes(32).toString('hex');
  return { token, hash: hashToken(token) };
};

const hashToken = (token) => crypto.createHash('sha256').update(String(token)).digest('hex');

module.exports = { signToken, generateResetToken, hashToken, DEFAULT_EXPIRES_IN };
