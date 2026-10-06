const path = require('path');

/**
 * Environment loading and startup validation.
 * `loadEnv()` reads Backend/.env once (server.js calls it before anything else);
 * `validateEnv()` fails fast with the NAMES of missing variables (never values).
 */
const loadEnv = () => {
  require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env'), quiet: true });
};

const REQUIRED = ['MONGO_URI', 'JWT_SECRET', 'EMAIL_USER', 'EMAIL_PASS'];
const REQUIRED_IN_PRODUCTION = ['FRONTEND_URL', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_CALLBACK_URL',
  'CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET', 'ADMIN_EMAIL'];

const validateEnv = (env = process.env) => {
  const isProd = env.NODE_ENV === 'production';
  const missing = [...REQUIRED, ...(isProd ? REQUIRED_IN_PRODUCTION : [])].filter((k) => !env[k]);
  if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
  if (isProd && env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters in production.');
  }
};

/** Frontend base URL used for OAuth redirects and email links (no trailing slash). */
const getFrontendUrl = () => (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/+$/, '');

/** CORS origin: explicit CORS_ORIGIN (comma-separated) > FRONTEND_URL > '*' (dev only). */
const getCorsOrigin = () => {
  const explicit = process.env.CORS_ORIGIN;
  if (explicit) {
    const list = explicit.split(',').map((s) => s.trim().replace(/\/+$/, '')).filter(Boolean);
    return list.length === 1 ? list[0] : list;
  }
  if (process.env.FRONTEND_URL) return getFrontendUrl();
  return '*';
};

/**
 * Allowed sign-up / Google domain, always returned as '@domain' in lowercase.
 * UNIVERSITY_DOMAIN may be given with or without the leading '@'.
 */
const getUniversityDomain = () => {
  const raw = (process.env.UNIVERSITY_DOMAIN || 'brainwareuniversity.ac.in').trim().toLowerCase();
  return raw.startsWith('@') ? raw : `@${raw}`;
};

module.exports = { loadEnv, validateEnv, getFrontendUrl, getCorsOrigin, getUniversityDomain };
