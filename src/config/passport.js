const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const User = require('../models/User');
const logger = require('../utils/logger');
const { getUniversityDomain } = require('./env');

const DOMAIN_ERROR = 'Only Brainware University emails are allowed.';
const NO_ACCOUNT_ERROR = 'Account not found. Please sign up first.';

const isConfigured = Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

if (isConfigured) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        // Absolute URL from env keeps the callback correct behind proxies/HTTPS.
        callbackURL: process.env.GOOGLE_CALLBACK_URL || '/api/auth/google/callback',
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value?.toLowerCase();

          if (!email || !email.endsWith(getUniversityDomain())) {
            return done(null, false, { message: DOMAIN_ERROR });
          }

          const user = await User.findOne({ email });
          if (!user) {
            return done(null, false, { message: NO_ACCOUNT_ERROR });
          }

          return done(null, user);
        } catch (error) {
          logger.error('Google strategy error', error);
          return done(error, null);
        }
      }
    )
  );
} else {
  logger.warn('Google OAuth is not configured (GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET missing); /api/auth/google is disabled.');
}

module.exports = passport;
module.exports.isGoogleConfigured = isConfigured;
module.exports.DOMAIN_ERROR = DOMAIN_ERROR;
