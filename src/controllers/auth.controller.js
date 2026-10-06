const bcrypt = require('bcryptjs');
const validator = require('validator');

const User = require('../models/User');
const passport = require('../config/passport');
const { getFrontendUrl, getUniversityDomain } = require('../config/env');
const HttpError = require('../utils/httpError');
const logger = require('../utils/logger');
const { generateOtp, hashOtp, otpMatches } = require('../utils/otp');
const { signToken, generateResetToken, hashToken } = require('../utils/token');
const { serializeUser, serializeUserForUrl } = require('../utils/serializeUser');
const authEmail = require('../services/email/auth.email');

const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;
const OTP_RESEND_COOLDOWN_MS = 60 * 1000;
const RESET_TTL_MS = 15 * 60 * 1000;
const PASSWORD_MIN = 6;
const PASSWORD_MAX = 128;
const PROGRAM_TYPES = ['Diploma', 'UG', 'PG', 'PhD'];

// Request fields must be plain strings (blocks operator objects like { "$ne": null }).
const str = (value) => (typeof value === 'string' ? value.trim() : '');
const email_ = (value) => str(value).toLowerCase();
const passwordProblem = (password) =>
  typeof password !== 'string' || password.length < PASSWORD_MIN || password.length > PASSWORD_MAX
    ? `Password must be between ${PASSWORD_MIN} and ${PASSWORD_MAX} characters long.`
    : null;

/* SIGN UP */
exports.signup = async (req, res) => {
  const body = req.body || {};
  const email = email_(body.email);
  const name = str(body.name);
  const programType = str(body.programType);
  const department = str(body.department);
  const year = str(body.year);
  const studentCode = str(body.studentCode);
  const { password } = body;

  if (!email || !validator.isEmail(email) || !email.endsWith(getUniversityDomain())) {
    throw new HttpError(400, 'Invalid email');
  }

  if (!name || typeof password !== 'string' || !password || !programType || !department || !year) {
    throw new HttpError(400, 'All required fields are required.');
  }

  if (!PROGRAM_TYPES.includes(programType)) throw new HttpError(400, 'Invalid program type.');
  const pwProblem = passwordProblem(password);
  if (pwProblem) throw new HttpError(400, pwProblem);

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    if (!existingUser.isVerified) {
      throw new HttpError(409, 'Account exists but not verified. Please verify OTP.', { needsVerification: true });
    }
    throw new HttpError(409, 'An account with this email already exists.');
  }

  const otp = generateOtp();
  let newUser;
  try {
    newUser = await User.create({
      name,
      email,
      password: await bcrypt.hash(password, 10),
      programType,
      department,
      year,
      ...(studentCode ? { studentCode } : {}),
      isVerified: false,
      emailOTP: hashOtp(otp),
      emailOTPExpires: new Date(Date.now() + OTP_TTL_MS),
      emailOTPAttempts: 0,
      emailOTPLastSentAt: new Date(),
    });
  } catch (err) {
    // Two simultaneous sign-ups for the same email: report a conflict, not a 500.
    if (err && err.code === 11000) throw new HttpError(409, 'An account with this email already exists.');
    throw err;
  }

  // For OTP mails delivery IS the operation: report a failure honestly (the account exists,
  // the user can use "Resend OTP"), exactly like the previous behaviour.
  try {
    await authEmail.sendVerificationOtp({ to: newUser.email, otp });
  } catch (err) {
    logger.error('Failed to send verification email', err);
    throw new HttpError(500, 'Failed to send verification email');
  }

  res.status(201).json({
    message: 'Signup successful. Verify OTP.',
    userId: newUser._id,
  });
};

/* LOGIN */
exports.login = async (req, res) => {
  const email = email_(req.body && req.body.email);
  const password = req.body && req.body.password;

  if (!email || typeof password !== 'string' || !password) {
    throw new HttpError(400, 'Email and password required.');
  }

  const user = await User.findOne({ email });
  if (!user) throw new HttpError(401, 'Invalid credentials.');

  if (!user.isVerified) throw new HttpError(403, 'Verify email first.');

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) throw new HttpError(401, 'Invalid credentials.');

  res.json({ message: 'Login successful', user: serializeUser(user), token: signToken(user._id) });
};

const invalidateOtp = (userId) =>
  User.updateOne({ _id: userId }, { $unset: { emailOTP: 1, emailOTPExpires: 1 }, $set: { emailOTPAttempts: 0 } });

/* VERIFY OTP */
exports.verifyOtp = async (req, res) => {
  const email = email_(req.body && req.body.email);
  const otp = str(req.body && req.body.otp);

  if (!email || !otp) throw new HttpError(400, 'Email and OTP are required.');

  const user = await User.findOne({ email });
  if (!user) throw new HttpError(404, 'User not found.');

  if (user.isVerified) throw new HttpError(400, 'Account already verified.');

  if (!user.emailOTP || !user.emailOTPExpires) {
    throw new HttpError(400, 'No OTP found. Please request a new OTP.');
  }

  if (user.emailOTPExpires < Date.now()) throw new HttpError(400, 'OTP expired.');

  // Count this attempt atomically BEFORE comparing, so parallel guesses cannot exceed the cap.
  const counted = await User.findOneAndUpdate(
    { _id: user._id, emailOTP: user.emailOTP },
    { $inc: { emailOTPAttempts: 1 } },
    { new: true }
  );
  if (!counted) throw new HttpError(400, 'Invalid OTP.'); // OTP was replaced concurrently

  const tooMany = () => new HttpError(429, 'Too many incorrect attempts. Please request a new OTP.');
  if (counted.emailOTPAttempts > OTP_MAX_ATTEMPTS) {
    await invalidateOtp(user._id);
    throw tooMany();
  }

  if (!otpMatches(otp, user.emailOTP)) {
    if (counted.emailOTPAttempts >= OTP_MAX_ATTEMPTS) {
      await invalidateOtp(user._id);
      throw tooMany();
    }
    throw new HttpError(400, 'Invalid OTP.');
  }

  await User.updateOne(
    { _id: user._id, emailOTP: user.emailOTP },
    {
      $set: { isVerified: true },
      $unset: { emailOTP: 1, emailOTPExpires: 1, emailOTPAttempts: 1, emailOTPLastSentAt: 1 },
    }
  );

  res.status(200).json({ message: 'Email verified successfully.' });
};

/* RESEND OTP */
exports.resendOtp = async (req, res) => {
  const email = email_(req.body && req.body.email);
  if (!email) throw new HttpError(400, 'Email is required.');

  const user = await User.findOne({ email });
  if (!user) throw new HttpError(404, 'No account found.');

  if (user.isVerified) throw new HttpError(400, 'Account already verified.');

  const now = Date.now();
  const otp = generateOtp();

  // Claim the resend slot atomically: enforces the cooldown even under concurrent requests.
  const claimed = await User.findOneAndUpdate(
    {
      _id: user._id,
      isVerified: false,
      $or: [
        { emailOTPLastSentAt: { $exists: false } },
        { emailOTPLastSentAt: { $lte: new Date(now - OTP_RESEND_COOLDOWN_MS) } },
      ],
    },
    {
      $set: {
        emailOTP: hashOtp(otp),
        emailOTPExpires: new Date(now + OTP_TTL_MS),
        emailOTPAttempts: 0,
        emailOTPLastSentAt: new Date(now),
      },
    },
    { new: true }
  );

  if (!claimed) {
    const last = user.emailOTPLastSentAt ? user.emailOTPLastSentAt.getTime() : now;
    const wait = Math.max(1, Math.ceil((OTP_RESEND_COOLDOWN_MS - (now - last)) / 1000));
    throw new HttpError(429, `Please wait ${wait} seconds before requesting another OTP.`);
  }

  try {
    await authEmail.sendResendOtp({ to: claimed.email, otp });
  } catch (err) {
    logger.error('Failed to resend OTP email', err);
    throw new HttpError(500, 'Failed to resend OTP.');
  }

  res.json({ message: 'OTP resent successfully.' });
};

const FORGOT_MESSAGE = 'If an account exists, a link was sent.';

/* FORGOT PASSWORD */
exports.forgotPassword = async (req, res) => {
  const email = email_(req.body && req.body.email);

  // Always the same answer, so the endpoint cannot be used to discover accounts
  // (including via a 500 when the mail fails for an existing account only).
  if (!email || !validator.isEmail(email)) return res.json({ message: FORGOT_MESSAGE });

  const user = await User.findOne({ email });
  if (!user) return res.json({ message: FORGOT_MESSAGE });

  const { token, hash } = generateResetToken();
  await User.updateOne(
    { _id: user._id },
    { $set: { resetPasswordToken: hash, resetPasswordExpires: new Date(Date.now() + RESET_TTL_MS) } }
  );

  try {
    await authEmail.sendPasswordReset({ to: user.email, link: `${getFrontendUrl()}/reset-password/${token}` });
  } catch (err) {
    logger.error('Failed to send password reset email', err);
  }

  res.json({ message: FORGOT_MESSAGE });
};

/* RESET PASSWORD */
exports.resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body || {};

  if (typeof password !== 'string' || !password) throw new HttpError(400, 'Password is required');
  const pwProblem = passwordProblem(password);
  if (pwProblem) throw new HttpError(400, pwProblem);

  if (!/^[a-f0-9]{64}$/i.test(token)) throw new HttpError(400, 'Invalid or expired token');

  const hashedToken = hashToken(token);
  const user = await User.findOne({
    resetPasswordToken: hashedToken,
    resetPasswordExpires: { $gt: new Date() },
  });
  if (!user) throw new HttpError(400, 'Invalid or expired token');

  // Token is single-use: the update only matches while the same token is still stored.
  const result = await User.updateOne(
    { _id: user._id, resetPasswordToken: hashedToken },
    {
      $set: { password: await bcrypt.hash(password, 10) },
      $unset: { resetPasswordToken: 1, resetPasswordExpires: 1 },
    }
  );
  if (result.modifiedCount !== 1) throw new HttpError(400, 'Invalid or expired token');

  res.json({ message: 'Password reset successful' });
};

/* GOOGLE OAUTH */
exports.googleAuth = (req, res, next) => {
  if (!passport.isGoogleConfigured) {
    return res.status(503).json({ message: 'Google sign-in is not configured.' });
  }
  return passport.authenticate('google', { scope: ['profile', 'email'], session: false })(req, res, next);
};

exports.googleCallback = (req, res, next) => {
  const frontend = getFrontendUrl();
  const fail = (code) => res.redirect(`${frontend}/?error=${code}`);

  if (!passport.isGoogleConfigured) return fail('server');
  if (req.query.error) return fail('denied'); // user cancelled on Google's consent screen

  passport.authenticate('google', { session: false }, (err, user, info) => {
    if (err) {
      logger.error('Google OAuth callback error', err);
      return fail('server');
    }
    if (!user) {
      return fail(info && info.message === passport.DOMAIN_ERROR ? 'invalid_email' : 'no_account');
    }

    // The frontend (App.tsx) reads `token` and `user` from the query string and does
    // JSON.parse(decodeURIComponent(searchParams.get('user'))): searchParams already decodes
    // once, so the JSON is encoded twice. This also keeps names containing '%' working.
    const userParam = encodeURIComponent(encodeURIComponent(JSON.stringify(serializeUserForUrl(user))));
    res.redirect(`${frontend}/?token=${encodeURIComponent(signToken(user._id))}&user=${userParam}`);
  })(req, res, next);
};
