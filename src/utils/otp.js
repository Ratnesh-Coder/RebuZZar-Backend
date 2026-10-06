const crypto = require('crypto');

/** 6-digit numeric OTP from a CSPRNG (not Math.random). */
const generateOtp = () => String(crypto.randomInt(0, 1000000)).padStart(6, '0');

const hashOtp = (otp) => crypto.createHash('sha256').update(String(otp)).digest('hex');

/** Constant-time comparison of a submitted OTP against a stored SHA-256 hash. */
const otpMatches = (submitted, storedHash) => {
  if (typeof submitted !== 'string' || typeof storedHash !== 'string') return false;
  const a = Buffer.from(hashOtp(submitted), 'hex');
  const b = Buffer.from(storedHash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

module.exports = { generateOtp, hashOtp, otpMatches };
