/**
 * Allow-list serializer for user objects sent to clients. Anything not listed
 * (password hash, OTP hash, reset-token hash, __v, ...) is never returned.
 * Every field the frontend reads (User type, EditProfile, Sell, Profile) is kept.
 */
const PUBLIC_FIELDS = [
  '_id', 'name', 'email', 'avatar', 'role', 'joinDate',
  'programType', 'department', 'year', 'studentCode',
  'phoneNumber', 'contactPreference', 'isVerified', 'createdAt', 'updatedAt',
];

const toPlain = (user) => (user && typeof user.toObject === 'function' ? user.toObject() : user || {});

const serializeUser = (user) => {
  const plain = toPlain(user);
  const out = {};
  for (const key of PUBLIC_FIELDS) {
    if (plain[key] !== undefined) out[key] = plain[key];
  }
  return out;
};

/**
 * Minimal user object for the Google OAuth redirect URL. URLs end up in browser
 * history and server logs, so the phone number is masked: the frontend only
 * needs to know that one exists (Sell page), never its value.
 */
const maskPhone = (phone) => {
  if (!phone) return phone;
  const digits = String(phone);
  return `${'*'.repeat(Math.max(digits.length - 4, 0))}${digits.slice(-4)}`;
};

const serializeUserForUrl = (user) => {
  const plain = toPlain(user);
  const out = {};
  for (const key of ['_id', 'name', 'email', 'role', 'avatar', 'studentCode', 'programType', 'department', 'year', 'contactPreference']) {
    if (plain[key] !== undefined) out[key] = plain[key];
  }
  if (plain.phoneNumber) out.phoneNumber = maskPhone(plain.phoneNumber);
  return out;
};

module.exports = { serializeUser, serializeUserForUrl, maskPhone, PUBLIC_FIELDS };
