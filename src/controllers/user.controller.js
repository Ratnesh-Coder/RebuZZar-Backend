const User = require('../models/User');
const HttpError = require('../utils/httpError');
const { serializeUser } = require('../utils/serializeUser');

const ALLOWED_PREFERENCES = ['call', 'whatsapp', 'both'];

exports.updateContactInfo = async (req, res) => {
  const { phoneNumber, contactPreference } = req.body || {};

  if (!phoneNumber || typeof phoneNumber !== 'string') {
    throw new HttpError(400, 'Phone number is required.');
  }

  const cleanedPhone = phoneNumber.replace(/\D/g, '');
  if (cleanedPhone.length !== 10) {
    throw new HttpError(400, 'Please enter a valid 10-digit phone number.');
  }

  if (contactPreference && (typeof contactPreference !== 'string' || !ALLOWED_PREFERENCES.includes(contactPreference))) {
    throw new HttpError(400, 'Invalid contact preference.');
  }

  const user = await User.findByIdAndUpdate(
    req.userId,
    { $set: { phoneNumber: cleanedPhone, contactPreference: contactPreference || 'both' } },
    { new: true, runValidators: true }
  );
  if (!user) throw new HttpError(404, 'User not found.');

  res.status(200).json({
    message: 'Contact information updated successfully.',
    user: serializeUser(user),
  });
};
