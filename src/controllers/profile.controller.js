const User = require('../models/User');
const HttpError = require('../utils/httpError');
const { serializeUser } = require('../utils/serializeUser');

const PROGRAM_TYPES = ['Diploma', 'UG', 'PG', 'PhD'];

/* UPDATE AVATAR */
exports.updateAvatar = async (req, res) => {
  if (!req.file) throw new HttpError(400, 'Avatar image required.');

  const avatarUrl = req.file.path || req.file.secure_url || req.file.location || req.file.url;

  const user = await User.findByIdAndUpdate(req.userId, { avatar: avatarUrl }, { new: true });
  if (!user) throw new HttpError(404, 'User not found.');

  // Bare user object: the frontend replaces its stored user with this response.
  res.json(serializeUser(user));
};

/* UPDATE PROFILE */
exports.updateProfile = async (req, res) => {
  const body = req.body || {};
  const updates = {};

  // Only these fields can be changed here. `avatar` is intentionally NOT accepted as a free-form
  // URL any more (the frontend never sends it; avatars go through POST /profile/avatar).
  if (body.name !== undefined) {
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (!name) throw new HttpError(400, 'Name is required.');
    updates.name = name;
  }
  for (const field of ['programType', 'department', 'year']) {
    if (body[field] === undefined || body[field] === '') continue; // blank = leave unchanged
    if (typeof body[field] !== 'string') throw new HttpError(400, `Invalid ${field}.`);
    updates[field] = body[field].trim();
  }
  if (updates.programType && !PROGRAM_TYPES.includes(updates.programType)) {
    throw new HttpError(400, 'Invalid program type.');
  }
  if (body.studentCode !== undefined) {
    if (typeof body.studentCode !== 'string' || body.studentCode.length > 50) {
      throw new HttpError(400, 'Invalid student code.');
    }
    updates.studentCode = body.studentCode.trim();
  }

  const user = await User.findByIdAndUpdate(req.userId, { $set: updates }, { new: true, runValidators: true });
  if (!user) throw new HttpError(404, 'User not found.');

  res.json(serializeUser(user));
};
