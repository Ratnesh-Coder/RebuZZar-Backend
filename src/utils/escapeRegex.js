/** Escape regex metacharacters so user input is matched literally in MongoDB $regex / RegExp. */
module.exports = function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
};
