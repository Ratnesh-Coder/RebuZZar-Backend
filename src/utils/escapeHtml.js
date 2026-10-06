/** Escape user-controlled text before interpolating it into HTML emails. */
const MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

module.exports = function escapeHtml(value) {
  if (value === undefined || value === null) return '';
  return String(value).replace(/[&<>"']/g, (ch) => MAP[ch]);
};
