/**
 * Admin-only guard. Runs after auth.middleware, which loads the user fresh from the
 * database on every request, so the role is never taken from the JWT or the client.
 */
module.exports = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admins only.' });
  }
  next();
};
