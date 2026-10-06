const mongoSanitize = require('express-mongo-sanitize');

/**
 * NoSQL-operator injection guard that is safe on Express 5.
 *
 * `app.use(mongoSanitize())` crashes on Express 5 (it assigns to the read-only
 * `req.query` getter), so only the library's pure `has()` detector is used.
 * Instead of silently rewriting data, a request whose body or route params
 * contain operator keys (`$gt`, `$ne`, dotted keys, ...) is rejected with 400.
 * Legitimate frontend payloads never contain such keys.
 *
 * Query strings need no rewriting: Express 5's default parser yields flat
 * string/array values (verified), and controllers coerce them to strings.
 */
module.exports = (req, res, next) => {
  if (mongoSanitize.has(req.body) || mongoSanitize.has(req.params)) {
    return res.status(400).json({ message: 'Invalid request payload.' });
  }
  next();
};
