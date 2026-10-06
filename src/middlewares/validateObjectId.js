const validator = require('validator');

/**
 * Reject malformed ObjectIds in route params before they reach Mongoose
 * (which would otherwise raise a CastError).
 *
 * validateObjectId('id', 404, 'Product not found.')  -> unknown id looks like "not found"
 * validateObjectId('productId', 400, 'Invalid productId.')
 */
module.exports = (param = 'id', status = 404, message = 'Not found.') => (req, res, next) => {
  const value = req.params[param];
  if (typeof value !== 'string' || !validator.isMongoId(value)) {
    return res.status(status).json({ message });
  }
  next();
};
