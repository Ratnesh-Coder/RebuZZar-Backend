const logger = require('../utils/logger');

const isProd = () => process.env.NODE_ENV === 'production';

/** 404 for unknown routes, in the same `{ message }` shape as every other error. */
const notFound = (req, res) => {
  res.status(404).json({ message: 'Route not found.' });
};

const firstValidationMessage = (err) => {
  const first = Object.values(err.errors || {})[0];
  return (first && first.message) || 'Validation failed.';
};

/**
 * Central error handler. Contract with the frontend: every error response has a
 * top-level string `message` (plus optional flags such as `needsVerification`).
 * 5xx messages are generic in production; stacks/internals are never sent.
 */
// eslint-disable-next-line no-unused-vars
const errorHandler = (err, req, res, next) => {
  if (res.headersSent) return next(err);

  let status = 500;
  let message = 'Internal server error.';
  let extra = {};

  if (err && err.name === 'HttpError') {
    status = err.status;
    message = err.message;
    extra = err.extra || {};
  } else if (err && err.name === 'ValidationError' && err.errors) {
    status = 400;
    message = firstValidationMessage(err);
  } else if (err && err.name === 'CastError') {
    status = 400;
    message = `Invalid ${err.path || 'value'}.`;
  } else if (err && err.code === 11000) {
    status = 409;
    message = 'A record with these details already exists.';
  } else if (err && err.name === 'MulterError') {
    status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    message =
      err.code === 'LIMIT_FILE_SIZE' ? 'File too large. Maximum size is 5MB.'
        : err.code === 'LIMIT_FILE_COUNT' || err.code === 'LIMIT_UNEXPECTED_FILE' ? 'Too many files or unexpected file field.'
          : 'Invalid file upload.';
  } else if (err && (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError')) {
    status = 401;
    message = err.name === 'TokenExpiredError' ? 'Token expired, please login again' : 'Invalid token';
  } else if (err && err.type === 'entity.too.large') {
    status = 413;
    message = 'Request body too large.';
  } else if (err && err.type === 'entity.parse.failed') {
    status = 400;
    message = 'Invalid JSON body.';
  } else if (err && Number.isInteger(err.status || err.statusCode) && (err.status || err.statusCode) >= 400 && (err.status || err.statusCode) < 600) {
    status = err.status || err.statusCode;
    message = err.expose ? err.message : status >= 500 ? message : err.message;
  }

  if (status >= 500) {
    logger.error(`${req.method} ${req.originalUrl} -> ${status}`, err);
    if (!isProd() && err && err.message) message = err.message;
  }

  res.status(status).json({ message, ...extra });
};

module.exports = { notFound, errorHandler };
