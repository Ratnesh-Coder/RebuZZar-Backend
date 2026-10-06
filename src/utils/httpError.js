/**
 * Error with an HTTP status. Anything thrown/forwarded as an HttpError is
 * rendered by the central error handler as `{ message }` with that status.
 */
class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.expose = true;
    // Optional extra top-level response fields (e.g. { needsVerification: true }).
    this.extra = extra;
  }
}

module.exports = HttpError;
