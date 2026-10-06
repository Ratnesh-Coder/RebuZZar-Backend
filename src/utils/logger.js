/**
 * Minimal logger. Never pass request bodies, passwords, OTPs, tokens or
 * connection strings to it. Errors are logged by name/message (+stack outside
 * production) only.
 */
const isProd = () => process.env.NODE_ENV === 'production';
const isTest = () => process.env.NODE_ENV === 'test';

const stamp = () => new Date().toISOString();

const describeError = (err) => {
  if (!err) return '';
  if (!(err instanceof Error)) return String(err);
  const base = `${err.name}: ${err.message}`;
  return isProd() ? base : `${base}\n${err.stack || ''}`;
};

const write = (level, message, err) => {
  if (isTest() && !process.env.LOG_IN_TEST) return;
  const line = `[${stamp()}] ${level.toUpperCase()} ${message}${err ? ` - ${describeError(err)}` : ''}`;
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
};

module.exports = {
  info: (message) => write('info', message),
  warn: (message, err) => write('warn', message, err),
  error: (message, err) => write('error', message, err),
};
