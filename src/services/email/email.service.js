const nodemailer = require('nodemailer');
const logger = require('../../utils/logger');

/**
 * Single place that talks to SMTP.
 *  - sendEmail(): throws on failure (use only where delivery IS the operation, e.g. OTP / reset link).
 *  - sendSafe():  never throws; logs and returns false on failure (notifications after a DB write).
 *  - dispatch():  sends several notifications independently (Promise.allSettled); never rejects.
 * The transporter is created lazily, so importing this module never crashes the app.
 */
let transporter;

const getTransporter = () => {
  if (transporter) return transporter;
  const { EMAIL_HOST, EMAIL_PORT, EMAIL_SECURE, EMAIL_USER, EMAIL_PASS } = process.env;
  const auth = { user: EMAIL_USER, pass: EMAIL_PASS };

  // Previously `service: 'gmail'` silently overrode EMAIL_HOST/PORT/SECURE. Honour them when set;
  // fall back to Gmail only when no host is configured.
  transporter = nodemailer.createTransport(
    EMAIL_HOST
      ? { host: EMAIL_HOST, port: Number(EMAIL_PORT) || 587, secure: EMAIL_SECURE === 'true', auth }
      : { service: 'gmail', auth }
  );
  return transporter;
};

/** Test hook: inject a stub transport (e.g. { sendMail: async () => ({}) }). */
const setTransporter = (t) => { transporter = t; };

const defaultFrom = () => `"RebuZZar" <${process.env.EMAIL_USER}>`;

const hasRecipient = (to) => Array.isArray(to) ? to.filter(Boolean).length > 0 : Boolean(to);

const sendEmail = async ({ to, subject, html, from, replyTo }) => {
  if (!hasRecipient(to)) throw new Error('No email recipients provided');
  await getTransporter().sendMail({ from: from || defaultFrom(), to, subject, html, ...(replyTo ? { replyTo } : {}) });
};

const sendSafe = async (mail, label = 'email') => {
  try {
    await sendEmail(mail);
    return true;
  } catch (err) {
    // Log the failure and the label only - never the recipient list, body or credentials.
    logger.error(`Failed to send ${label}`, err);
    return false;
  }
};

/** Send independent notifications; a failure in one never affects the others or the caller. */
const dispatch = async (mails, label) => {
  const list = (mails || []).filter(Boolean);
  const results = await Promise.allSettled(list.map((m) => sendSafe(m, m.label || label)));
  return results.map((r) => r.status === 'fulfilled' && r.value === true);
};

module.exports = { sendEmail, sendSafe, dispatch, setTransporter };
