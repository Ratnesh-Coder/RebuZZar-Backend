const { google } = require('googleapis');
const MailComposer = require('nodemailer/lib/mail-composer');
const logger = require('../../utils/logger');

let transporter;
let oauthClient;

const getOAuthClient = () => {
  if (oauthClient) return oauthClient;

  const {
    GMAIL_OAUTH_CLIENT_ID,
    GMAIL_OAUTH_CLIENT_SECRET,
    GMAIL_OAUTH_REDIRECT_URI,
    GMAIL_OAUTH_REFRESH_TOKEN,
  } = process.env;

  if (
    !GMAIL_OAUTH_CLIENT_ID ||
    !GMAIL_OAUTH_CLIENT_SECRET ||
    !GMAIL_OAUTH_REDIRECT_URI ||
    !GMAIL_OAUTH_REFRESH_TOKEN
  ) {
    throw new Error('Gmail API OAuth environment variables are missing');
  }

  oauthClient = new google.auth.OAuth2(
    GMAIL_OAUTH_CLIENT_ID,
    GMAIL_OAUTH_CLIENT_SECRET,
    GMAIL_OAUTH_REDIRECT_URI
  );

  oauthClient.setCredentials({
    refresh_token: GMAIL_OAUTH_REFRESH_TOKEN,
  });

  return oauthClient;
};

const setTransporter = (t) => {
  transporter = t;
};

const defaultFrom = () => `"RebuZZar" <${process.env.EMAIL_USER}>`;

const hasRecipient = (to) =>
  Array.isArray(to) ? to.filter(Boolean).length > 0 : Boolean(to);

const buildRawMessage = async ({ to, subject, html, from, replyTo }) => {
  const composer = new MailComposer({
    from: from || defaultFrom(),
    to,
    subject,
    html,
    ...(replyTo ? { replyTo } : {}),
  });

  const message = await new Promise((resolve, reject) => {
    composer.compile().build((err, buffer) => {
      if (err) return reject(err);
      resolve(buffer);
    });
  });

  return message
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
};

const sendEmail = async ({ to, subject, html, from, replyTo }) => {
  if (!hasRecipient(to)) {
    throw new Error('No email recipients provided');
  }

  // Keep compatibility with tests that inject a mock transporter.
  if (transporter) {
    await transporter.sendMail({
      from: from || defaultFrom(),
      to,
      subject,
      html,
      ...(replyTo ? { replyTo } : {}),
    });
    return;
  }

  const auth = getOAuthClient();
  const gmail = google.gmail({ version: 'v1', auth });

  const raw = await buildRawMessage({
    to,
    subject,
    html,
    from,
    replyTo,
  });

  await gmail.users.messages.send({
    userId: 'me',
    requestBody: { raw },
  });
};

const sendSafe = async (mail, label = 'email') => {
  try {
    await sendEmail(mail);
    return true;
  } catch (err) {
    logger.error(`Failed to send ${label}`, err);
    return false;
  }
};

const dispatch = async (mails, label) => {
  const list = (mails || []).filter(Boolean);

  const results = await Promise.allSettled(
    list.map((mail) => sendSafe(mail, mail.label || label))
  );

  return results.map(
    (result) =>
      result.status === 'fulfilled' && result.value === true
  );
};

module.exports = {
  sendEmail,
  sendSafe,
  dispatch,
  setTransporter,
};
