const express = require('express');
const crypto = require('crypto');
const { google } = require('googleapis');

const router = express.Router();

// Temporary authorization state, held only while the server process is running.
const pendingStates = new Set();

const getOAuthClient = () => {
  const {
    GMAIL_OAUTH_CLIENT_ID,
    GMAIL_OAUTH_CLIENT_SECRET,
    GMAIL_OAUTH_REDIRECT_URI,
  } = process.env;

  if (!GMAIL_OAUTH_CLIENT_ID ||
      !GMAIL_OAUTH_CLIENT_SECRET ||
      !GMAIL_OAUTH_REDIRECT_URI) {
    throw new Error('Gmail OAuth environment variables are missing');
  }

  return new google.auth.OAuth2(
    GMAIL_OAUTH_CLIENT_ID,
    GMAIL_OAUTH_CLIENT_SECRET,
    GMAIL_OAUTH_REDIRECT_URI
  );
};

// Temporary setup endpoint. Remove after obtaining the refresh token.
router.get('/google', (req, res, next) => {
  try {
    const expected = process.env.GMAIL_OAUTH_SETUP_KEY;
    const supplied =
      typeof req.query.key === 'string' ? req.query.key : '';
    
    console.log('[Gmail OAuth setup]', {
      keyConfigured: Boolean(expected),
      suppliedKeyPresent: Boolean(supplied),
      expectedLength: expected?.length ?? 0,
      suppliedLength: supplied.length,
    });

    if (!expected || !supplied ||
        Buffer.byteLength(expected) !== Buffer.byteLength(supplied) ||
        !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(supplied))) {
      return res.status(404).send('Not found');
    }

    const state = crypto.randomBytes(32).toString('hex');
    pendingStates.add(state);

    const oauth2Client = getOAuthClient();
    const url = oauth2Client.generateAuthUrl({
      access_type: 'offline',
      prompt: 'consent',
      state,
      scope: ['https://www.googleapis.com/auth/gmail.send'],
    });

    res.redirect(url);
  } catch (err) {
    next(err);
  }
});

router.get('/google/callback', async (req, res, next) => {
  try {
    const state = typeof req.query.state === 'string' ? req.query.state : '';

    if (!state || !pendingStates.has(state)) {
      return res.status(400).send('Invalid or expired OAuth state. Start authorization again.');
    }

    pendingStates.delete(state);

    if (req.query.error) {
      return res.status(400).send('Google authorization was cancelled or denied.');
    }

    const code = typeof req.query.code === 'string' ? req.query.code : '';
    if (!code) return res.status(400).send('Authorization code is missing.');

    const oauth2Client = getOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);

    if (!tokens.refresh_token) {
      return res.status(400).send(
        'Google did not return a refresh token. Restart authorization and consent again.'
      );
    }

    // Display only the refresh token needed for manual configuration.
    // Do not log it or send it to a frontend application.
    res.set('Cache-Control', 'no-store');
    res.type('html').send(`<!doctype html>
      <html><head><meta name="robots" content="noindex">
      <title>Gmail authorization complete</title></head>
      <body style="font-family: sans-serif; max-width: 760px; margin: 40px auto;">
        <h2>Gmail authorization complete</h2>
        <p>Copy this refresh token into Render as
        <code>GMAIL_OAUTH_REFRESH_TOKEN</code>. Treat it like a password.</p>
        <textarea readonly rows="6" style="width:100%;">${String(tokens.refresh_token).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</textarea>
        <p>After saving it in Render, remove the temporary OAuth setup routes.</p>
      </body></html>`);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
