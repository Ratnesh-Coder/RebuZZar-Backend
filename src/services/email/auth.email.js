const { sendEmail } = require('./email.service');
const { e } = require('./layout');

const SUPPORT_FROM = () => `"RebuZZar Support" <${process.env.EMAIL_USER}>`;

const buildVerificationOtp = ({ to, otp }) => ({
  from: SUPPORT_FROM(),
  to,
  replyTo: 'support@rebuzzar.com',
  subject: 'Verify your RebuZZar account',
  html: `
    <div style="font-family: Arial, sans-serif; color: #333;">
      <h2>Verify your RebuZZar account</h2>
      <p>Hello,</p>
      <p>Your One-Time Password (OTP) is:</p>
      <h1 style="letter-spacing: 4px;">${e(otp)}</h1>
      <p>This OTP is valid for <strong>10 minutes</strong>.</p>
      <p>If you did not request this, you can safely ignore this email.</p>
      <br/>
      <p>— RebuZZar Team</p>
    </div>`,
});

const buildResendOtp = ({ to, otp }) => ({
  from: SUPPORT_FROM(),
  to,
  subject: 'Your new verification OTP',
  html: `<p>Your new OTP is:</p><h2>${e(otp)}</h2><p>This OTP is valid for <strong>10 minutes</strong>.</p>`,
});

const buildPasswordReset = ({ to, link }) => ({
  from: process.env.EMAIL_FROM || undefined,
  to,
  subject: 'Reset Password Request',
  html: `<p>You requested a password reset. Click below to proceed:</p>
         <a href="${e(link)}">Reset Password</a>
         <p>This link expires in 15 minutes.</p>`,
});

// Delivery IS the operation for these three, so they throw on failure and the
// controller decides how to report it (see auth.controller.js).
module.exports = {
  buildVerificationOtp,
  buildResendOtp,
  buildPasswordReset,
  sendVerificationOtp: (args) => sendEmail(buildVerificationOtp(args)),
  sendResendOtp: (args) => sendEmail(buildResendOtp(args)),
  sendPasswordReset: (args) => sendEmail(buildPasswordReset(args)),
};
