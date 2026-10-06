// DEPRECATED: used only by the legacy ../../index.js. The modular backend sends mail through
// src/services/email/email.service.js. Delete this file together with index.js.
const nodemailer = require('nodemailer');

if (!process.env.EMAIL_HOST || !process.env.EMAIL_USER) {
  throw new Error('Email environment variables are missing');
}

const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT) || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

module.exports = transporter;