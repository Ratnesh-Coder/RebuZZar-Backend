const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const {
  loginLimiter, signupLimiter, otpVerifyLimiter, otpResendLimiter,
  forgotPasswordLimiter, resetPasswordLimiter,
} = require('../middlewares/rateLimiters');

// Email / password auth
router.post('/signup', signupLimiter, authController.signup);
router.post('/verify-otp', otpVerifyLimiter, authController.verifyOtp);
router.post('/resend-otp', otpResendLimiter, authController.resendOtp);
router.post('/login', loginLimiter, authController.login);

// Forgot password
router.post('/forgot-password', forgotPasswordLimiter, authController.forgotPassword);
router.post('/reset-password/:token', resetPasswordLimiter, authController.resetPassword);

// Google OAuth
router.get('/google', authController.googleAuth);
router.get('/google/callback', authController.googleCallback);

module.exports = router;
