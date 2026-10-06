const express = require('express');
const router = express.Router();

const auth = require('../middlewares/auth.middleware');
const upload = require('../middlewares/upload');
const profileController = require('../controllers/profile.controller');

router.post(
  '/avatar',
  auth,
  upload.single('avatar'),
  profileController.updateAvatar
);

router.put(
  '/',
  auth,
  profileController.updateProfile
);

module.exports = router;
