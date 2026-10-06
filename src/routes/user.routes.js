const express = require('express');
const router = express.Router();

const authMiddleware = require('../middlewares/auth.middleware');
const { updateContactInfo } = require('../controllers/user.controller');

router.put('/contact', authMiddleware, updateContactInfo);

module.exports = router;