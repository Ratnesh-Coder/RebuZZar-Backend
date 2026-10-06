const express = require('express');
const router = express.Router();

const adminController = require('../controllers/admin.controller');
const auth = require('../middlewares/auth.middleware');
const admin = require('../middlewares/admin.middleware');
const validateObjectId = require('../middlewares/validateObjectId');

// Get pending products
router.get('/products/pending', auth, admin, adminController.getPendingProducts);

// Approve / reject product
router.put(
  '/products/:id/status',
  auth,
  admin,
  validateObjectId('id', 404, 'Product not found.'),
  adminController.updateProductStatus
);

module.exports = router;
