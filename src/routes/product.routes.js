const express = require('express');
const router = express.Router();

const productController = require('../controllers/product.controller');
const auth = require('../middlewares/auth.middleware');
const upload = require('../middlewares/upload');
const validateObjectId = require('../middlewares/validateObjectId');

const productId = validateObjectId('id', 404, 'Product not found.');

// =====================
// PUBLIC ROUTES
// =====================
router.get('/', productController.getAllProducts);
router.get('/category/:category', productController.getProductsByCategory);

// =====================
// PROTECTED ROUTES
// =====================
router.get('/my-products', auth, productController.getMyProducts);

router.post(
  '/',
  auth,
  upload.array('images', 5),
  (req, res, next) => {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ message: 'At least one image is required' });
    }
    next();
  },
  productController.createProduct
);

// =====================
// DYNAMIC ROUTES
// =====================
router.put('/:id', auth, productId, productController.updateProduct);
router.delete('/:id', auth, productId, productController.deleteProduct);
router.get('/:id/contact', auth, productId, productController.getSellerContact);
router.get('/:id', productId, productController.getProductById);

module.exports = router;
