const express = require('express');
const router = express.Router();

const cartController = require('../controllers/cart.controller');
const auth = require('../middlewares/auth.middleware');

// Get cart
router.get('/', auth, cartController.getCart);

// Add to cart
router.post('/add', auth, cartController.addToCart);

// Update cart item
router.put('/item/:productId', auth, cartController.updateCartItem);

// Remove item
router.delete('/item/:productId', auth, cartController.removeCartItem);

// Clear cart
router.post('/clear', auth, cartController.clearCart);

module.exports = router;
