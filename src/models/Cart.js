const mongoose = require('mongoose');

const CartItemSchema = new mongoose.Schema(
  {
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    title: { type: String, required: true, trim: true },
    price: { type: Number, required: true, min: 0 },
    imageUrl: { type: [String], default: [] },
    quantity: { type: Number, required: true, min: 1, default: 1 },
    // Seller snapshot is optional so carts written before these fields existed stay valid.
    sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    sellerName: { type: String, trim: true },
    sellerEmail: { type: String, lowercase: true, trim: true }
  },
  { _id: false }
);

const CartSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: { type: [CartItemSchema], default: [] }
  }, { timestamps: true }
);

CartSchema.index({ userId: 1 }, { unique: true });

module.exports = mongoose.model('Cart', CartSchema);
