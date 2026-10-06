const mongoose = require('mongoose');

const ProductSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  price: { type: Number, required: true, min: 0 },
  quantity: { type: Number, required: true, min: 1 },
  description: { type: String, required: true, trim: true },
  imageUrl: { type: [String], required: true },
  category: { type: String, required: true },
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, immutable: true },
  // Snapshots used for notifications. Not `required`, so documents created before
  // they existed still validate on save(); new products always set them.
  sellerName: { type: String, immutable: true },
  sellerEmail: { type: String, immutable: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  postDate: { type: Date, default: Date.now },
  isDeleted: { type: Boolean, default: false, index: true },
  deletedAt: { type: Date, default: null },
  isBooked: { type: Boolean, default: false },
}, { timestamps: true });

// The frontend never reads the seller snapshot from product responses (verified), and
// public product endpoints must not expose seller PII. The fields stay in the database
// for notifications/booking snapshots; they are only stripped from JSON output.
ProductSchema.set('toJSON', {
  transform: (doc, ret) => {
    delete ret.sellerEmail;
    delete ret.sellerName;
    return ret;
  },
});

module.exports = mongoose.model('Product', ProductSchema);
