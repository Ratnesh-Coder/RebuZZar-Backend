const mongoose = require('mongoose');

const BookingSchema = new mongoose.Schema({
  buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  buyerName: { type: String, required: true },
  buyerEmail: { type: String, required: true },

  products: [
    {
      productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
      title: { type: String, required: true },
      imageUrl: { type: [String], required: true },
      quantity: { type: Number, required: true, default: 1 },
      price: { type: Number, required: true },
      sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      sellerName: { type: String, required: true },
      sellerEmail: { type: String, required: true },
    }
  ],
  totalPrice: { type: Number, required: true },
  status: { type: String, enum: ['Booked', 'Dispatched', 'Delivered', 'Cancelled'], default: 'Booked' },
  bookingDate: { type: Date, default: Date.now }
}, { timestamps: true });

module.exports = mongoose.model('Booking', BookingSchema);
