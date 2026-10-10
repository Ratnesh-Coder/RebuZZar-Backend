const mongoose = require('mongoose');
const validator = require('validator');

const Booking = require('../models/Booking');
const Product = require('../models/Product');
const HttpError = require('../utils/httpError');
const logger = require('../utils/logger');
const { MAX_ITEM_QUANTITY, MAX_BOOKING_ITEMS } = require('../utils/constants');

const NOT_DELETED = { $ne: true };

const UNAVAILABLE = 'One or more products are no longer available.';
const ALREADY_BOOKED = 'One or more products already booked.';
const CHANGED = 'One or more products were just booked or changed. Please review your cart and try again.';

const roundMoney = (n) => Math.round((n + Number.EPSILON) * 100) / 100;

/**
 * Validate the booking request and reduce it to [{ productId, quantity }].
 * Everything else the client sends (price, totalPrice, seller*, title, imageUrl) is ignored:
 * the server is the only authority for those values.
 */
const parseBookingRequest = (body) => {
  const products = body && body.products;
  if (!Array.isArray(products) || products.length === 0) throw new HttpError(400, 'Invalid booking data.');
  if (products.length > MAX_BOOKING_ITEMS) {
    throw new HttpError(400, `A booking can contain at most ${MAX_BOOKING_ITEMS} different products.`);
  }

  const seen = new Set();
  return products.map((item) => {
    const productId = item && item.productId;
    if (typeof productId !== 'string' || !validator.isMongoId(productId)) {
      throw new HttpError(400, 'Invalid booking data.');
    }
    if (seen.has(productId)) throw new HttpError(400, 'Duplicate products in booking.');
    seen.add(productId);

    // Missing quantity keeps the previous default of 1; anything present must be a sane integer.
    let quantity = 1;
    if (item.quantity !== undefined) {
      quantity = typeof item.quantity === 'number' || typeof item.quantity === 'string' ? Number(item.quantity) : NaN;
      if (!Number.isInteger(quantity) || quantity < 1 || quantity > MAX_ITEM_QUANTITY) {
        throw new HttpError(400, 'Invalid quantity.');
      }
    }
    return { productId, quantity };
  });
};

const isTransactionUnsupported = (err) =>
  err && (err.code === 20 || /Transaction numbers are only allowed|replica set member or mongos/i.test(err.message || ''));

/**
 * Atomically lock every product for this booking and create the booking.
 * Each product update is conditioned on the exact state/price the booking was priced from,
 * so a concurrent booking, deletion, un-approval or price edit makes the whole thing fail
 * (409) instead of booking at a stale price.
 */
const lockAndCreate = async ({ buyer, lines, totalPrice, session }) => {
  const opts = session ? { session } : {};
  const locked = [];
  try {
    for (const line of lines) {
      const res = await Product.updateOne(
        {
          _id: line.productId,
          isBooked: { $ne: true },
          isDeleted: NOT_DELETED,
          status: 'approved',
          price: line.price, // the price this booking was calculated from
        },
        { $set: { isBooked: true } },
        opts
      );
      if (res.modifiedCount !== 1) throw new HttpError(409, CHANGED);
      locked.push(line.productId);
    }

    const [booking] = await Booking.create(
      [{
        buyerId: buyer._id,
        buyerName: buyer.name,
        buyerEmail: buyer.email,
        products: lines,
        totalPrice,
      }],
      opts
    );
    return booking;
  } catch (err) {
    // Only relevant without a transaction (standalone MongoDB): undo the locks we took.
    if (!session && locked.length) {
      await Product.updateMany({ _id: { $in: locked } }, { $set: { isBooked: false } }).catch((e) =>
        logger.error('Failed to release product locks after a failed booking', e)
      );
    }
    throw err;
  }
};

/**
 * Create a booking from [{ productId, quantity }] using only trusted, database-derived data.
 */
const createBooking = async ({ buyer, items }) => {
  const ids = items.map((i) => i.productId);

  const products = await Product.find({ _id: { $in: ids }, isDeleted: NOT_DELETED })
    .populate('sellerId', 'name email');

  // Exists, not deleted AND approved: moderation cannot be bypassed by calling the API directly.
  // (Moderation state is deliberately not revealed to buyers: same message as "gone".)
  if (products.length !== ids.length || products.some((p) => p.status !== 'approved')) {
    throw new HttpError(400, UNAVAILABLE);
  }
  if (products.some((p) => p.isBooked)) throw new HttpError(400, ALREADY_BOOKED);

  // Prevent buyers from booking their own products.
  const buyerId = String(buyer._id);

  if (products.some((p) => String(p.sellerId?._id || p.sellerId) === buyerId)) {
    throw new HttpError(403, 'You cannot book your own product.');
  }

  const byId = new Map(products.map((p) => [String(p._id), p]));

  const lines = items.map(({ productId, quantity }) => {
    const p = byId.get(productId);
    const seller = p.sellerId || {};
    const sellerName = seller.name || p.sellerName;
    const sellerEmail = seller.email || p.sellerEmail;
    if (!sellerName || !sellerEmail) {
      throw new HttpError(500, 'Seller information missing for one or more products.');
    }
    return {
      productId: p._id,
      title: p.title,
      imageUrl: p.imageUrl,
      sellerId: seller._id || (typeof p.populated === 'function' && p.populated('sellerId')) || undefined,
      sellerName,
      sellerEmail,
      quantity,
      price: p.price, // authoritative: from the database
    };
  });

  const totalPrice = roundMoney(lines.reduce((sum, l) => sum + l.price * l.quantity, 0));

  const session = await mongoose.startSession();
  try {
    let booking;
    try {
      await session.withTransaction(async () => {
        booking = await lockAndCreate({ buyer, lines, totalPrice, session });
      });
    } catch (err) {
      if (!isTransactionUnsupported(err)) throw err;
      // MongoDB without a replica set (typically local development): same checks, no transaction.
      logger.warn('MongoDB transactions are unavailable; creating the booking without one.');
      booking = await lockAndCreate({ buyer, lines, totalPrice, session: null });
    }
    return booking;
  } finally {
    await session.endSession();
  }
};

module.exports = { parseBookingRequest, createBooking, roundMoney, UNAVAILABLE, ALREADY_BOOKED };
