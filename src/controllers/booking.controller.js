const Booking = require('../models/Booking');
const Product = require('../models/Product');
const HttpError = require('../utils/httpError');
const bookingService = require('../services/booking.service');
const bookingEmail = require('../services/email/booking.email');

const CANCELLABLE = ['Booked', 'Dispatched']; // Cancelled / Delivered cannot be cancelled (unchanged)

/* CREATE BOOKING */
exports.createBooking = async (req, res) => {
  // Only productId + quantity are taken from the client; prices come from the database.
  const items = bookingService.parseBookingRequest(req.body);
  const buyer = req.user;

  const booking = await bookingService.createBooking({ buyer, items });

  // The booking is committed: respond first, then notify. Mail failures never undo or fail it.
  res.status(201).json({
    message: 'Booking successful!',
    bookingId: booking._id,
    booking,
  });
  await bookingEmail.notifyBookingCreated({ buyer, booking });
};

/* GET MY BOOKINGS */
exports.getMyBookings = async (req, res) => {
  const bookings = await Booking.find({ buyerId: req.userId }).sort({ bookingDate: -1 });
  res.json(bookings);
};

/*
 * GET BOOKING BY ID - owner or admin only. Everyone else gets the same 404 as a missing
 * booking, so booking ids cannot be probed.
 */
exports.getBookingById = async (req, res) => {
  const booking = await Booking.findById(req.params.id);
  const isOwner = Boolean(booking && booking.buyerId && booking.buyerId.equals(req.userId));
  const isAdmin = req.user && req.user.role === 'admin';

  if (!booking || (!isOwner && !isAdmin)) throw new HttpError(404, 'Booking not found.');

  res.json(booking);
};

/* CANCEL BOOKING - owner only, atomic status transition */
exports.cancelBooking = async (req, res) => {
  const booking = await Booking.findOneAndUpdate(
    { _id: req.params.id, buyerId: req.userId, status: { $in: CANCELLABLE } },
    { $set: { status: 'Cancelled' } },
    { new: true }
  );

  if (!booking) {
    // Not cancellable: tell "someone else's / unknown" (404) apart from "mine, wrong state" (400).
    const own = await Booking.exists({ _id: req.params.id, buyerId: req.userId });
    if (!own) throw new HttpError(404, 'Booking not found.');
    throw new HttpError(400, 'Cannot cancel this booking.');
  }

  await Product.updateMany(
    { _id: { $in: booking.products.map((p) => p.productId) } },
    { $set: { isBooked: false } }
  );

  res.json({ message: 'Booking cancelled successfully.', booking });
  await bookingEmail.notifyBookingCancelled({ buyer: req.user, booking });
};
