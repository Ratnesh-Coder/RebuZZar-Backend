const express = require('express');
const router = express.Router();

const bookingController = require('../controllers/booking.controller');
const auth = require('../middlewares/auth.middleware');
const validateObjectId = require('../middlewares/validateObjectId');

const bookingId = validateObjectId('id', 404, 'Booking not found.');

// Create booking
router.post('/create', auth, bookingController.createBooking);

// Get my bookings
router.get('/my-bookings', auth, bookingController.getMyBookings);

// Get booking by ID (owner or admin)
router.get('/:id', auth, bookingId, bookingController.getBookingById);

// Cancel booking (owner)
router.put('/:id/cancel', auth, bookingId, bookingController.cancelBooking);

module.exports = router;
