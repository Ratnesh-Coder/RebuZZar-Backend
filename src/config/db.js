const mongoose = require('mongoose');
const logger = require('../utils/logger');

/** Connect to MongoDB. Rejects on failure; server.js decides whether to exit. */
const connectDB = async () => {
  await mongoose.connect(process.env.MONGO_URI);
  logger.info('MongoDB connected.');
};

module.exports = connectDB;
