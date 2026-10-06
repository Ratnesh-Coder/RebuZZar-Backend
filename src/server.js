// Start with: node src/server.js   (or: npm start)

// 1) environment first - everything below reads process.env
const { loadEnv, validateEnv } = require('./config/env');
loadEnv();

const logger = require('./utils/logger');

try {
  validateEnv();
} catch (err) {
  logger.error(err.message);
  process.exit(1);
}

const connectDB = require('./config/db');
const app = require('./app');

const PORT = process.env.PORT || 5000;

const start = async () => {
  try {
    await connectDB();
  } catch (err) {
    logger.error('MongoDB connection failed', err);
    process.exit(1);
  }

  app.listen(PORT, () => {
    logger.info(`Backend server running on port ${PORT}`);
  });
};

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled promise rejection', reason instanceof Error ? reason : new Error(String(reason)));
});

start();
