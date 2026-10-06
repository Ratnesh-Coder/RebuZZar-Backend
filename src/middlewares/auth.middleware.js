const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');

module.exports = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ message: 'Authorization token required.' });
    }

    const [type, token] = authHeader.split(' ');
    if (type !== 'Bearer' || !token) {
      return res.status(401).json({ message: 'Invalid token format.' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });

    if (!decoded.id || typeof decoded.id !== 'string') {
      return res.status(401).json({ message: 'Invalid token payload.' });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ message: 'User not found.' });
    }

    req.user = user;
    req.userId = user._id;

    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired, please login again' });
    }

    if (error.name === 'JsonWebTokenError' || error.name === 'NotBeforeError' || error.name === 'CastError') {
      return res.status(401).json({ message: 'Invalid token' });
    }

    logger.error('Auth middleware unexpected error', error);
    return res.status(401).json({ message: 'Unauthorized' });
  }
};
