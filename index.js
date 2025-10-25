// ========================
// BACKEND SERVER SETUP
// ========================

// --- IMPORTS ---
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const validator = require('validator');
require('dotenv').config();

// Cloudinary + multer-storage-cloudinary
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// --- APP CONFIG ---
const app = express();
const port = process.env.PORT || 5000;

// ========================
// UTILITY: SAFE LOGGER
// ========================
const logError = (context, error) => {
  if (process.env.NODE_ENV === 'development') {
    console.error(`❌ ${context}:`, error);
  } else {
    // avoid leaking stack in production logs
    console.error(`❌ ${context}:`, error && error.message ? error.message : error);
  }
};

// ========================
// CLOUDINARY CONFIG
// ========================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ========================
// MIDDLEWARE
// ========================
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => {
  req.query = { ...req.query };
  mongoSanitize.sanitize(req.query);
  next();
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: 'Too many requests from this IP, try again later.' },
});

// ========================
// DATABASE CONNECTION
// ========================
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('✅ MongoDB Connected Successfully'))
  .catch(err => {
    logError('MongoDB Connection Error', err);
    process.exit(1);
  });

// ========================
// SCHEMAS & MODELS
// ========================
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  avatar: { type: String, default: 'https://via.placeholder.com/150' },
  joinDate: { type: Date, default: Date.now },
  programType: { type: String, required: true, enum: ['Diploma', 'UG', 'PG', 'PhD'] },
  department: { type: String, required: true },
  year: { type: String, required: true },
  studentCode: { type: String }, // optional
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
  role: { type: String, enum: ['student', 'admin'], default: 'student' },
}, { timestamps: true });

const ProductSchema = new mongoose.Schema({
  title: { type: String, required: true },
  price: { type: Number, required: true },
  description: { type: String, required: true },
  imageUrl: { type: String, required: true },
  category: { type: String, required: true },
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  postDate: { type: Date, default: Date.now },
}, { timestamps: true });

// Cascade delete
UserSchema.pre('findOneAndDelete', async function (next) {
  try {
    const user = await this.model.findOne(this.getFilter());
    if (user) await Product.deleteMany({ sellerId: user._id });
    next();
  } catch (err) {
    next(err);
  }
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);

// ========================
// MULTER + CLOUDINARY STORAGE CONFIG
// ========================

// Cloudinary storage using multer-storage-cloudinary
const cloudinaryStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: process.env.CLOUDINARY_FOLDER || 'bw-market',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 1200, crop: 'limit' }], // keep images reasonable size
  },
});

// multer using cloudinary storage
const upload = multer({
  storage: cloudinaryStorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Only image files allowed (jpeg, png, webp).'), false);
    }
    const allowedExt = /jpeg|jpg|png|webp/;
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowedExt.test(ext)) {
      return cb(new Error('Only image files allowed (jpeg, png, webp).'), false);
    }
    cb(null, true);
  },
});

// ========================
// AUTH & ROLE MIDDLEWARE
// ========================
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: 'Authorization token required.' });

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ message: 'Token format: "Bearer TOKEN"' });

    const token = parts[1];
    if (!validator.isMongoId(token)) return res.status(401).json({ message: 'Invalid token format.' });

    const user = await User.findById(token);
    if (!user) return res.status(403).json({ message: 'Invalid or unknown user token.' });

    req.userId = user._id;
    next();
  } catch (err) {
    next(err);
  }
};

const adminMiddleware = async (req, res, next) => {
  try {
    const user = await User.findById(req.userId);
    if (!user || user.role !== 'admin') return res.status(403).json({ message: 'Access denied: Admins only.' });
    next();
  } catch (err) {
    next(err); // Pass error to centralized handler
  }
};

// ========================
// ROUTES
// ========================

// Helper to wrap async route functions
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// --- PROFILE ROUTES ---
// Avatar upload: uploads to Cloudinary; we store the secure URL returned
app.post('/api/profile/avatar', authMiddleware, upload.single('avatar'), asyncHandler(async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'Avatar image file is required.' });

  // multer-storage-cloudinary sets file.path to the URL in many versions; be defensive
  const avatarUrl = req.file.path || req.file?.location || req.file?.secure_url || req.file?.url;
  if (!avatarUrl) return res.status(500).json({ message: 'Failed to retrieve uploaded avatar URL.' });

  const updatedUser = await User.findByIdAndUpdate(req.userId, { avatar: avatarUrl }, { new: true }).select('-password');
  if (!updatedUser) return res.status(404).json({ message: 'User not found.' });

  res.json(updatedUser);
}));

// ✅ Updated Edit Profile Route
app.put('/api/profile', authMiddleware, asyncHandler(async (req, res) => {
    const { email, password, ...updates } = req.body;

    // Disallow sensitive field changes
    const disallowedFields = ['role', '_id', 'email', 'password', 'resetPasswordToken', 'resetPasswordExpires'];
    disallowedFields.forEach((f) => delete updates[f]);

    // Whitelisted editable fields
    const allowedUpdates = ['name', 'programType', 'department', 'year', 'studentCode', 'avatar'];

    const validUpdates = {};
    for (const field of allowedUpdates) {
      if (updates[field] !== undefined) validUpdates[field] = updates[field];
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      { $set: validUpdates },
      { new: true, runValidators: true }
    ).select('-password');

    if (!updatedUser) return res.status(404).json({ message: 'User not found.' });
    res.json(updatedUser);
  })
);

// --- PRODUCT ROUTES ---
app.get('/api/products', asyncHandler(async (req, res) => {
  const { category, search } = req.query;
  const filter = { status: 'approved' };
  if (category) filter.category = { $regex: new RegExp(`^${category}$`, 'i') };
  if (search) filter.title = { $regex: search, $options: 'i' };

  const products = await Product.find(filter);
  res.json(products);
}));

app.get('/api/products/:id', asyncHandler(async (req, res) => {
  const product = await Product.findById(req.params.id);
  if (!product) return res.status(404).json({ message: 'Product not found' });
  res.json(product);
}));

app.get('/api/profile/products', authMiddleware, asyncHandler(async (req, res) => {
  const userProducts = await Product.find({ sellerId: req.userId });
  res.json(userProducts);
}));

// Create product: upload image to Cloudinary and store returned URL
app.post('/api/products', authMiddleware, upload.single('image'), asyncHandler(async (req, res) => {
  const { title, price, description, category } = req.body;
  if (!req.file || !title || !price || !description || !category)
    return res.status(400).json({ message: 'All fields, including image, are required.' });

  // Get Cloudinary URL defensively
  const imageUrl = req.file.path || req.file?.location || req.file?.secure_url || req.file?.url;
  if (!imageUrl) return res.status(500).json({ message: 'Failed to retrieve uploaded image URL.' });

  const newProduct = new Product({ title, price: Number(price), description, category, imageUrl, sellerId: req.userId });
  await newProduct.save();
  res.status(201).json(newProduct);
}));

app.put('/api/products/:id', authMiddleware, asyncHandler(async (req, res) => {
  const { title, price, description, category } = req.body;
  const product = await Product.findById(req.params.id);
  if (!product) return res.status(404).json({ message: 'Product not found.' });
  if (product.sellerId.toString() !== req.userId.toString())
    return res.status(403).json({ message: 'User not authorized to edit this product.' });

  product.title = title;
  product.price = price;
  product.description = description;
  product.category = category;

  const updatedProduct = await product.save();
  res.json(updatedProduct);
}));

app.delete('/api/products/:id', authMiddleware, asyncHandler(async (req, res) => {
  const product = await Product.findById(req.params.id);
  if (!product) return res.status(404).json({ message: 'Product not found.' });
  if (product.sellerId.toString() !== req.userId.toString())
    return res.status(403).json({ message: 'User not authorized to delete this product.' });

  await Product.findByIdAndDelete(req.params.id);
  res.json({ message: 'Product deleted successfully.' });
}));

// --- ADMIN ROUTES ---
app.get('/api/admin/products/pending', authMiddleware, adminMiddleware, asyncHandler(async (req, res) => {
  const pendingProducts = await Product.find({ status: 'pending' }).populate('sellerId', 'name email');
  res.json(pendingProducts);
}));

app.put('/api/admin/products/:id/status', authMiddleware, adminMiddleware, asyncHandler(async (req, res) => {
  const { status } = req.body;
  if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ message: 'Invalid status.' });

  const product = await Product.findById(req.params.id);
  if (!product) return res.status(404).json({ message: 'Product not found.' });

  product.status = status;
  await product.save();

  res.json({ message: `Product ${status} successfully.`, product });
}));

// --- AUTH ROUTES ---
app.post('/api/auth/signup', asyncHandler(async (req, res) => {
  const { name, email, password, programType, department, year, studentCode } = req.body;

  const universityDomain = process.env.UNIVERSITY_DOMAIN || '@brainwareuniversity.ac.in';

  // Basic validation
  if (!email || !validator.isEmail(email) || !email.endsWith(universityDomain))
    return res.status(400).json({ message: `Invalid email` });

  if (!name || !password || !programType || !department || !year)
    return res.status(400).json({ message: 'All required fields are required.' });

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser)
    return res.status(409).json({ message: 'Account with this email already exists.' });

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create new user
  const newUser = new User({
    name,
    email,
    password: hashedPassword,
    programType,
    department,
    year,
    studentCode
  });

  await newUser.save();

  // Send response without password
  const { password: _, ...userToSend } = newUser.toObject();
  res.status(201).json({ message: 'User created successfully!', user: userToSend, token: userToSend._id });
}));

app.post('/api/auth/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email and password required.' });

  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ message: 'Invalid email or password' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ message: 'Invalid email or password' });

  const { password: _, ...userToSend } = user.toObject();
  res.json({ message: "Login successful!", user: userToSend, token: userToSend._id });
}));

// --- PASSWORD RESET ---
app.post('/api/auth/forgot-password', authLimiter, asyncHandler(async (req, res) => {
  const { email } = req.body;
  if (!email || !validator.isEmail(email)) return res.json({ message: 'If an account exists, a password reset link has been sent.' });

  const user = await User.findOne({ email });
  if (!user) return res.json({ message: 'If an account exists, a password reset link has been sent.' });

  const rawToken = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

  user.resetPasswordToken = hashedToken;
  user.resetPasswordExpires = Date.now() + 1000 * 60 * 60;
  await user.save();

  const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
  const resetLink = `${FRONTEND_URL}/reset-password/${rawToken}`;

  const mailPort = Number(process.env.EMAIL_PORT) || 587;
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: mailPort,
    secure: process.env.EMAIL_SECURE === 'true' || mailPort === 465,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
  });

  const html = `
    <html>
      <body style="font-family: Arial, sans-serif;">
        <h2>Password Reset Request</h2>
        <p><a href="${resetLink}">Click here to reset your password</a></p>
        <p>Expires in 1 hour.</p>
      </body>
    </html>`;

  await transporter.sendMail({
    from: process.env.EMAIL_FROM || '"Support" <no-reply@campuskart.com>',
    to: `${user.name} <${user.email}>`,
    subject: 'Password Reset Link',
    text: `Reset password: ${resetLink}`,
    html
  });

  res.json({ message: 'If an account exists, a password reset link has been sent.' });
}));

app.post('/api/auth/reset-password/:token', asyncHandler(async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters long.' });

  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  const user = await User.findOne({ resetPasswordToken: hashedToken, resetPasswordExpires: { $gt: Date.now() } });
  if (!user) return res.status(400).json({ message: 'Token invalid or expired.' });

  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(password, salt);
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();

  res.json({ message: 'Password updated successfully.' });
}));

// ========================
// CENTRALIZED ERROR HANDLER
// ========================
app.use((err, req, res, next) => {
  logError('Unhandled Error', err);
  // send safe error to client
  res.status(500).json({ message: err.message || 'Internal Server Error' });
});

// ========================
// START SERVER
// ========================
app.listen(port, () => {
  console.log(`✅ Backend server is running on http://localhost:${port}`);
});
