// ============================================================================
// REBUZZAR - BACKEND SERVER (index.js)
// Rearranged & commented for readability (no logic changes)
// ============================================================================

// ----------------------------
// IMPORTS / ENV
// ----------------------------
const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
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
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Cloudinary + multer-storage-cloudinary
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// ----------------------------
// APP CONFIG
// ----------------------------
const app = express();
const port = process.env.PORT || 5000;

// ----------------------------
// UTILITY: SAFE LOGGER
// - Keeps stack traces in development only
// ----------------------------
const logError = (context, error) => {
  if (process.env.NODE_ENV === 'development') {
    console.error(`❌ ${context}:`, error);
  } else {
    // avoid leaking stack in production logs
    console.error(`❌ ${context}:`, error && error.message ? error.message : error);
  }
};

// ----------------------------
// CLOUDINARY CONFIG
// ----------------------------
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ----------------------------
// GLOBAL MIDDLEWARE
// ----------------------------
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '10kb' }));
app.use(passport.initialize());

// NOTE: using manual sanitize of req.query because express-mongo-sanitize's
// default app.use(mongoSanitize()) caused a runtime error in this app's environment.
// The manual approach clones req.query and sanitizes the clone in-place.
app.use((req, res, next) => { 
  req.query = { ...req.query };
  mongoSanitize.sanitize(req.query);
  next();
});

// Rate limiter for sensitive endpoints (applied individually where needed)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: 'Too many requests from this IP, try again later.' },
});

// ----------------------------
// DATABASE CONNECTION
// ----------------------------
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected Successfully'))
  .catch(err => {
    logError('MongoDB Connection Error', err);
    process.exit(1);
  });

// ----------------------------
// SCHEMAS & MODELS
// ----------------------------
// USER
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

  // ---------- NEW: Email verification fields ----------
  isVerified: { type: Boolean, default: false },        // whether email is verified
  emailOTP: { type: String },                           // SHA256 hash of OTP (do NOT store plain OTP)
  emailOTPExpires: { type: Date },                      // expiry timestamp for OTP
  // ----------------------------------------------------

  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
  role: { type: String, enum: ['student', 'admin'], default: 'student' },
}, { timestamps: true });

// PRODUCT
const ProductSchema = new mongoose.Schema({
  title: { type: String, required: true },
  price: { type: Number, required: true },
  description: { type: String, required: true },
  imageUrl: { type: [String], required: true },
  category: { type: String, required: true },
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  postDate: { type: Date, default: Date.now },
  isBooked: { type: Boolean, default: false },
}, { timestamps: true });

// BOOKING
const BookingSchema = new mongoose.Schema({
  buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  products: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    quantity: { type: Number, required: true, default: 1 },
    price: { type: Number, required: true }
  }],
  totalPrice: { type: Number, required: true },
  status: { 
    type: String, 
    enum: ['Booked', 'Dispatched', 'Delivered', 'Cancelled'], 
    default: 'Booked' 
  },
  bookingDate: { type: Date, default: Date.now }
}, { timestamps: true });

const Booking = mongoose.model('Booking', BookingSchema);

// Register Product model before using it in hooks
const Product = mongoose.model('Product', ProductSchema);

// Cascade delete: when a user is deleted, delete their products
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

// CART (snapshot style)
const CartItemSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  title: { type: String, required: true },
  price: { type: Number, required: true },
  imageUrl: { type: [String], default: [] },
  quantity: { type: Number, required: true, min: 1, default: 1 },
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { _id: false });

const CartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  items: [CartItemSchema],
  updatedAt: { type: Date, default: Date.now },
}, { timestamps: true });

CartSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

const Cart = mongoose.model('Cart', CartSchema);

// ----------------------------
// MULTER + CLOUDINARY STORAGE
// ----------------------------
const cloudinaryStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: process.env.CLOUDINARY_FOLDER || 'bw-market',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 1200, crop: 'limit' }],
  },
});

const upload = multer({
  storage: cloudinaryStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
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

// ----------------------------
// AUTH & ROLE MIDDLEWARE
// ----------------------------
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: 'Authorization token required.' });

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer')
      return res.status(401).json({ message: 'Token format: "Bearer TOKEN"' });

    const token = parts[1];

    // Basic sanity checks (avoid passing 'null'/'undefined' etc into jwt.verify)
    if (!token || typeof token !== 'string' || token.trim() === '' || token === 'null' || token === 'undefined') {
      return res.status(401).json({ message: 'Invalid authorization token.' });
    }

    // Verify JWT token (this can throw if token is malformed/invalid)
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (verifyErr) {
      // Return a 401 instead of letting the error bubble to the global handler
      return res.status(401).json({ message: verifyErr.message || 'Unauthorized' });
    }

    if (!decoded || !decoded.id) return res.status(401).json({ message: 'Invalid token payload.' });

    const user = await User.findById(decoded.id);
    if (!user) return res.status(403).json({ message: 'Invalid or unknown user token.' });

    req.userId = user._id;
    next();
  } catch (err) {
    // fallback
    next(err);
  }
};

const adminMiddleware = async (req, res, next) => {
  try {
    const user = await User.findById(req.userId);
    if (!user || user.role !== 'admin') return res.status(403).json({ message: 'Access denied: Admins only.' });
    next();
  } catch (err) {
    next(err);
  }
};

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        let user = await User.findOne({ email });

        if (!user) {
          user = await User.create({
            name: profile.displayName,
            email,
            password: crypto.randomBytes(16).toString('hex'), // random password
            isVerified: true,
          });
        }

        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

// ----------------------------
// ROUTES: helper
// ----------------------------
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ----------------------------
// PROFILE ROUTES
// ----------------------------
app.post('/api/profile/avatar', authMiddleware, upload.single('avatar'), asyncHandler(async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'Avatar image file is required.' });

  const avatarUrl = req.file.path || req.file?.location || req.file?.secure_url || req.file?.url;
  if (!avatarUrl) return res.status(500).json({ message: 'Failed to retrieve uploaded avatar URL.' });

  const updatedUser = await User.findByIdAndUpdate(req.userId, { avatar: avatarUrl }, { new: true }).select('-password');
  if (!updatedUser) return res.status(404).json({ message: 'User not found.' });

  res.json(updatedUser);
}));

app.put('/api/profile', authMiddleware, asyncHandler(async (req, res) => {
    const { email, password, ...updates } = req.body;

    const disallowedFields = ['role', '_id', 'email', 'password', 'resetPasswordToken', 'resetPasswordExpires'];
    disallowedFields.forEach((f) => delete updates[f]);

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

// ----------------------------
// PRODUCT ROUTES
// ----------------------------
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

app.get('/api/products/category/:categoryName', asyncHandler(async (req, res) => {
  const { categoryName } = req.params;
  
  // Find products where the category matches (case-insensitive)
  const products = await Product.find({ 
    category: { $regex: new RegExp(`^${categoryName}$`, 'i') },
    status: 'approved' // Ensure you only show approved products
  });

  if (!products || products.length === 0) {
    return res.json([]); 
  }

  res.json(products);
}));

app.get('/api/profile/products', authMiddleware, asyncHandler(async (req, res) => {
  const userProducts = await Product.find({ sellerId: req.userId });
  res.json(userProducts);
}));

app.post('/api/products', authMiddleware, upload.array('images', 5), asyncHandler(async (req, res) => {

  const { title, price, description, category } = req.body;
  if (!req.files || req.files.length === 0 || !title || !price || !description || !category)
    return res.status(400).json({ message: 'All fields, including image, are required.' });

  const imageUrls = req.files.map(file => file.path || file.location || file.secure_url || file.url);
  if (!imageUrls || imageUrls.length === 0) 
    return res.status(400).json({ message: 'At least one image is required.' });

  const newProduct = new Product({ 
    title, 
    price: Number(price), 
    description, 
    category, 
    imageUrl: imageUrls,
    sellerId: req.userId });
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

// ----------------------------
// ADMIN ROUTES
// ----------------------------
app.get('/api/admin/products/pending', authMiddleware, adminMiddleware, asyncHandler(async (req, res) => {
  const pendingProducts = await Product.find({ status: 'pending' }).populate('sellerId', 'name email');
  res.json(pendingProducts);
}));

app.put('/api/admin/products/:id/status', authMiddleware, adminMiddleware, asyncHandler(async (req, res) => {
  const { status } = req.body;
  if (!['approved', 'rejected'].includes(status)) 
    return res.status(400).json({ message: 'Invalid status.' });

  const product = await Product.findById(req.params.id);
  if (!product) 
    return res.status(404).json({ message: 'Product not found.' });

  product.status = status;
  await product.save();

  res.json({ message: `Product ${status} successfully.`, product });
}));

// ----------------------------
// AUTH ROUTES
// ----------------------------
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

  // Generate OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');

  // Create new user
  const newUser = new User({
    name,
    email,
    password: hashedPassword,
    programType,
    department,
    year,
    studentCode,
    isVerified: false,
    emailOTP: hashedOTP,
    emailOTPExpires: Date.now() + 10 * 60 * 1000, // 10 min expiry
  });

  await newUser.save();

  // ✉️ Send OTP mail
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: Number(process.env.EMAIL_PORT) || 587,
    secure: process.env.EMAIL_SECURE === 'true',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  });

  const mailOptions = {
    from: process.env.EMAIL_FROM || '"RebuZZar" <no-reply@rebuzzar.com>',
    to: newUser.email,
    subject: 'Verify your RebuZZar Account',
    html: `
      <h2>Verify your RebuZZar account</h2>
      <p>Hi ${newUser.name},</p>
      <p>Your One-Time Password (OTP) for verification is:</p>
      <h1 style="letter-spacing:3px;">${otp}</h1>
      <p>This code expires in 10 minutes.</p>
      <p>– RebuZZar Team</p>
    `,
  };

  await transporter.sendMail(mailOptions);

  // ⛔ Do NOT send token yet; user must verify OTP first
  res.status(201).json({
    message: 'User created! OTP sent to your email for verification.',
    userId: newUser._id,
  });
}));

// ✅ VERIFY EMAIL OTP
app.post('/api/auth/verify-otp', asyncHandler(async (req, res) => {
  const { userId, otp } = req.body;

  if (!userId || !otp)
    return res.status(400).json({ message: 'User ID and OTP are required.' });

  const user = await User.findById(userId);
  if (!user)
    return res.status(404).json({ message: 'User not found.' });

  // If already verified
  if (user.isVerified)
    return res.status(400).json({ message: 'Email already verified.' });

  // Check expiry
  if (user.emailOTPExpires < Date.now())
    return res.status(400).json({ message: 'OTP expired. Please sign up again.' });

  // Compare hash
  const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');
  if (hashedOTP !== user.emailOTP)
    return res.status(400).json({ message: 'Invalid OTP.' });

  // ✅ Mark verified and clear OTP fields
  user.isVerified = true;
  user.emailOTP = undefined;
  user.emailOTPExpires = undefined;
  await user.save();

  // ✅ Generate token for login
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d'
  });

  res.status(200).json({
    message: 'Email verified successfully!',
    token,
  });
}));

// Redirect to Google login
app.get('/api/auth/google', 
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Google callback
app.get('/api/auth/google/callback',
  passport.authenticate('google', { session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`http://localhost:5173/?token=${token}`);
  }
);

app.post('/api/auth/login', authLimiter, asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Validation
  if (!email || !password)
    return res.status(400).json({ message: 'Email and password required.' });

  // Find user
  const user = await User.findOne({ email });
  if (!user)
    return res.status(401).json({ message: 'Invalid email or password' });

  // Check password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch)
    return res.status(401).json({ message: 'Invalid email or password' });

  // Generate JWT token
  const token = jwt.sign(
    { id: user._id },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );

  // Remove password before sending user data
  const { password: _, ...userToSend } = user.toObject();

  // Send response
  res.json({
    message: "Login successful!",
    user: userToSend,
    token
  });
}));

// ----------------------------
// PASSWORD RESET
// ----------------------------
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

  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: Number(process.env.EMAIL_PORT) || 587,
    secure: process.env.EMAIL_SECURE === 'true',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  });

  const html = `
    <html>
      <body style="font-family: Arial, sans-serif;">
        <h2>Password Reset Request</h2>
        <p>Click below to reset your password:</p>
        <a href="${resetLink}" style="background:#007bff;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">Reset Password</a>
        <p>This link will expire in 1 hour.</p>
      </body>
    </html>`;

  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: user.email,
    subject: 'Password Reset Link - RebuZZar',
    html,
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

// ----------------------------
// NODEMAILER TRANSPORTER
// ----------------------------
const mailPort = Number(process.env.EMAIL_PORT) || 465;
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: mailPort,
  secure: process.env.EMAIL_SECURE === 'true' || mailPort === 465,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ----------------------------
// BOOKING ROUTES
// ----------------------------
app.post('/api/bookings/create', authMiddleware, asyncHandler(async (req, res) => {
  const { products, totalPrice } = req.body;

  if (!products || products.length === 0 || !totalPrice) {
    return res.status(400).json({ message: 'Booking requires products and a total price.' });
  }

  const newBooking = new Booking({
    buyerId: req.userId, // From authMiddleware
    products,
    totalPrice,
  });

  await newBooking.save();

  for (const item of products) {
    await Product.findByIdAndUpdate(item.productId, { isBooked: true });
  }

  // ----------------------------
  // EMAIL NOTIFICATIONS
  // ----------------------------
  // Fetch buyer info and product details (including seller)
  const buyer = await User.findById(req.userId).select('name email');
  const productIds = products.map(p => p.productId);
  const bookedProducts = await Product.find({ _id: { $in: productIds } }).populate('sellerId', 'name email');

  // Prepare nodemailer transporter (uses existing env variables)
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: Number(process.env.EMAIL_PORT) || 587,
    secure: process.env.EMAIL_SECURE === 'true' || (process.env.EMAIL_PORT === '465'),
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  // --- Buyer email ---
  const buyerProductsHtml = bookedProducts.map(p => {
    const qty = (products.find(x => String(x.productId) === String(p._id)) || {}).quantity || 1;
    const priceSnapshot = (products.find(x => String(x.productId) === String(p._id)) || {}).price ?? p.price;
    return `<li><b>${p.title}</b> — Qty: ${qty} — ₹${Number(priceSnapshot).toLocaleString('en-IN')}</li>`;
  }).join('');

  const buyerMail = {
    from: `"RebuZZar" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
    to: buyer.email,
    subject: 'Booking Confirmation — RebuZZar',
    html: `
      <div style="font-family: Arial, sans-serif; color: #222;">
        <h3>Hi ${buyer.name},</h3>
        <p>Thank you for booking with RebuZZar. Your booking is confirmed.</p>
        <p><strong>Booking ID:</strong> ${newBooking._id}</p>
        <p><strong>Items booked:</strong></p>
        <ul>${buyerProductsHtml}</ul>
        <p><strong>Total:</strong> ₹${Number(totalPrice).toLocaleString('en-IN')}</p>
        <p>We will notify you with delivery / pickup details shortly.</p>
        <p>— RebuZZar Team</p>
      </div>
    `
  };

  // --- Admin email ---
  const adminProductsHtml = bookedProducts.map(p => {
    const qty = (products.find(x => String(x.productId) === String(p._id)) || {}).quantity || 1;
    const priceSnapshot = (products.find(x => String(x.productId) === String(p._id)) || {}).price ?? p.price;
    return `<li>
      <b>${p.title}</b> — Qty: ${qty} — ₹${Number(priceSnapshot).toLocaleString('en-IN')}
      <br/><small>Seller: ${p.sellerId?.name || 'N/A'} (${p.sellerId?.email || 'N/A'})</small>
    </li>`;
  }).join('');

  const adminMail = {
    from: `"RebuZZar System" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
    to: process.env.ADMIN_EMAIL, // <--- make sure ADMIN_EMAIL is set in .env
    subject: `New Booking (${buyer.name}) — ${bookedProducts.length} item(s)`,
    html: `
      <div style="font-family: Arial, sans-serif; color: #222;">
        <h3>New Booking Alert</h3>
        <p><strong>Buyer:</strong> ${buyer.name} — ${buyer.email}</p>
        <p><strong>Booking ID:</strong> ${newBooking._id}</p>
        <p><strong>Total:</strong> ₹${Number(totalPrice).toLocaleString('en-IN')}</p>
        <p><strong>Items:</strong></p>
        <ul>${adminProductsHtml}</ul>
        <p>Note: sellers will be notified that their item is booked. Pickup date/time will be provided separately.</p>
      </div>
    `
  };

  // --- Seller emails (one email per seller, listing only that seller's sold items) ---
  // group products by seller email
  const sellerMap = new Map(); // sellerId -> { seller, items: [] }
  for (const p of bookedProducts) {
    const seller = p.sellerId;
    if (!seller || !seller.email) continue; // skip if no seller contact
    const key = String(seller._id);
    const qty = (products.find(x => String(x.productId) === String(p._id)) || {}).quantity || 1;
    const priceSnapshot = (products.find(x => String(x.productId) === String(p._id)) || {}).price ?? p.price;
    const itemEntry = { title: p.title, qty, price: priceSnapshot, id: p._id };

    if (!sellerMap.has(key)) {
      sellerMap.set(key, { seller, items: [itemEntry] });
    } else {
      sellerMap.get(key).items.push(itemEntry);
    }
  }

  const sellerMailPromises = [];
  for (const [_, { seller, items }] of sellerMap) {
    const itemsHtml = items.map(it => `<li><b>${it.title}</b> — Qty: ${it.qty} — ₹${Number(it.price).toLocaleString('en-IN')}</li>`).join('');
    const sellerMail = {
      from: `"RebuZZar" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
      to: seller.email,
      subject: `Your item(s) have been booked on RebuZZar`,
      html: `
        <div style="font-family: Arial, sans-serif; color: #222;">
          <h3>Hi ${seller.name || 'Seller'},</h3>
          <p>The following item(s) of yours have been booked on RebuZZar:</p>
          <ul>${itemsHtml}</ul>
          <p><strong>Booking ID:</strong> ${newBooking._id}</p>
          <p>We will notify you soon with the pickup date & time.</p>
          <p>Please do not contact the buyer directly — RebuZZar will coordinate pickup/delivery.</p>
          <p>— RebuZZar Team</p>
        </div>
      `
    };

    sellerMailPromises.push(transporter.sendMail(sellerMail).catch(err => {
      // log seller mail error but do not break the whole flow
      console.error('Seller mail error for', seller.email, err && err.message ? err.message : err);
      return null;
    }));
  }

  // Send buyer + admin + all seller emails (safely)
  try {
    // buyer + admin in parallel, plus all seller promises
    await Promise.all([
      transporter.sendMail(buyerMail),
      transporter.sendMail(adminMail),
      ...sellerMailPromises
    ]);
  } catch (err) {
    // if sending fails, log but booking is already created & products marked booked
    console.error('Booking created but failed to send one or more emails:', err);
    // We still respond success to frontend; emails can be retried separately if needed.
  }

  res.status(201).json({
      message: 'Booking successful!',
      bookingId: newBooking._id,
      booking: newBooking
  });
}));

app.get('/api/bookings/my-bookings', authMiddleware, asyncHandler(async (req, res) => {
    const bookings = await Booking.find({ buyerId: req.userId })
        .populate('products.productId', 'title imageUrl') // Get product details
        .sort({ bookingDate: -1 }); // Show newest first

    if (!bookings) {
        return res.status(404).json({ message: 'No bookings found.' });
    }
    res.json(bookings);
}));

// Get booking details by ID
app.get('/api/bookings/:id', authMiddleware, asyncHandler(async (req, res) => {
  const booking = await Booking.findById(req.params.id)
    .populate('products.productId', 'title imageUrl price')
    .populate('buyerId', 'name email');

  if (!booking) {
    return res.status(404).json({ message: 'Booking not found.' });
  }

  res.json(booking);
}));

// ✅ Cancel Booking Route (fixed)
app.put('/api/bookings/:id/cancel', authMiddleware, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id)
    .populate('buyerId', 'name email')
    .populate('products.productId', 'title price sellerId');

    if (!booking) {
      return res.status(404).json({ message: 'Booking not found.' });
    }

    // ✅ Ensure only the booking owner can cancel
    if (booking.buyerId._id.toString() !== req.userId.toString()) {
      return res.status(403).json({ message: 'Not authorized to cancel this booking.' });
    }

    // ✅ Prevent cancelling already cancelled or delivered bookings
    if (['Cancelled', 'Delivered'].includes(booking.status)) {
      return res.status(400).json({ message: `Cannot cancel a ${booking.status.toLowerCase()} booking.` });
    }

    booking.status = 'Cancelled';
    await booking.save();

    // 🟢 Mark all related products as available again
    const productIds = booking.products.map(p => p.productId);
    await Product.updateMany(
      { _id: { $in: productIds } },
      { $set: { isBooked: false } }
    );

    // ✅ Get seller info
  const sellerIds = booking.products.map(p => p.productId.sellerId);
  const sellers = await User.find({ _id: { $in: sellerIds } }, 'name email');

  // ✅ Setup mail transporter
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: Number(process.env.EMAIL_PORT) || 587,
    secure: process.env.EMAIL_SECURE === 'true',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  });

  // ✅ Email content
  const buyerMail = {
    from: process.env.EMAIL_FROM,
    to: booking.buyerId.email,
    subject: 'Booking Cancelled - RebuZZar',
    html: `
      <h2>Booking Cancelled</h2>
      <p>Hi ${booking.buyerId.name},</p>
      <p>Your booking for the following items has been cancelled:</p>
      <ul>
        ${booking.products.map(p => `<li>${p.productId.title} - ₹${p.productId.price}</li>`).join('')}
      </ul>
      <p>If this wasn’t you, please contact RebuZZar Support.</p>
    `,
  };

  // Send mail to each seller
  for (const seller of sellers) {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: seller.email,
      subject: 'Item Booking Cancelled - RebuZZar',
      html: `
        <h2>Your Item Has Been Cancelled</h2>
        <p>Hi ${seller.name},</p>
        <p>The following item(s) booked from your listing have been cancelled by the buyer:</p>
        <ul>
          ${booking.products.map(p => `<li>${p.productId.title} - ₹${p.productId.price}</li>`).join('')}
        </ul>
        <p>You will be notified later about the next steps for pickup rescheduling.</p>
      `,
    });
  }

  // ✅ Notify admin
  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: process.env.ADMIN_EMAIL,
    subject: 'Booking Cancelled - RebuZZar Admin Notice',
    html: `
      <h2>Booking Cancelled</h2>
      <p><strong>Buyer:</strong> ${booking.buyerId.name} (${booking.buyerId.email})</p>
      <p><strong>Items:</strong></p>
      <ul>
        ${booking.products.map(p => `<li>${p.productId.title} - ₹${p.productId.price}</li>`).join('')}
      </ul>
    `,
  });

    res.status(200).json({
      message: 'Booking cancelled successfully. Product(s) are now available again.',
      booking
    });

  } catch (err) {
    console.error('Cancel Booking Error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ----------------------------
// CART ROUTES
// ----------------------------
app.get('/api/cart', authMiddleware, asyncHandler(async (req, res) => {
  let cart = await Cart.findOne({ userId: req.userId });
  if (!cart) {
    cart = new Cart({ userId: req.userId, items: [] });
    await cart.save();
  }
  res.json(cart);
}));

app.post('/api/cart/add', authMiddleware, asyncHandler(async (req, res) => {
  const { productId, quantity = 1 } = req.body;

  if (!productId || !validator.isMongoId(String(productId)))
    return res.status(400).json({ message: 'Valid productId is required.' });

  const qty = parseInt(quantity, 10) || 1;
  if (qty < 1) return res.status(400).json({ message: 'Quantity must be at least 1.' });

  const product = await Product.findById(productId);
  if (!product) return res.status(404).json({ message: 'Product not found.' });
  if (product.status !== 'approved') return res.status(400).json({ message: 'Product is not available for purchase.' });

  let cart = await Cart.findOne({ userId: req.userId });
  if (!cart) {
    cart = new Cart({ userId: req.userId, items: [] });
  }

  const existingIndex = cart.items.findIndex(item => item.productId.toString() === product._id.toString());
  if (existingIndex > -1) {
    // Update quantity
    cart.items[existingIndex].quantity += qty;
    // Also update snapshot fields in case you want to refresh title/price/img (optional)
    cart.items[existingIndex].price = product.price;
    cart.items[existingIndex].title = product.title;
    cart.items[existingIndex].imageUrl = product.imageUrl || [];
    cart.items[existingIndex].sellerId = product.sellerId;
  } else {
    // Push a snapshot of the product
    cart.items.push({
      productId: product._id,
      title: product.title,
      price: product.price,
      imageUrl: product.imageUrl || [],
      quantity: qty,
      sellerId: product.sellerId
    });
  }

  await cart.save();
  res.status(200).json({ message: 'Product added to cart successfully.', cart });
}));

app.put('/api/cart/item/:productId', authMiddleware, asyncHandler(async (req, res) => {
  const { productId } = req.params;
  const { quantity } = req.body;

  if (!validator.isMongoId(productId)) return res.status(400).json({ message: 'Invalid productId.' });

  const qty = parseInt(quantity, 10);
  if (isNaN(qty)) return res.status(400).json({ message: 'Quantity must be a number.' });

  const cart = await Cart.findOne({ userId: req.userId });
  if (!cart) return res.status(404).json({ message: 'Cart not found.' });

  const itemIndex = cart.items.findIndex(i => i.productId.toString() === productId.toString());
  if (itemIndex === -1) return res.status(404).json({ message: 'Item not found in cart.' });

  if (qty <= 0) {
    // remove item
    cart.items.splice(itemIndex, 1);
  } else {
    cart.items[itemIndex].quantity = qty;
  }

  await cart.save();
  res.json({ message: 'Cart updated successfully.', cart });
}));

app.delete('/api/cart/item/:productId', authMiddleware, asyncHandler(async (req, res) => {
  const { productId } = req.params;
  if (!validator.isMongoId(productId)) return res.status(400).json({ message: 'Invalid productId.' });

  const cart = await Cart.findOne({ userId: req.userId });
  if (!cart) return res.status(404).json({ message: 'Cart not found.' });

  const prevLen = cart.items.length;
  cart.items = cart.items.filter(i => i.productId.toString() !== productId.toString());
  if (cart.items.length === prevLen) return res.status(404).json({ message: 'Item not found in cart.' });

  await cart.save();
  res.json({ message: 'Item removed from cart.', cart });
}));

app.post('/api/cart/clear', authMiddleware, asyncHandler(async (req, res) => {
  const cart = await Cart.findOne({ userId: req.userId });
  if (!cart) return res.status(404).json({ message: 'Cart not found.' });

  cart.items = [];
  await cart.save();
  res.json({ message: 'Cart cleared successfully.', cart });
}));

// ----------------------------
// CENTRALIZED ERROR HANDLER
// ----------------------------
app.use((err, req, res, next) => {
  logError('Unhandled Error', err);
  const status = err.statusCode || 500;
  res.status(status).json({ message: err.message || 'Internal Server Error' });
});

// ----------------------------
// START SERVER
// ----------------------------
app.listen(port, () => {
  console.log(`✅ Backend server is running on http://localhost:${port}`);
});
