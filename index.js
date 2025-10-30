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
  imageUrl: { type: [String], required: true },
  category: { type: String, required: true },
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  postDate: { type: Date, default: Date.now },
}, { timestamps: true });

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
// NEW: CART SCHEMA & MODEL
// ========================

/**
 * CartItem stores a snapshot of the product at the time it was added to cart.
 * This protects the user from price edits after adding to cart and makes checkout easier.
 */
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

// ========================
// MULTER + CLOUDINARY STORAGE CONFIG
// ========================

// Cloudinary storage using multer-storage-cloudinary
const cloudinaryStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: process.env.CLOUDINARY_FOLDER || 'bw-market',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 1200, crop: 'limit' }],
  },
});

// multer using cloudinary storage
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
    next(err); 
  }
};

// ========================
// ROUTES
// ========================

// Helper to wrap async route functions
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// --- PROFILE ROUTES ---
app.post('/api/profile/avatar', authMiddleware, upload.single('avatar'), asyncHandler(async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'Avatar image file is required.' });

  const avatarUrl = req.file.path || req.file?.location || req.file?.secure_url || req.file?.url;
  if (!avatarUrl) return res.status(500).json({ message: 'Failed to retrieve uploaded avatar URL.' });

  const updatedUser = await User.findByIdAndUpdate(req.userId, { avatar: avatarUrl }, { new: true }).select('-password');
  if (!updatedUser) return res.status(404).json({ message: 'User not found.' });

  res.json(updatedUser);
}));

// Updated Edit Profile Route
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
    from: process.env.EMAIL_FROM || '"Support" <no-reply@rebuzzar.com>',
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
// BOOKING ROUTES
// ========================
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

  // Here you can later add logic to notify sellers via email
  // For now, we just confirm the booking was created

  res.status(201).json({ message: 'Booking successful!', booking: newBooking });
}));

app.post('/api/bookings/create', authMiddleware, asyncHandler(async (req, res) => {
    // ... your existing create booking code
}));

// ✅ ADD THIS ROUTE: Get bookings for the logged-in user
app.get('/api/bookings/my-bookings', authMiddleware, asyncHandler(async (req, res) => {
    const bookings = await Booking.find({ buyerId: req.userId })
        .populate('products.productId', 'title imageUrl') // Get product details
        .sort({ bookingDate: -1 }); // Show newest first

    if (!bookings) {
        return res.status(404).json({ message: 'No bookings found.' });
    }
    res.json(bookings);
}));

// ========================
// NEW: CART ROUTES
// ========================
// Get or create cart for user
app.get('/api/cart', authMiddleware, asyncHandler(async (req, res) => {
  let cart = await Cart.findOne({ userId: req.userId });
  if (!cart) {
    cart = new Cart({ userId: req.userId, items: [] });
    await cart.save();
  }
  res.json(cart);
}));

// Add item to cart (snapshot style)
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

// Update item quantity in cart or remove if quantity <= 0
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

// Remove item from cart
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

// Clear entire cart
app.post('/api/cart/clear', authMiddleware, asyncHandler(async (req, res) => {
  const cart = await Cart.findOne({ userId: req.userId });
  if (!cart) return res.status(404).json({ message: 'Cart not found.' });

  cart.items = [];
  await cart.save();
  res.json({ message: 'Cart cleared successfully.', cart });
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
