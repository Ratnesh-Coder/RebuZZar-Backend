// // ========================
// // BACKEND SERVER SETUP
// // ========================

// // --- IMPORTS ---
// const express = require('express');
// const cors = require('cors');
// const multer = require('multer');
// const path = require('path');
// const mongoose = require('mongoose');
// const bcrypt = require('bcryptjs');
// const crypto = require('crypto');
// const nodemailer = require('nodemailer');
// const rateLimit = require('express-rate-limit'); // Rate limiting
// const helmet = require('helmet'); // Security headers
// const mongoSanitize = require('express-mongo-sanitize'); // Sanitize input
// const validator = require('validator'); // Simple validation helpers
// require('dotenv').config();

// // --- APP CONFIG ---
// const app = express();
// const port = process.env.PORT || 5000;

// // ========================
// // MIDDLEWARE
// // ========================
// app.use(helmet()); // Add secure headers
// app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
// app.use(express.json({ limit: '10kb' })); // Protect against large JSON
// app.use((req, res, next) => {
//   // Sanitize query params to prevent NoSQL injection
//   req.query = { ...req.query };
//   mongoSanitize.sanitize(req.query);
//   next();
// });

// // --- RATE LIMITERS ---
// const authLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 10,
//   message: { message: 'Too many requests from this IP, try again later.' }
// });

// // ========================
// // DATABASE CONNECTION
// // ========================
// mongoose.connect(process.env.MONGO_URI, {
//   useNewUrlParser: true,
//   useUnifiedTopology: true,
// })
//   .then(() => console.log('✅ MongoDB Connected Successfully'))
//   .catch(err => {
//     console.error('❌ MongoDB Connection Error:', err);
//     process.exit(1);
//   });

// // ========================
// // SCHEMAS & MODELS
// // ========================

// // --- USER SCHEMA ---
// const UserSchema = new mongoose.Schema({
//   name: { type: String, required: true },
//   email: { type: String, required: true, unique: true, lowercase: true, trim: true },
//   password: { type: String, required: true },
//   avatar: { type: String, default: 'https://via.placeholder.com/150' },
//   joinDate: { type: Date, default: Date.now },
//   department: { type: String },
//   programName: { type: String },
//   section: { type: String },
//   rollNumber: { type: String },
//   studentCode: { type: String },
//   registrationNumber: { type: String },
//   resetPasswordToken: { type: String },
//   resetPasswordExpires: { type: Date },
//   role: { type: String, enum: ['student', 'admin'], default: 'student' },
// }, { timestamps: true });

// const User = mongoose.model('User', UserSchema);

// // --- PRODUCT SCHEMA ---
// const ProductSchema = new mongoose.Schema({
//   title: { type: String, required: true },
//   price: { type: Number, required: true },
//   description: { type: String, required: true },
//   imageUrl: { type: String, required: true },
//   category: { type: String, required: true },
//   sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
//   status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
//   postDate: { type: Date, default: Date.now },
// }, { timestamps: true });

// // Cascade delete: remove products when a user is deleted
// UserSchema.pre('findOneAndDelete', async function(next) {
//   try {
//     const user = await this.model.findOne(this.getFilter());
//     if (user) await Product.deleteMany({ sellerId: user._id });
//     next();
//   } catch (err) {
//     next(err);
//   }
// });

// const Product = mongoose.model('Product', ProductSchema);

// // ========================
// // MULTER CONFIGURATION (FILE UPLOAD)
// // ========================
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => cb(null, 'uploads/'),
//   filename: (req, file, cb) => cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`)
// });

// const fileFilter = (req, file, cb) => {
//   const allowed = /jpeg|jpg|png|webp/;
//   const ext = path.extname(file.originalname).toLowerCase();
//   if (allowed.test(ext)) cb(null, true);
//   else cb(new Error('Only image files are allowed (jpeg, jpg, png, webp).'), false);
// };

// const upload = multer({
//   storage,
//   limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
//   fileFilter
// });

// // ========================
// // AUTH & ROLE MIDDLEWARE
// // ========================

// // --- AUTHENTICATION MIDDLEWARE ---
// const authMiddleware = async (req, res, next) => {
//   try {
//     const authHeader = req.headers['authorization'];
//     if (!authHeader) return res.status(401).json({ message: 'Authorization token required.' });

//     const parts = authHeader.split(' ');
//     if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ message: 'Token format: "Bearer TOKEN"' });

//     const token = parts[1];
//     if (!validator.isMongoId(token)) return res.status(401).json({ message: 'Invalid token format.' });

//     const user = await User.findById(token);
//     if (!user) return res.status(403).json({ message: 'Invalid or unknown user token.' });

//     req.userId = user._id;
//     next();
//   } catch (err) {
//     console.error('Auth middleware error:', err);
//     res.status(500).json({ message: 'Internal Server Error during authentication.' });
//   }
// };

// // --- ADMIN ROLE MIDDLEWARE ---
// const adminMiddleware = async (req, res, next) => {
//   try {
//     const user = await User.findById(req.userId);
//     if (!user || user.role !== 'admin') return res.status(403).json({ message: 'Access denied: Admins only.' });
//     next();
//   } catch (err) {
//     console.error('Admin middleware error:', err);
//     res.status(500).json({ message: 'Internal Server Error' });
//   }
// };

// // ========================
// // ROUTES
// // ========================

// // --- SERVE UPLOADS ---
// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// // --- PROFILE ROUTES ---
// app.post('/api/profile/avatar', authMiddleware, upload.single('avatar'), async (req, res) => {
//   try {
//     if (!req.file) return res.status(400).json({ message: 'Avatar image file is required.' });

//     const avatarUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;

//     const updatedUser = await User.findByIdAndUpdate(req.userId, { avatar: avatarUrl }, { new: true }).select('-password');
//     if (!updatedUser) return res.status(404).json({ message: 'User not found.' });

//     res.json(updatedUser);
//   } catch (error) {
//     console.error("Error uploading avatar:", error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.put('/api/profile', authMiddleware, async (req, res) => {
//   try {
//     const { email, password, ...allowedUpdates } = req.body;
//     const updatedUser = await User.findByIdAndUpdate(req.userId, { $set: allowedUpdates }, { new: true, runValidators: true }).select('-password');
//     if (!updatedUser) return res.status(404).json({ message: 'User not found.' });
//     res.json(updatedUser);
//   } catch (error) {
//     console.error('PUT /api/profile error:', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // --- PRODUCT ROUTES ---

// // Get all approved products (optional filters)
// app.get('/api/products', async (req, res) => {
//   try {
//     const { category, search } = req.query;
//     const filter = { status: 'approved' };
//     if (category) filter.category = { $regex: new RegExp(`^${category}$`, 'i') };
//     if (search) filter.title = { $regex: search, $options: 'i' };

//     const products = await Product.find(filter);
//     res.json(products);
//   } catch (error) {
//     console.error('GET /api/products error:', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // Get single product
// app.get('/api/products/:id', async (req, res) => {
//   try {
//     const product = await Product.findById(req.params.id);
//     if (!product) return res.status(404).json({ message: 'Product not found' });
//     res.json(product);
//   } catch (error) {
//     console.error('GET /api/products/:id error:', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // Get products of logged-in user
// app.get('/api/profile/products', authMiddleware, async (req, res) => {
//   try {
//     const userProducts = await Product.find({ sellerId: req.userId });
//     res.json(userProducts);
//   } catch (error) {
//     console.error("Error fetching user products:", error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // Create product (status defaults to 'pending')
// app.post('/api/products', authMiddleware, upload.single('image'), async (req, res) => {
//   try {
//     const { title, price, description, category } = req.body;
//     if (!req.file || !title || !price || !description || !category) return res.status(400).json({ message: 'All fields, including image, are required.' });

//     const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
//     const newProduct = new Product({ title, price: Number(price), description, category, imageUrl, sellerId: req.userId });
//     await newProduct.save();
//     res.status(201).json(newProduct);
//   } catch (error) {
//     console.error('POST /api/products error:', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // Update product (only owner)
// app.put('/api/products/:id', authMiddleware, async (req, res) => {
//   try {
//     const { title, price, description, category } = req.body;
//     const product = await Product.findById(req.params.id);
//     if (!product) return res.status(404).json({ message: 'Product not found.' });
//     if (product.sellerId.toString() !== req.userId.toString()) return res.status(403).json({ message: 'User not authorized to edit this product.' });

//     product.title = title;
//     product.price = price;
//     product.description = description;
//     product.category = category;

//     const updatedProduct = await product.save();
//     res.json(updatedProduct);
//   } catch (error) {
//     console.error('PUT /api/products/:id error:', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // Delete product (only owner)
// app.delete('/api/products/:id', authMiddleware, async (req, res) => {
//   try {
//     const product = await Product.findById(req.params.id);
//     if (!product) return res.status(404).json({ message: 'Product not found.' });
//     if (product.sellerId.toString() !== req.userId.toString()) return res.status(403).json({ message: 'User not authorized to delete this product.' });

//     await Product.findByIdAndDelete(req.params.id);
//     res.json({ message: 'Product deleted successfully.' });
//   } catch (error) {
//     console.error('DELETE /api/products/:id error:', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // --- ADMIN ROUTES ---
// // Get all pending products
// app.get('/api/admin/products/pending', authMiddleware, adminMiddleware, async (req, res) => {
//   try {
//     const pendingProducts = await Product.find({ status: 'pending' }).populate('sellerId', 'name email');
//     res.json(pendingProducts);
//   } catch (error) {
//     console.error('GET /api/admin/products/pending error:', error);
//     res.status(500).json({ message: 'Internal Server Error' });
//   }
// });

// // Approve/Reject product
// app.put('/api/admin/products/:id/status', authMiddleware, adminMiddleware, async (req, res) => {
//   try {
//     const { status } = req.body;
//     if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ message: 'Invalid status.' });

//     const product = await Product.findById(req.params.id);
//     if (!product) return res.status(404).json({ message: 'Product not found.' });

//     product.status = status;
//     await product.save();

//     res.json({ message: `Product ${status} successfully.`, product });
//   } catch (error) {
//     console.error('PUT /api/admin/products/:id/status error:', error);
//     res.status(500).json({ message: 'Internal Server Error' });
//   }
// });

// // ========================
// // AUTH ROUTES
// // ========================

// // --- SIGNUP ---
// app.post('/api/auth/signup', async (req, res) => {
//   try {
//     const { name, email, password, department, programName, section, rollNumber, studentCode, registrationNumber } = req.body;

//     const universityDomain = process.env.UNIVERSITY_DOMAIN || '@brainwareuniversity.ac.in';
//     if (!email || !validator.isEmail(email) || !email.endsWith(universityDomain)) {
//       return res.status(400).json({ message: `Email must end with ${universityDomain}` });
//     }

//     if (!name || !password) return res.status(400).json({ message: 'All required fields are required.' });

//     const existingUser = await User.findOne({ email });
//     if (existingUser) return res.status(409).json({ message: 'Account with this email already exists.' });

//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);

//     const newUser = new User({ name, email, password: hashedPassword, department, programName, section, rollNumber, studentCode, registrationNumber });
//     await newUser.save();

//     const { password: _, ...userToSend } = newUser.toObject();
//     res.status(201).json({ message: 'User created successfully!', user: userToSend, token: userToSend._id });
//   } catch (error) {
//     console.error("Signup Error:", error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // --- LOGIN ---
// app.post('/api/auth/login', async (req, res) => {
//   try {
//     const { email, password } = req.body;
//     if (!email || !password) return res.status(400).json({ message: 'Email and password required.' });

//     const user = await User.findOne({ email });
//     if (!user) return res.status(401).json({ message: 'Invalid email or password' });

//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) return res.status(401).json({ message: 'Invalid email or password' });

//     const { password: _, ...userToSend } = user.toObject();
//     res.json({ message: "Login successful!", user: userToSend, token: userToSend._id });
//   } catch (error) {
//     console.error('Login error:', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // ========================
// // PASSWORD RESET ROUTES
// // ========================

// // --- FORGOT PASSWORD ---
// app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
//   try {
//     const { email } = req.body;
//     if (!email || !validator.isEmail(email)) return res.json({ message: 'If an account exists, a password reset link has been sent.' });

//     const user = await User.findOne({ email });
//     if (!user) return res.json({ message: 'If an account exists, a password reset link has been sent.' });

//     const rawToken = crypto.randomBytes(32).toString('hex');
//     const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

//     user.resetPasswordToken = hashedToken;
//     user.resetPasswordExpires = Date.now() + 1000 * 60 * 60; // 1 hour
//     await user.save();

//     const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
//     const resetLink = `${FRONTEND_URL}/reset-password/${rawToken}`;

//     const mailPort = Number(process.env.EMAIL_PORT) || 587;
//     const transporter = nodemailer.createTransport({
//       host: process.env.EMAIL_HOST,
//       port: mailPort,
//       secure: process.env.EMAIL_SECURE === 'true' || mailPort === 465,
//       auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
//     });

//     const html = `
//       <html>
//         <body style="font-family: Arial, sans-serif;">
//           <h2>Password Reset Request</h2>
//           <p><a href="${resetLink}">Click here to reset your password</a></p>
//           <p>Expires in 1 hour.</p>
//         </body>
//       </html>`;

//     await transporter.sendMail({
//       from: process.env.EMAIL_FROM || '"Support" <no-reply@campuskart.com>',
//       to: `${user.name} <${user.email}>`,
//       subject: 'Password Reset Link',
//       text: `Reset password: ${resetLink}`,
//       html
//     });

//     res.json({ message: 'If an account exists, a password reset link has been sent.' });
//   } catch (error) {
//     console.error("Forgot Password Error:", error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // --- RESET PASSWORD ---
// app.post('/api/auth/reset-password/:token', async (req, res) => {
//   try {
//     const { token } = req.params;
//     const { password } = req.body;

//     if (!password || password.length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters long.' });

//     const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
//     const user = await User.findOne({ resetPasswordToken: hashedToken, resetPasswordExpires: { $gt: Date.now() } });
//     if (!user) return res.status(400).json({ message: 'Token invalid or expired.' });

//     const salt = await bcrypt.genSalt(10);
//     user.password = await bcrypt.hash(password, salt);
//     user.resetPasswordToken = undefined;
//     user.resetPasswordExpires = undefined;
//     await user.save();

//     res.json({ message: 'Password updated successfully.' });
//   } catch (error) {
//     console.error('Reset password error:', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // ========================
// // START SERVER
// // ========================
// app.listen(port, () => {
//   console.log(`✅ Backend server is running on http://localhost:${port}`);
// });





// // ========================
// // BACKEND SERVER SETUP
// // ========================

// // --- IMPORTS ---
// const express = require('express');
// const cors = require('cors');
// const multer = require('multer');
// const path = require('path');
// const mongoose = require('mongoose');
// const bcrypt = require('bcryptjs');
// const crypto = require('crypto');
// const nodemailer = require('nodemailer');
// const rateLimit = require('express-rate-limit');
// const helmet = require('helmet');
// const mongoSanitize = require('express-mongo-sanitize');
// const validator = require('validator');
// require('dotenv').config();

// // --- APP CONFIG ---
// const app = express();
// const port = process.env.PORT || 5000;

// // ========================
// // UTILITY: SAFE LOGGER
// // ========================
// const logError = (context, error) => {
//   if (process.env.NODE_ENV === 'development') {
//     console.error(`❌ ${context}:`, error);
//   } else {
//     console.error(`❌ ${context}:`, error.message);
//   }
// };

// // ========================
// // MIDDLEWARE
// // ========================
// app.use(helmet());
// app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
// app.use(express.json({ limit: '10kb' }));
// app.use((req, res, next) => {
//   req.query = { ...req.query };
//   mongoSanitize.sanitize(req.query);
//   next();
// });

// const authLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: 10,
//   message: { message: 'Too many requests from this IP, try again later.' }
// });

// // ========================
// // DATABASE CONNECTION
// // ========================
// mongoose.connect(process.env.MONGO_URI, {
//   useNewUrlParser: true,
//   useUnifiedTopology: true,
// })
//   .then(() => console.log('✅ MongoDB Connected Successfully'))
//   .catch(err => {
//     logError('❌ MongoDB Connection Error', err);
//     process.exit(1);
//   });

// // ========================
// // SCHEMAS & MODELS
// // ========================
// const UserSchema = new mongoose.Schema({
//   name: { type: String, required: true },
//   email: { type: String, required: true, unique: true, lowercase: true, trim: true },
//   password: { type: String, required: true },
//   avatar: { type: String, default: 'https://via.placeholder.com/150' },
//   joinDate: { type: Date, default: Date.now },
//   department: { type: String },
//   programName: { type: String },
//   section: { type: String },
//   rollNumber: { type: String },
//   studentCode: { type: String },
//   registrationNumber: { type: String },
//   resetPasswordToken: { type: String },
//   resetPasswordExpires: { type: Date },
//   role: { type: String, enum: ['student', 'admin'], default: 'student' },
// }, { timestamps: true });

// const User = mongoose.model('User', UserSchema);

// const ProductSchema = new mongoose.Schema({
//   title: { type: String, required: true },
//   price: { type: Number, required: true },
//   description: { type: String, required: true },
//   imageUrl: { type: String, required: true },
//   category: { type: String, required: true },
//   sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
//   status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
//   postDate: { type: Date, default: Date.now },
// }, { timestamps: true });

// // Cascade delete
// UserSchema.pre('findOneAndDelete', async function (next) {
//   try {
//     const user = await this.model.findOne(this.getFilter());
//     if (user) await Product.deleteMany({ sellerId: user._id });
//     next();
//   } catch (err) {
//     next(err);
//   }
// });

// const Product = mongoose.model('Product', ProductSchema);

// // ========================
// // MULTER CONFIG
// // ========================
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => cb(null, 'uploads/'),
//   filename: (req, file, cb) => cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`)
// });

// const fileFilter = (req, file, cb) => {
//   const allowed = /jpeg|jpg|png|webp/;
//   const ext = path.extname(file.originalname).toLowerCase();
//   if (allowed.test(ext)) cb(null, true);
//   else cb(new Error('Only image files are allowed (jpeg, jpg, png, webp).'), false);
// };

// const upload = multer({
//   storage,
//   limits: { fileSize: 2 * 1024 * 1024 },
//   fileFilter
// });

// // ========================
// // AUTH & ROLE MIDDLEWARE
// // ========================
// const authMiddleware = async (req, res, next) => {
//   try {
//     const authHeader = req.headers['authorization'];
//     if (!authHeader) return res.status(401).json({ message: 'Authorization token required.' });

//     const parts = authHeader.split(' ');
//     if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ message: 'Token format: "Bearer TOKEN"' });

//     const token = parts[1];
//     if (!validator.isMongoId(token)) return res.status(401).json({ message: 'Invalid token format.' });

//     const user = await User.findById(token);
//     if (!user) return res.status(403).json({ message: 'Invalid or unknown user token.' });

//     req.userId = user._id;
//     next();
//   } catch (err) {
//     logError('Auth middleware error', err);
//     res.status(500).json({ message: 'Internal Server Error during authentication.' });
//   }
// };

// const adminMiddleware = async (req, res, next) => {
//   try {
//     const user = await User.findById(req.userId);
//     if (!user || user.role !== 'admin') return res.status(403).json({ message: 'Access denied: Admins only.' });
//     next();
//   } catch (err) {
//     logError('Admin middleware error', err);
//     res.status(500).json({ message: 'Internal Server Error' });
//   }
// };

// // ========================
// // ROUTES
// // ========================
// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// // --- PROFILE ROUTES ---
// app.post('/api/profile/avatar', authMiddleware, upload.single('avatar'), async (req, res) => {
//   try {
//     if (!req.file) return res.status(400).json({ message: 'Avatar image file is required.' });

//     const avatarUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
//     const updatedUser = await User.findByIdAndUpdate(req.userId, { avatar: avatarUrl }, { new: true }).select('-password');
//     if (!updatedUser) return res.status(404).json({ message: 'User not found.' });

//     res.json(updatedUser);
//   } catch (error) {
//     logError('Error uploading avatar', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.put('/api/profile', authMiddleware, async (req, res) => {
//   try {
//     const { email, password, ...allowedUpdates } = req.body;
//     const updatedUser = await User.findByIdAndUpdate(req.userId, { $set: allowedUpdates }, { new: true, runValidators: true }).select('-password');
//     if (!updatedUser) return res.status(404).json({ message: 'User not found.' });
//     res.json(updatedUser);
//   } catch (error) {
//     logError('PUT /api/profile error', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // --- PRODUCT ROUTES ---
// app.get('/api/products', async (req, res) => {
//   try {
//     const { category, search } = req.query;
//     const filter = { status: 'approved' };
//     if (category) filter.category = { $regex: new RegExp(`^${category}$`, 'i') };
//     if (search) filter.title = { $regex: search, $options: 'i' };

//     const products = await Product.find(filter);
//     res.json(products);
//   } catch (error) {
//     logError('GET /api/products error', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.get('/api/products/:id', async (req, res) => {
//   try {
//     const product = await Product.findById(req.params.id);
//     if (!product) return res.status(404).json({ message: 'Product not found' });
//     res.json(product);
//   } catch (error) {
//     logError('GET /api/products/:id error', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.get('/api/profile/products', authMiddleware, async (req, res) => {
//   try {
//     const userProducts = await Product.find({ sellerId: req.userId });
//     res.json(userProducts);
//   } catch (error) {
//     logError('Error fetching user products', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.post('/api/products', authMiddleware, upload.single('image'), async (req, res) => {
//   try {
//     const { title, price, description, category } = req.body;
//     if (!req.file || !title || !price || !description || !category)
//       return res.status(400).json({ message: 'All fields, including image, are required.' });

//     const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
//     const newProduct = new Product({ title, price: Number(price), description, category, imageUrl, sellerId: req.userId });
//     await newProduct.save();
//     res.status(201).json(newProduct);
//   } catch (error) {
//     logError('POST /api/products error', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.put('/api/products/:id', authMiddleware, async (req, res) => {
//   try {
//     const { title, price, description, category } = req.body;
//     const product = await Product.findById(req.params.id);
//     if (!product) return res.status(404).json({ message: 'Product not found.' });
//     if (product.sellerId.toString() !== req.userId.toString())
//       return res.status(403).json({ message: 'User not authorized to edit this product.' });

//     product.title = title;
//     product.price = price;
//     product.description = description;
//     product.category = category;

//     const updatedProduct = await product.save();
//     res.json(updatedProduct);
//   } catch (error) {
//     logError('PUT /api/products/:id error', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.delete('/api/products/:id', authMiddleware, async (req, res) => {
//   try {
//     const product = await Product.findById(req.params.id);
//     if (!product) return res.status(404).json({ message: 'Product not found.' });
//     if (product.sellerId.toString() !== req.userId.toString())
//       return res.status(403).json({ message: 'User not authorized to delete this product.' });

//     await Product.findByIdAndDelete(req.params.id);
//     res.json({ message: 'Product deleted successfully.' });
//   } catch (error) {
//     logError('DELETE /api/products/:id error', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // --- ADMIN ROUTES ---
// app.get('/api/admin/products/pending', authMiddleware, adminMiddleware, async (req, res) => {
//   try {
//     const pendingProducts = await Product.find({ status: 'pending' }).populate('sellerId', 'name email');
//     res.json(pendingProducts);
//   } catch (error) {
//     logError('GET /api/admin/products/pending error', error);
//     res.status(500).json({ message: 'Internal Server Error' });
//   }
// });

// app.put('/api/admin/products/:id/status', authMiddleware, adminMiddleware, async (req, res) => {
//   try {
//     const { status } = req.body;
//     if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ message: 'Invalid status.' });

//     const product = await Product.findById(req.params.id);
//     if (!product) return res.status(404).json({ message: 'Product not found.' });

//     product.status = status;
//     await product.save();

//     res.json({ message: `Product ${status} successfully.`, product });
//   } catch (error) {
//     logError('PUT /api/admin/products/:id/status error', error);
//     res.status(500).json({ message: 'Internal Server Error' });
//   }
// });

// // --- AUTH ROUTES ---
// app.post('/api/auth/signup', async (req, res) => {
//   try {
//     const { name, email, password, department, programName, section, rollNumber, studentCode, registrationNumber } = req.body;

//     const universityDomain = process.env.UNIVERSITY_DOMAIN || '@brainwareuniversity.ac.in';
//     if (!email || !validator.isEmail(email) || !email.endsWith(universityDomain)) {
//       return res.status(400).json({ message: `Email must end with ${universityDomain}` });
//     }

//     if (!name || !password) return res.status(400).json({ message: 'All required fields are required.' });

//     const existingUser = await User.findOne({ email });
//     if (existingUser) return res.status(409).json({ message: 'Account with this email already exists.' });

//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);

//     const newUser = new User({ name, email, password: hashedPassword, department, programName, section, rollNumber, studentCode, registrationNumber });
//     await newUser.save();

//     const { password: _, ...userToSend } = newUser.toObject();
//     res.status(201).json({ message: 'User created successfully!', user: userToSend, token: userToSend._id });
//   } catch (error) {
//     logError('Signup Error', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.post('/api/auth/login', async (req, res) => {
//   try {
//     const { email, password } = req.body;
//     if (!email || !password) return res.status(400).json({ message: 'Email and password required.' });

//     const user = await User.findOne({ email });
//     if (!user) return res.status(401).json({ message: 'Invalid email or password' });

//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) return res.status(401).json({ message: 'Invalid email or password' });

//     const { password: _, ...userToSend } = user.toObject();
//     res.json({ message: "Login successful!", user: userToSend, token: userToSend._id });
//   } catch (error) {
//     logError('Login Error', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // --- PASSWORD RESET ---
// app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
//   try {
//     const { email } = req.body;
//     if (!email || !validator.isEmail(email)) return res.json({ message: 'If an account exists, a password reset link has been sent.' });

//     const user = await User.findOne({ email });
//     if (!user) return res.json({ message: 'If an account exists, a password reset link has been sent.' });

//     const rawToken = crypto.randomBytes(32).toString('hex');
//     const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

//     user.resetPasswordToken = hashedToken;
//     user.resetPasswordExpires = Date.now() + 1000 * 60 * 60;
//     await user.save();

//     const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
//     const resetLink = `${FRONTEND_URL}/reset-password/${rawToken}`;

//     const mailPort = Number(process.env.EMAIL_PORT) || 587;
//     const transporter = nodemailer.createTransport({
//       host: process.env.EMAIL_HOST,
//       port: mailPort,
//       secure: process.env.EMAIL_SECURE === 'true' || mailPort === 465,
//       auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
//     });

//     const tml = `
//       <html>
//         <body style="font-family: Arial, sans-serif;">
//           <h2>Password Reset Request</h2>
//           <p><a href="${resetLink}">Click here to reset your password</a></p>
//           <p>Expires in 1 hour.</p>
//         </body>
//       </html>`;

//     await transporter.sendMail({
//       from: process.env.EMAIL_FROM || '"Support" <no-reply@campuskart.com>',
//       to: `${user.name} <${user.email}>`,
//       subject: 'Password Reset Link',
//       texth: `Reset password: ${resetLink}`,
//       html
//     });

//     res.json({ message: 'If an account exists, a password reset link has been sent.' });
//   } catch (error) {
//     logError('Forgot Password Error', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.post('/api/auth/reset-password/:token', async (req, res) => {
//   try {
//     const { token } = req.params;
//     const { password } = req.body;

//     if (!password || password.length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters long.' });

//     const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
//     const user = await User.findOne({ resetPasswordToken: hashedToken, resetPasswordExpires: { $gt: Date.now() } });
//     if (!user) return res.status(400).json({ message: 'Token invalid or expired.' });

//     const salt = await bcrypt.genSalt(10);
//     user.password = await bcrypt.hash(password, salt);
//     user.resetPasswordToken = undefined;
//     user.resetPasswordExpires = undefined;
//     await user.save();

//     res.json({ message: 'Password updated successfully.' });
//   } catch (error) {
//     logError('Reset Password Error', error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // ========================
// // START SERVER
// // ========================
// app.listen(port, () => {
//   console.log(`✅ Backend server is running on http://localhost:${port}`);
// });


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
    console.error(`❌ ${context}:`, error.message);
  }
};

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
  studentCode: { type: String, required: true }, // optional
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
// MULTER CONFIG
// ========================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`)
});

const fileFilter = (req, file, cb) => {
  const allowed = /jpeg|jpg|png|webp/;
  const ext = path.extname(file.originalname).toLowerCase();
  if (allowed.test(ext)) cb(null, true);
  else cb(new Error('Only image files are allowed (jpeg, jpg, png, webp).'), false);
};

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter
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
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Helper to wrap async route functions
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// --- PROFILE ROUTES ---
app.post('/api/profile/avatar', authMiddleware, upload.single('avatar'), asyncHandler(async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'Avatar image file is required.' });

  const avatarUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  const updatedUser = await User.findByIdAndUpdate(req.userId, { avatar: avatarUrl }, { new: true }).select('-password');
  if (!updatedUser) return res.status(404).json({ message: 'User not found.' });

  res.json(updatedUser);
}));

// app.put('/api/profile', authMiddleware, asyncHandler(async (req, res) => {
//   const { email, password, ...allowedUpdates } = req.body;
//   const updatedUser = await User.findByIdAndUpdate(req.userId, { $set: allowedUpdates }, { new: true, runValidators: true }).select('-password');
//   if (!updatedUser) return res.status(404).json({ message: 'User not found.' });
//   res.json(updatedUser);
// }));

// ✅ Updated Edit Profile Route
app.put(
  '/api/profile',
  authMiddleware,
  asyncHandler(async (req, res) => {
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

app.post('/api/products', authMiddleware, upload.single('image'), asyncHandler(async (req, res) => {
  const { title, price, description, category } = req.body;
  if (!req.file || !title || !price || !description || !category)
    return res.status(400).json({ message: 'All fields, including image, are required.' });

  const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
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
// app.post('/api/auth/signup', asyncHandler(async (req, res) => {
//   const { name, email, password, department, programName, section, rollNumber, studentCode, registrationNumber } = req.body;
//   const universityDomain = process.env.UNIVERSITY_DOMAIN || '@brainwareuniversity.ac.in';
//   if (!email || !validator.isEmail(email) || !email.endsWith(universityDomain))
//     return res.status(400).json({ message: `Email must end with ${universityDomain}` });
//   if (!name || !password) return res.status(400).json({ message: 'All required fields are required.' });

//   const existingUser = await User.findOne({ email });
//   if (existingUser) return res.status(409).json({ message: 'Account with this email already exists.' });

//   const salt = await bcrypt.genSalt(10);
//   const hashedPassword = await bcrypt.hash(password, salt);

//   const newUser = new User({ name, email, password: hashedPassword, department, programName, section, rollNumber, studentCode, registrationNumber });
//   await newUser.save();

//   const { password: _, ...userToSend } = newUser.toObject();
//   res.status(201).json({ message: 'User created successfully!', user: userToSend, token: userToSend._id });
// }));

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
  res.status(500).json({ message: 'Internal Server Error' });
});

// ========================
// START SERVER
// ========================
app.listen(port, () => {
  console.log(`✅ Backend server is running on http://localhost:${port}`);
});
