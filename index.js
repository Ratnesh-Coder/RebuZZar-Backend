const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // Import bcryptjs
const crypto = require('crypto');
require('dotenv').config();

// --- MULTER CONFIG ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage });

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected Successfully'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// --- MONGOOSE SCHEMAS & MODELS ---
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Store hashed password
  avatar: { type: String, default: 'https://via.placeholder.com/150' },
  joinDate: { type: Date, default: Date.now },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});
const User = mongoose.model('User', UserSchema);

const ProductSchema = new mongoose.Schema({
  title: { type: String, required: true },
  price: { type: Number, required: true },
  description: { type: String, required: true },
  imageUrl: { type: String, required: true },
  category: { type: String, required: true },
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  postDate: { type: Date, default: Date.now },
});
const Product = mongoose.model('Product', ProductSchema);

// --- EXPRESS APP SETUP ---
const app = express();
const port = 5000;
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// --- AUTH MIDDLEWARE ---
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: 'Authorization token required.' });
    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token format is "Bearer TOKEN".' });

    const user = await User.findById(token);
    if (user) {
      req.userId = user._id;
      next();
    } else {
      res.status(403).json({ message: 'Invalid or unknown user token.' });
    }
  } catch (error) {
    console.error("Auth Middleware Error:", error); // Added specific log
    res.status(500).json({ message: "Internal Server Error during authentication." });
  }
};

// --- PRODUCT ROUTES ---
app.get('/api/products', async (req, res) => {
  try {
    const { category, search } = req.query;
    let filter = {};
    if (category) {
      filter.category = { $regex: new RegExp(`^${category}$`, 'i') };
    }
    if (search) {
      filter.title = { $regex: search, $options: 'i' };
    }
    console.log("Filtering products with:", filter);
    const products = await Product.find(filter);
    res.json(products);
  } catch (error) {
    console.error("Error fetching products:", error); // Added specific log
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (product) {
      res.json(product);
    } else {
      res.status(404).json({ message: 'Product not found' });
    }
  } catch (error) {
    console.error("Error fetching single product:", error); // Added specific log
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post('/api/products', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    const { title, price, description, category } = req.body;
    if (!req.file || !title || !price || !description || !category) {
      return res.status(400).json({ message: 'All fields, including image, are required.' });
    }
    const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    const newProduct = new Product({
      title, price: Number(price), description, imageUrl, category,
      sellerId: req.userId
    });
    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (error) {
    console.error("Error posting product:", error); // Added specific log
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// DELETE a product (NEW!)
app.delete('/api/products/:id', authMiddleware, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);

    if (!product) {
      return res.status(404).json({ message: 'Product not found.' });
    }

    // Ensure the user deleting the product is the one who created it
    if (product.sellerId.toString() !== req.userId.toString()) {
      return res.status(403).json({ message: 'User not authorized to delete this product.' });
    }

    await Product.findByIdAndDelete(req.params.id);

    // Note: In a real app, you would also delete the associated image file from the 'uploads' folder here.
    // We will skip that for now to keep it simple.

    res.json({ message: 'Product deleted successfully.' });
  } catch (error) {
    console.error("Error deleting product:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// --- AUTH ROUTES (WITH DETAILED DEBUGGING LOGS) ---

// POST User Signup
app.post('/api/auth/signup', async (req, res) => {
  console.log('--- Signup Attempt ---');
  try {
    const { name, email, password } = req.body;
    console.log('Received signup request for email:', email);

    if (!name || !email || !password) {
      console.log('Signup failed: Missing fields.');
      return res.status(400).json({ message: 'All fields are required.' });
    }
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log('Signup failed: Email already exists:', email);
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    const salt = await bcrypt.genSalt(10);
    console.log('Generated salt for password.');
    const hashedPassword = await bcrypt.hash(password, salt);
    console.log('Hashed password successfully.');

    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();
    console.log('New user saved to DB:', email);
    
    const { password: _, ...userToSend } = newUser.toObject();
    res.status(201).json({
      message: 'User created successfully!',
      user: userToSend,
      token: userToSend._id
    });
    console.log('Signup successful, response sent for:', email);
  } catch (error) {
    console.error("Signup Error (Catch Block):", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
  console.log('--- End Signup Attempt ---');
});

// POST User Login
app.post('/api/auth/login', async (req, res) => {
  console.log('--- Login Attempt ---');
  try {
    const { email, password } = req.body;
    console.log('Received login request for email:', email);

    // Find the user by email only
    const user = await User.findOne({ email });
    if (!user) {
      console.log('Login failed: User not found for email:', email);
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    console.log('User found for email:', user.email);

    // Compare the provided password with the stored hash
    // This is where the error likely occurs if the stored password isn't hashed or is null/undefined
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Login failed: Password mismatch for email:', email);
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    console.log('Password matched for user:', user.email);

    // POST Forgot Password (NEW!)
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      // Security best practice: Don't reveal if an email is registered or not.
      // Always send a generic success message.
      console.log(`Password reset attempt for non-existent email: ${email}`);
      return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    }

    // Generate a random, secure token
    const token = crypto.randomBytes(20).toString('hex');

    // Set the token and its expiration on the user's document
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // Token expires in 1 hour

    await user.save();

    // --- SIMULATE SENDING AN EMAIL ---
    // In a real production app, you would use a service like SendGrid, Mailgun, or Nodemailer here.
    // For our project, we will log the link to the console.
    const resetLink = `http://localhost:5173/reset-password/${token}`;
    console.log('--- PASSWORD RESET ---');
    console.log(`A password reset was requested for: ${user.email}`);
    console.log(`Reset Link (copy this and paste in browser): ${resetLink}`);
    console.log('--------------------');

    res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
  } catch (error) {
    console.error("Forgot Password Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});
    
    // Login successful
    const { password: _, ...userToSend } = user.toObject();
    res.json({
      message: "Login successful!",
      user: userToSend,
      token: userToSend._id
    });
    console.log('Login successful, response sent for:', email);
  } catch (error) {
    console.error("Login Error (Catch Block):", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
  console.log('--- End Login Attempt ---');
});

// --- START SERVER ---
app.listen(port, () => {
  console.log(`✅ Backend server is running on http://localhost:${port}`);
});