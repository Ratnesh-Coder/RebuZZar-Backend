const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
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
  password: { type: String, required: true },
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
    const products = await Product.find(filter);
    res.json(products);
  } catch (error) {
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
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.put('/api/products/:id', authMiddleware, async (req, res) => {
  try {
    const { title, price, description, category } = req.body;
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found.' });
    }
    if (product.sellerId.toString() !== req.userId.toString()) {
      return res.status(403).json({ message: 'User not authorized to edit this product.' });
    }
    product.title = title;
    product.price = price;
    product.description = description;
    product.category = category;
    const updatedProduct = await product.save();
    res.json(updatedProduct);
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.delete('/api/products/:id', authMiddleware, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found.' });
    }
    if (product.sellerId.toString() !== req.userId.toString()) {
      return res.status(403).json({ message: 'User not authorized to delete this product.' });
    }
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted successfully.' });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'Seller not found.' });
    }
    res.json({ name: user.name, email: user.email });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// --- AUTH ROUTES ---
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();
    const { password: _, ...userToSend } = newUser.toObject();
    res.status(201).json({
      message: 'User created successfully!',
      user: userToSend,
      token: userToSend._id
    });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    const { password: _, ...userToSend } = user.toObject();
    res.json({
      message: "Login successful!",
      user: userToSend,
      token: userToSend._id
    });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    }
    const token = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();
    
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const resetLink = `http://localhost:5173/reset-password/${token}`;

    const mailOptions = {
      from: '"Campus Kart Support" <no-reply@campuskart.com>',
      to: user.email,
      subject: 'Your Campus Kart Password Reset Link',
      html: `<p>Please click the following link to reset your password: <a href="${resetLink}">${resetLink}</a></p>`
    };

    await transporter.sendMail(mailOptions);
    console.log(`Password reset email sent to Mailtrap for: ${user.email}`);
    
    res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
  } catch (error) {
    console.error("Forgot Password Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post('/api/auth/reset-password/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() },
    });
    if (!user) {
      return res.status(400).json({ message: 'Password reset token is invalid or has expired.' });
    }
    const { password } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();
    res.json({ message: 'Your password has been updated successfully.' });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// --- START SERVER ---
app.listen(port, () => {
  console.log(`✅ Backend server is running on http://localhost:${port}`);
});