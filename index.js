// const express = require('express');
// const cors = require('cors');
// const multer = require('multer');
// const path = require('path');
// const mongoose = require('mongoose');
// const bcrypt = require('bcryptjs');
// const crypto = require('crypto');
// const nodemailer = require('nodemailer');
// require('dotenv').config();

// // --- MULTER CONFIG ---
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => cb(null, 'uploads/'),
//   filename: (req, file, cb) => cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`)
// });
// const upload = multer({ storage });

// // --- DATABASE CONNECTION ---
// mongoose.connect(process.env.MONGO_URI)
//   .then(() => console.log('✅ MongoDB Connected Successfully'))
//   .catch(err => console.error('❌ MongoDB Connection Error:', err));

// // --- MONGOOSE SCHEMAS & MODELS ---
// const UserSchema = new mongoose.Schema({
//   name: { type: String, required: true },
//   email: { type: String, required: true, unique: true },
//   password: { type: String, required: true },
//   avatar: { type: String,  default: 'https://via.placeholder.com/150' },
//   joinDate: { type: Date,  default: Date.now },
//   department: { type: String },
//   programName: { type: String },
//   section: { type: String },
//   rollNumber: { type: String },
//   studentCode: { type: String },
//   registrationNumber: { type: String },

//   // Optional fields for password reset
//   resetPasswordToken: { type: String },
//   resetPasswordExpires: { type: Date },
// });

// const User = mongoose.model('User', UserSchema);
// User.collection.dropIndex('id_1').catch(() => {});

// const ProductSchema = new mongoose.Schema({
//   title: { type: String, required: true },
//   price: { type: Number, required: true },
//   description: { type: String, required: true },
//   imageUrl: { type: String, required: true },
//   category: { type: String, required: true },
//   sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
//   postDate: { type: Date, default: Date.now },
// });
// const Product = mongoose.model('Product', ProductSchema);

// // --- EXPRESS APP SETUP ---
// const app = express();
// const port = 5000;
// app.use(cors());
// app.use(express.json());
// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// // --- AUTH MIDDLEWARE ---
// const authMiddleware = async (req, res, next) => {
//   try {
//     const authHeader = req.headers['authorization'];
//     if (!authHeader) return res.status(401).json({ message: 'Authorization token required.' });
//     const token = authHeader.split(' ')[1];
//     if (!token) return res.status(401).json({ message: 'Token format is "Bearer TOKEN".' });
//     const user = await User.findById(token);
//     if (user) {
//       req.userId = user._id;
//       next();
//     } else {
//       res.status(403).json({ message: 'Invalid or unknown user token.' });
//     }
//   } catch (error) {
//     res.status(500).json({ message: "Internal Server Error during authentication." });
//   }
// };

// // --- NEW: AVATAR UPLOAD ROUTE ---
// app.post('/api/profile/avatar', authMiddleware, upload.single('avatar'), async (req, res) => {
//   try {
//     if (!req.file) {
//       return res.status(400).json({ message: 'Avatar image file is required.' });
//     }
    
//     // Construct the URL for the new avatar
//     const avatarUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;

//     // Find the user and update their avatar URL
//     const updatedUser = await User.findByIdAndUpdate(
//       req.userId,
//       { avatar: avatarUrl },
//       { new: true }
//     ).select('-password');

//     if (!updatedUser) {
//       return res.status(404).json({ message: 'User not found.' });
//     }

//     console.log(`Avatar updated for user: ${updatedUser.email}`);
//     res.json(updatedUser);
//   } catch (error) {
//     console.error("Error uploading avatar:", error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // --- PRODUCT ROUTES ---
// app.get('/api/products', async (req, res) => {
//   try {
//     const { category, search } = req.query;
//     let filter = {};
//     if (category) {
//       filter.category = { $regex: new RegExp(`^${category}$`, 'i') };
//     }
//     if (search) {
//       filter.title = { $regex: search, $options: 'i' };
//     }
//     const products = await Product.find(filter);
//     res.json(products);
//   } catch (error) {
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.get('/api/products/:id', async (req, res) => {
//   try {
//     const product = await Product.findById(req.params.id);
//     if (product) {
//       res.json(product);
//     } else {
//       res.status(404).json({ message: 'Product not found' });
//     }
//   } catch (error) {
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.get('/api/profile/products', authMiddleware, async (req, res) => {
//   try {
//     // req.userId is attached by the authMiddleware
//     const userProducts = await Product.find({ sellerId: req.userId });
//     res.json(userProducts);
//   } catch (error) {
//     console.error("Error fetching user products:", error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.post('/api/products', authMiddleware, upload.single('image'), async (req, res) => {
//   try {
//     const { title, price, description, category } = req.body;
//     if (!req.file || !title || !price || !description || !category) {
//       return res.status(400).json({ message: 'All fields, including image, are required.' });
//     }
//     const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
//     const newProduct = new Product({
//       title, price: Number(price), description, imageUrl, category,
//       sellerId: req.userId
//     });
//     await newProduct.save();
//     res.status(201).json(newProduct);
//   } catch (error) {
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.put('/api/products/:id', authMiddleware, async (req, res) => {
//   try {
//     const { title, price, description, category } = req.body;
//     const product = await Product.findById(req.params.id);
//     if (!product) {
//       return res.status(404).json({ message: 'Product not found.' });
//     }
//     if (product.sellerId.toString() !== req.userId.toString()) {
//       return res.status(403).json({ message: 'User not authorized to edit this product.' });
//     }
//     product.title = title;
//     product.price = price;
//     product.description = description;
//     product.category = category;
//     const updatedProduct = await product.save();
//     res.json(updatedProduct);
//   } catch (error) {
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.delete('/api/products/:id', authMiddleware, async (req, res) => {
//   try {
//     const product = await Product.findById(req.params.id);
//     if (!product) {
//       return res.status(404).json({ message: 'Product not found.' });
//     }
//     if (product.sellerId.toString() !== req.userId.toString()) {
//       return res.status(403).json({ message: 'User not authorized to delete this product.' });
//     }
//     await Product.findByIdAndDelete(req.params.id);
//     res.json({ message: 'Product deleted successfully.' });
//   } catch (error) {
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.get('/api/users/:id', async (req, res) => {
//   try {
//     const user = await User.findById(req.params.id);
//     if (!user) {
//       return res.status(404).json({ message: 'Seller not found.' });
//     }
//     res.json({ name: user.name, email: user.email });
//   } catch (error) {
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.put('/api/profile', authMiddleware, async (req, res) => {
//   try {
//     const userId = req.userId;
//     const { email, password, ...allowedUpdates } = req.body;
//     const updatedUser = await User.findByIdAndUpdate(
//       userId,
//       { $set: allowedUpdates },
//       { new: true, runValidators: true }
//     ).select('-password');
//     if (!updatedUser) {
//       return res.status(404).json({ message: 'User not found.' });
//     }
//     res.json(updatedUser);
//   } catch (error) {
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // POST User Signup (UPDATED FOR UNIVERSITY EMAIL VALIDATION)
// app.post('/api/auth/signup', async (req, res) => {
//   try {
//     const { 
//       name, email, password, 
//       department, programName, section, rollNumber, studentCode, registrationNumber 
//     } = req.body;

//     // --- NEW: University Email Validation ---
//     const universityDomain = '@brainwareuniversity.ac.in'; // <--- IMPORTANT: Change this to your university's email domain
//     if (!email.endsWith(universityDomain)) {
//       return res.status(400).json({ message: `Registration is only open to users with a students of Brainware Univerity.` });
//     }
//     // ------------------------------------

//     if (!name || !password) {
//       return res.status(400).json({ message: 'All fields are required.' });
//     }

//     const existingUser = await User.findOne({ email });
//     if (existingUser) {
//       return res.status(409).json({ message: 'An account with this email already exists.' });
//     }

//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);

//     const newUser = new User({ 
//       name, 
//       email, 
//       password: hashedPassword,
//       department,
//       programName,
//       section,
//       rollNumber,
//       studentCode,
//       registrationNumber
//     });
//     await newUser.save();

//     const { password: _, ...userToSend } = newUser.toObject();
//     res.status(201).json({
//       message: 'User created successfully!',
//       user: userToSend,
//       token: userToSend._id
//     });
//   } catch (error) {
//     console.error("Signup Error:", error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.post('/api/auth/login', async (req, res) => {
//   try {
//     const { email, password } = req.body;
//     const user = await User.findOne({ email });
//     if (!user) {
//       return res.status(401).json({ message: 'Invalid email or password' });
//     }
//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) {
//       return res.status(401).json({ message: 'Invalid email or password' });
//     }
//     const { password: _, ...userToSend } = user.toObject();
//     res.json({
//       message: "Login successful!",
//       user: userToSend,
//       token: userToSend._id
//     });
//   } catch (error) {
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.post('/api/auth/forgot-password', async (req, res) => {
//   try {
//     const { email } = req.body;
//     const user = await User.findOne({ email });
//     if (!user) {
//       return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
//     }
//     const token = crypto.randomBytes(20).toString('hex');
//     user.resetPasswordToken = token;
//     user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
//     await user.save();
    
//     const transporter = nodemailer.createTransport({
//       host: process.env.EMAIL_HOST,
//       port: process.env.EMAIL_PORT,
//       auth: {
//         user: process.env.EMAIL_USER,
//         pass: process.env.EMAIL_PASS
//       }
//     });

//     const resetLink = `http://localhost:5173/reset-password/${token}`;

//     const mailOptions = {
//       from: '"Campus Kart Support" <no-reply@campuskart.com>',
//       to: user.email,
//       subject: 'Your Campus Kart Password Reset Link',
//       html: `<p>Please click the following link to reset your password: <a href="${resetLink}">${resetLink}</a></p>`
//     };

//     await transporter.sendMail(mailOptions);
//     console.log(`Password reset email sent to Mailtrap for: ${user.email}`);
    
//     res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
//   } catch (error) {
//     console.error("Forgot Password Error:", error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.post('/api/auth/reset-password/:token', async (req, res) => {
//   try {
//     const user = await User.findOne({
//       resetPasswordToken: req.params.token,
//       resetPasswordExpires: { $gt: Date.now() },
//     });
//     if (!user) {
//       return res.status(400).json({ message: 'Password reset token is invalid or has expired.' });
//     }
//     const { password } = req.body;
//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);
//     user.password = hashedPassword;
//     user.resetPasswordToken = undefined;
//     user.resetPasswordExpires = undefined;
//     await user.save();
//     res.json({ message: 'Your password has been updated successfully.' });
//   } catch (error) {
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// // --- START SERVER ---
// app.listen(port, () => {
//   console.log(`✅ Backend server is running on http://localhost:${port}`);
// });


// server.js (updated, annotated)
// --------------------------------------------------
// KEEP CORE ROUTES/BEHAVIOR — security & quality updates only
// --------------------------------------------------

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit'); // CHANGE #1: rate limiting
const helmet = require('helmet'); // CHANGE #2: security headers
const mongoSanitize = require('express-mongo-sanitize'); // CHANGE #3: sanitize
const validator = require('validator'); // CHANGE #4: simple validation helpers
require('dotenv').config();

// --- BASIC APP SETUP ---
const app = express();
const port = process.env.PORT || 5000;

app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*', // set explicit origins in production
}));
app.use(express.json({ limit: '10kb' })); // protect against very large JSON bodies
app.use((req, res, next) => {
  req.query = { ...req.query }; // create a shallow copy
  mongoSanitize.sanitize(req.query); // sanitize the copy
  next();
});

// --- RATE LIMITERS ---
// CHANGE #1: apply rate limiting especially to auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: { message: 'Too many requests from this IP, please try again later.' }
});

// --- MULTER CONFIG ---
// CHANGE #5: added file size limit and allow only images
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
const upload = multer({ storage, limits: { fileSize: 2 * 1024 * 1024 }, fileFilter }); // 2MB limit

// --- DATABASE CONNECTION ---
// CHANGE #6: add safe mongoose options and better logging
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('✅ MongoDB Connected Successfully'))
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err);
    process.exit(1);
  });

// --- MONGOOSE SCHEMAS & MODELS ---
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  avatar: { type: String, default: 'https://via.placeholder.com/150' },
  joinDate: { type: Date, default: Date.now },
  department: { type: String },
  programName: { type: String },
  section: { type: String },
  rollNumber: { type: String },
  studentCode: { type: String },
  registrationNumber: { type: String },

  // password reset fields
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

// safe index drop attempt — swallow error if not present
User.collection.dropIndex('id_1').catch(() => {});

// Product schema same as before
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

const Product = mongoose.model('Product', ProductSchema);

// --- AUTH MIDDLEWARE ---
// NOTE: this preserves your simple userId-as-token approach but makes checks safer
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: 'Authorization token required.' });
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return res.status(401).json({ message: 'Token format is "Bearer TOKEN".' });
    }
    const token = parts[1];
    if (!validator.isMongoId(token)) {
      return res.status(401).json({ message: 'Invalid token format.' });
    }
    const user = await User.findById(token);
    if (!user) return res.status(403).json({ message: 'Invalid or unknown user token.' });

    req.userId = user._id;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ message: 'Internal Server Error during authentication.' });
  }
};

// --- NEW: AVATAR UPLOAD ROUTE ---
app.post('/api/profile/avatar', authMiddleware, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'Avatar image file is required.' });
    }

    const avatarUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;

    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      { avatar: avatarUrl },
      { new: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found.' });
    }

    console.log(`Avatar updated for user: ${updatedUser.email}`);
    res.json(updatedUser);
  } catch (error) {
    console.error("Error uploading avatar:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// --- PRODUCT ROUTES --- (kept core behavior)
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
    console.error('GET /api/products error:', error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (product) return res.json(product);
    res.status(404).json({ message: 'Product not found' });
  } catch (error) {
    console.error('GET /api/products/:id error:', error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get('/api/profile/products', authMiddleware, async (req, res) => {
  try {
    const userProducts = await Product.find({ sellerId: req.userId });
    res.json(userProducts);
  } catch (error) {
    console.error("Error fetching user products:", error);
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
    console.error('POST /api/products error:', error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.put('/api/products/:id', authMiddleware, async (req, res) => {
  try {
    const { title, price, description, category } = req.body;
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found.' });
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
    console.error('PUT /api/products/:id error:', error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.delete('/api/products/:id', authMiddleware, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found.' });
    if (product.sellerId.toString() !== req.userId.toString()) {
      return res.status(403).json({ message: 'User not authorized to delete this product.' });
    }
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted successfully.' });
  } catch (error) {
    console.error('DELETE /api/products/:id error:', error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'Seller not found.' });
    res.json({ name: user.name, email: user.email });
  } catch (error) {
    console.error('GET /api/users/:id error:', error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// update profile (name, department, etc.) — email/password updates excluded
app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const { email, password, ...allowedUpdates } = req.body;
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $set: allowedUpdates },
      { new: true, runValidators: true }
    ).select('-password');
    if (!updatedUser) return res.status(404).json({ message: 'User not found.' });
    res.json(updatedUser);
  } catch (error) {
    console.error('PUT /api/profile error:', error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// --- AUTH: SIGNUP ---
app.post('/api/auth/signup', async (req, res) => {
  try {
    const {
      name, email, password,
      department, programName, section, rollNumber, studentCode, registrationNumber
    } = req.body;

    // CHANGE #7: university email validation (adjust domain as needed)
    const universityDomain = process.env.UNIVERSITY_DOMAIN || '@brainwareuniversity.ac.in';
    if (!email || !validator.isEmail(email) || !email.endsWith(universityDomain)) {
      return res.status(400).json({ message: `Registration is only open to users with a ${universityDomain} email.` });
    }

    if (!name || !password) {
      return res.status(400).json({ message: 'All required fields are required.' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(409).json({ message: 'An account with this email already exists.' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      department,
      programName,
      section,
      rollNumber,
      studentCode,
      registrationNumber
    });
    await newUser.save();

    const { password: _, ...userToSend } = newUser.toObject();
    res.status(201).json({
      message: 'User created successfully!',
      user: userToSend,
      token: userToSend._id // NOTE: retains original simple token behavior
    });
  } catch (error) {
    console.error("Signup Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// --- AUTH: LOGIN ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required.' });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid email or password' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid email or password' });

    const { password: _, ...userToSend } = user.toObject();
    res.json({
      message: "Login successful!",
      user: userToSend,
      token: userToSend._id
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// --- AUTH: FORGOT PASSWORD ---
// CHANGE #8: using authLimiter and hashed token storage for safety
app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !validator.isEmail(email)) {
      // don't reveal details; return same message
      return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    }

    // CHANGE #9: generate a 32-byte token, send raw token in email but store HASH
    const rawToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = Date.now() + 1000 * 60 * 60; // 1 hour
    await user.save();

    // CHANGE #10: FRONTEND_URL from env
    const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
    const resetLink = `${FRONTEND_URL}/reset-password/${rawToken}`;

    // CHANGE #11: robust transporter creation (parse port & secure)
    const mailPort = Number(process.env.EMAIL_PORT) || 587;
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: mailPort,
      secure: process.env.EMAIL_SECURE === 'true' || mailPort === 465, // true for 465
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      },
    });

    // CHANGE #12: text + html, proper tags, and consistent from/to formatting
    const html = `
      <html>
        <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
          <h2>Password Reset Request</h2>
          <p>Click the link below to reset your RebuZZar password. This link expires in 1 hour.</p>
          <p><a href="${resetLink}" style="color: #1f2937; text-decoration: underline;">Reset password</a></p>
          <p>If you didn't request this, you can safely ignore this email.</p>
        </body>
      </html>
    `;

    const text = `Password Reset Request\n\nVisit this link to reset your password (expires in 1 hour):\n\n${resetLink}\n\nIf you didn't request this, ignore this email.`;

    const mailOptions = {
      from: process.env.EMAIL_FROM || '"RebuZZar Support" <no-reply@campuskart.com>',
      to: `${user.name || 'User'} <${user.email}>`,
      subject: 'Your RebuZZar Password Reset Link',
      text,
      html
    };

    await transporter.sendMail(mailOptions);
    console.log(`Password reset email queued for: ${user.email}`);

    res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
  } catch (error) {
    console.error("Forgot Password Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// --- AUTH: RESET PASSWORD ---
// CHANGE #13: match hashed token (do not store raw token in DB)
app.post('/api/auth/reset-password/:token', async (req, res) => {
  try {
    const rawToken = req.params.token;
    const { password } = req.body;

    if (!password || password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long.' });
    }

    const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Password reset token is invalid or has expired.' });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Your password has been updated successfully.' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// --- START SERVER ---
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.listen(port, () => {
  console.log(`✅ Backend server is running on http://localhost:${port}`);
});
