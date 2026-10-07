const Product = require('../models/Product');
const User = require('../models/User');
const Booking = require('../models/Booking');
const HttpError = require('../utils/httpError');
const escapeRegex = require('../utils/escapeRegex');
const productEmail = require('../services/email/product.email');
const { deleteUploadedFiles } = require('../middlewares/upload');

const NOT_DELETED = { $ne: true }; // works for documents with or without the isDeleted field
const RELATED_LIMIT = 11; // frontend shows up to 10 related items after excluding the current one

// Query-string values may be arrays (?a=1&a=2); take the first string, cap the length.
const queryString = (value, max = 100) => {
  const v = Array.isArray(value) ? value[0] : value;
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
};

/**
 * Validate product fields. `partial` (update) only checks the fields that are present.
 * Works for JSON bodies and multipart fields (everything arrives as strings there).
 */
const validateProductInput = (body, { partial = false } = {}) => {
  const src = body || {};
  const out = {};
  const has = (k) => src[k] !== undefined;

  const text = (key, label, max) => {
    if (!has(key)) { if (!partial) throw new HttpError(400, `${label} is required.`); return; }
    const v = typeof src[key] === 'string' ? src[key].trim() : '';
    if (!v) throw new HttpError(400, `${label} is required.`);
    if (v.length > max) throw new HttpError(400, `${label} must be at most ${max} characters.`);
    out[key] = v;
  };
  text('title', 'Title', 150);
  text('description', 'Description', 3000);
  text('category', 'Category', 50);

  if (has('price') || !partial) {
    const price = typeof src.price === 'string' || typeof src.price === 'number' ? Number(src.price) : NaN;
    if (!Number.isFinite(price) || price <= 0 || price > 10000000) {
      throw new HttpError(400, 'Price must be a number greater than zero.');
    }
    out.price = price;
  }
  if (has('quantity') || !partial) {
    const quantity = typeof src.quantity === 'string' || typeof src.quantity === 'number' ? Number(src.quantity) : NaN;
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 10000) {
      throw new HttpError(400, 'Quantity must be a whole number of at least 1.');
    }
    out.quantity = quantity;
  }
  return out;
};

/* GET all approved products */
exports.getAllProducts = async (req, res) => {
  const category = queryString(req.query.category);
  const search = queryString(req.query.search);

  const filter = { status: 'approved', isDeleted: NOT_DELETED };
  if (category) filter.category = new RegExp(`^${escapeRegex(category)}$`, 'i');
  if (search) filter.title = { $regex: escapeRegex(search), $options: 'i' };

  const products = await Product.find(filter);
  res.json(products);
};

/*
 * GET product by ID. Deliberately public and NOT limited to approved products:
 * EditProduct loads pending/rejected products through this endpoint without a token.
 * Seller PII (sellerName/sellerEmail) is stripped by the Product toJSON transform.
 */
exports.getProductById = async (req, res) => {
  const product = await Product.findOne({ _id: req.params.id, isDeleted: NOT_DELETED });
  if (!product) throw new HttpError(404, 'Product not found');

  res.json(product);
};

/* GET seller contact for a product */
exports.getSellerContact = async (req, res) => {
  const product = await Product.findOne({
    _id: req.params.id,
    isDeleted: NOT_DELETED,
  });

  if (!product) {
    throw new HttpError(404, 'Product not found.');
  }

  const seller = await User.findById(product.sellerId).select(
    'name department year phoneNumber contactPreference'
  );

  if (!seller) {
    throw new HttpError(404, 'Seller not found.');
  }

  res.json({
    seller: {
      name: seller.name,
      department: seller.department,
      year: seller.year,
      phoneNumber: seller.phoneNumber,
      contactPreference: seller.contactPreference,
    },
  });
};

/* CREATE product */
exports.createProduct = async (req, res) => {
  const files = req.files || [];
  let product;
  try {
    if (files.length === 0) throw new HttpError(400, 'Images required.');
    const fields = validateProductInput(req.body);

    // req.user was loaded by the auth middleware (fresh from the database).
    const seller = req.user;

    product = await Product.create({
      ...fields,
      imageUrl: files.map((f) => f.path),
      sellerId: seller._id,
      sellerName: seller.name,
      sellerEmail: seller.email,
    });
  } catch (err) {
    await deleteUploadedFiles(files); // don't leave orphaned images in Cloudinary
    throw err;
  }

  // The product is saved: respond first, then notify. A mail failure is logged, never surfaced.
  res.status(201).json(product);
  await productEmail.notifyProductSubmitted({ seller: req.user, product });
};

/* UPDATE product */
exports.updateProduct = async (req, res) => {
  const product = await Product.findOne({ _id: req.params.id, isDeleted: NOT_DELETED });
  if (!product) throw new HttpError(404, 'Product not found.');

  // Authorization: only the owner may edit.
  if (!product.sellerId.equals(req.userId)) {
    throw new HttpError(403, 'You are not authorized to edit this product.');
  }

  // Whitelisted, validated fields only. (Editing does not re-trigger moderation - existing behaviour.)
  const updates = validateProductInput(req.body, { partial: true });
  Object.assign(product, updates);
  await product.save();

  res.json({ message: 'Product updated successfully.', product });
};

/* DELETE product */
exports.deleteProduct = async (req, res) => {
  const product = await Product.findOne({ _id: req.params.id, isDeleted: NOT_DELETED });
  if (!product) throw new HttpError(404, 'Product not found.');

  if (!product.sellerId.equals(req.userId)) {
    throw new HttpError(403, 'You do not have permission to delete this product.');
  }

  // Was the product ever booked (and not cancelled)?
  const findActiveBooking = () => Booking.findOne({
    'products.productId': product._id,
    status: { $ne: 'Cancelled' },
  }).populate('buyerId', 'name email');
  let booking = await findActiveBooking();

  // Hard delete only when it is certain nobody holds it: the filter on isBooked makes this
  // safe against a booking created between the lookup above and the delete.
  let hardDeleted = false;
  if (!booking) {
    const result = await Product.deleteOne({ _id: product._id, isBooked: { $ne: true } });
    hardDeleted = result.deletedCount === 1;
  }
  if (!hardDeleted) {
    await Product.updateOne({ _id: product._id }, { $set: { isDeleted: true, deletedAt: new Date() } });
    // The hard delete was refused because the product got booked after the lookup above:
    // look again so the buyer is still told their item was removed.
    if (!booking) booking = await findActiveBooking();
  }

  res.json(
    hardDeleted
      ? { message: 'Product deleted successfully.', deletionType: 'hard' }
      : { message: 'Product removed successfully.', deletionType: 'soft' }
  );

  await productEmail.notifyProductRemoved({
    seller: req.user,
    product,
    booking: booking || null,
    buyer: booking ? booking.buyerId : null,
  });
};

/* Related products by category (exact category, approved, not deleted) */
exports.getProductsByCategory = async (req, res) => {
  const products = await Product.find({
    category: req.params.category,
    status: 'approved',
    isDeleted: NOT_DELETED,
  }).limit(RELATED_LIMIT);
  res.json(products);
};

/* GET products of logged-in user */
exports.getMyProducts = async (req, res) => {
  const products = await Product.find({
    sellerId: req.userId,
    isDeleted: NOT_DELETED,
  }).sort({ createdAt: -1 });
  res.json(products);
};

exports._validateProductInput = validateProductInput; // exported for unit tests
