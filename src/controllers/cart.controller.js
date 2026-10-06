const validator = require('validator');
const Cart = require('../models/Cart');
const Product = require('../models/Product');
const HttpError = require('../utils/httpError');
const { MAX_ITEM_QUANTITY } = require('../utils/constants');

/**
 * Response view of a cart. Stored item snapshots can go stale, so title/price/image are
 * refreshed from the live product, and items that can no longer be bought (deleted, not
 * approved, already booked) are flagged `unavailable: true` - never silently removed.
 * The stored snapshot is not trusted by checkout (the booking service reads DB prices).
 */
const presentCart = async (cart) => {
  const plain = typeof cart.toObject === 'function' ? cart.toObject() : cart;
  const ids = plain.items.map((i) => i.productId);
  const products = ids.length
    ? await Product.find({ _id: { $in: ids } }).select('title price imageUrl status isDeleted isBooked')
    : [];
  const byId = new Map(products.map((p) => [String(p._id), p]));

  plain.items = plain.items.map((item) => {
    const p = byId.get(String(item.productId));
    if (!p || p.isDeleted === true || p.status !== 'approved') return { ...item, unavailable: true };
    return {
      ...item,
      title: p.title,
      price: p.price,
      imageUrl: p.imageUrl,
      ...(p.isBooked ? { unavailable: true } : {}),
    };
  });
  return plain;
};

const parseQuantity = (value, { defaultValue } = {}) => {
  if (value === undefined && defaultValue !== undefined) return defaultValue;
  const n = typeof value === 'number' || typeof value === 'string' ? Number(value) : NaN;
  return Number.isInteger(n) ? n : NaN;
};

/* GET CART */
exports.getCart = async (req, res) => {
  // Upsert avoids a duplicate-key race on the unique userId index.
  const cart = await Cart.findOneAndUpdate(
    { userId: req.userId },
    { $setOnInsert: { items: [] } },
    { new: true, upsert: true }
  );
  res.json(await presentCart(cart));
};

/* ADD TO CART */
exports.addToCart = async (req, res) => {
  const { productId } = req.body || {};
  const quantity = req.body && req.body.quantity;

  if (typeof productId !== 'string' || !validator.isMongoId(productId)) {
    throw new HttpError(400, 'Invalid productId.');
  }

  const qty = parseQuantity(quantity, { defaultValue: 1 });
  if (!(qty >= 1 && qty <= MAX_ITEM_QUANTITY)) throw new HttpError(400, 'Invalid quantity.');

  const product = await Product.findOne({ _id: productId, isDeleted: { $ne: true } })
    .populate('sellerId', 'name email');
  if (!product || product.status !== 'approved') throw new HttpError(400, 'Product not available.');
  if (product.isBooked) throw new HttpError(400, 'Product is already booked.');

  const seller = product.sellerId || {};
  const snapshot = {
    title: product.title,
    price: product.price,
    imageUrl: product.imageUrl,
  };

  const bump = () => Cart.findOneAndUpdate(
    { userId: req.userId, 'items.productId': product._id },
    {
      $inc: { 'items.$.quantity': qty },
      $set: { 'items.$.title': snapshot.title, 'items.$.price': snapshot.price, 'items.$.imageUrl': snapshot.imageUrl },
    },
    { new: true }
  );

  // Make sure the cart document exists (an E11000 here just means a concurrent request created it).
  await Cart.updateOne({ userId: req.userId }, { $setOnInsert: { items: [] } }, { upsert: true })
    .catch((err) => { if (!err || err.code !== 11000) throw err; });

  // 1) already in the cart: bump quantity and refresh the snapshot, atomically
  let cart = await bump();

  // 2) not in the cart yet: push a new item (only if it is still absent)
  if (!cart) {
    cart = await Cart.findOneAndUpdate(
      { userId: req.userId, 'items.productId': { $ne: product._id } },
      {
        $push: {
          items: {
            productId: product._id,
            ...snapshot,
            quantity: qty,
            // populate() yields null when the seller account is gone: keep the original id then,
            // and never store `sellerId: null`.
            sellerId: seller._id || (typeof product.populated === 'function' && product.populated('sellerId')) || undefined,
            sellerName: seller.name || product.sellerName,
            sellerEmail: seller.email || product.sellerEmail,
          },
        },
      },
      { new: true }
    );
  }

  // 3) lost a race with a concurrent add of the same product: it exists now, so bump instead
  if (!cart) cart = await bump();
  if (!cart) throw new HttpError(409, 'Could not update the cart. Please try again.');

  res.json({ message: 'Added to cart', cart: await presentCart(cart) });
};

/* UPDATE CART ITEM */
exports.updateCartItem = async (req, res) => {
  const { productId } = req.params;
  const qty = parseQuantity(req.body && req.body.quantity);

  if (!validator.isMongoId(productId)) throw new HttpError(400, 'Invalid productId.');
  if (!Number.isInteger(qty) || qty > MAX_ITEM_QUANTITY) throw new HttpError(400, 'Invalid quantity.');

  // quantity <= 0 removes the item (the frontend relies on this contract)
  const update = qty <= 0
    ? { $pull: { items: { productId } } }
    : { $set: { 'items.$.quantity': qty } };

  const cart = await Cart.findOneAndUpdate(
    { userId: req.userId, 'items.productId': productId },
    update,
    { new: true }
  );
  if (!cart) {
    const exists = await Cart.exists({ userId: req.userId });
    throw new HttpError(404, exists ? 'Item not found.' : 'Cart not found.');
  }

  res.json({ cart: await presentCart(cart) });
};

/* REMOVE ITEM */
exports.removeCartItem = async (req, res) => {
  const { productId } = req.params;
  if (!validator.isMongoId(productId)) throw new HttpError(400, 'Invalid productId.');

  const cart = await Cart.findOneAndUpdate(
    { userId: req.userId },
    { $pull: { items: { productId } } },
    { new: true }
  );
  if (!cart) throw new HttpError(404, 'Cart not found.');

  res.json({ cart: await presentCart(cart) });
};

/* CLEAR CART */
exports.clearCart = async (req, res) => {
  const cart = await Cart.findOneAndUpdate({ userId: req.userId }, { $set: { items: [] } }, { new: true });
  if (!cart) throw new HttpError(404, 'Cart not found.');

  res.json({ cart: await presentCart(cart) });
};

exports._presentCart = presentCart; // exported for unit tests
