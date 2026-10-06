const Product = require('../models/Product');
const HttpError = require('../utils/httpError');
const productEmail = require('../services/email/product.email');

const NOT_DELETED = { $ne: true };

/* GET pending products (the admin UI reads sellerId.name / sellerId.email) */
exports.getPendingProducts = async (req, res) => {
  const products = await Product.find({ status: 'pending', isDeleted: NOT_DELETED })
    .populate('sellerId', 'name email');

  // If a seller account no longer exists, populate() yields null and the admin page would crash
  // on `product.sellerId.name`. Fall back to the stored snapshot (sellerName/sellerEmail).
  res.json(products.map((p) => {
    const plain = p.toJSON();
    if (!plain.sellerId) {
      plain.sellerId = { name: p.sellerName || 'Unknown seller', email: p.sellerEmail || '' };
    }
    return plain;
  }));
};

/* UPDATE product status (approve / reject) */
exports.updateProductStatus = async (req, res) => {
  const status = req.body && req.body.status;
  if (typeof status !== 'string' || !['approved', 'rejected'].includes(status)) {
    throw new HttpError(400, 'Invalid status.');
  }

  const product = await Product.findOneAndUpdate(
    { _id: req.params.id, isDeleted: NOT_DELETED },
    { $set: { status } },
    { new: true }
  ).populate('sellerId', 'name email');
  if (!product) throw new HttpError(404, 'Product not found.');

  res.json({ message: `Product ${status} successfully.`, product });

  // Notify the seller after the status change is saved; failures are logged only.
  const seller = product.sellerId || {};
  await productEmail.notifyProductReviewed({
    sellerName: seller.name || product.sellerName,
    sellerEmail: seller.email || product.sellerEmail,
    product,
    status,
  });
};
