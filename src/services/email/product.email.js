const { dispatch } = require('./email.service');
const { shell, table, date, e } = require('./layout');

const adminTo = () => process.env.ADMIN_EMAIL;

/* ---------- Submission (seller + admin) ---------- */
const buildProductSubmitted = ({ seller, product }) => [
  {
    label: 'product-submitted (seller)',
    to: seller.email,
    subject: 'Product submitted successfully | RebuZZar',
    html: shell({
      headerBg: '#0d6efd', title: 'RebuZZar Seller Notification', pad: 24, maxWidth: 640,
      footer: 'This is an automated email. Please do not reply.',
      body: `
        <p style="font-size:16px;">Hello <b>${e(seller.name)}</b>,</p>
        <p>Your product has been <b>successfully submitted</b> on RebuZZar and is currently under admin review.</p>
        <h3 style="margin-top:24px;">📦 Product Details</h3>
        ${table([
          ['Product Name', product.title], ['Category', product.category], ['Price', `₹${product.price}`],
          ['Available Quantity', product.quantity], ['Product ID', String(product._id)],
          ['Upload Date', date(product.createdAt), true], ['Current Status', 'Pending Approval'],
        ])}
        <p style="margin-top:20px;">Once approved, your product will become visible to buyers on the platform.</p>
        <p>You can manage or update your product anytime from your seller dashboard.</p>
        <p style="margin-top:24px;">Thank you for selling with <b>RebuZZar</b>.</p>
        <p>Regards,<br/><b>RebuZZar Seller Support</b></p>`,
    }),
  },
  {
    label: 'product-submitted (admin)',
    to: adminTo(),
    subject: 'New product awaiting approval | RebuZZar Admin',
    html: shell({
      headerBg: '#198754', title: 'RebuZZar Admin Alert', pad: 24, maxWidth: 640,
      footer: 'Internal system notification. Not for external distribution.',
      body: `
        <p style="font-size:16px;">A new product has been uploaded and requires administrative review.</p>
        <h3 style="margin-top:24px;">👤 Seller Information</h3>
        ${table([['Seller Name', seller.name], ['Seller Email', seller.email], ['Seller ID', String(seller._id)]])}
        <h3 style="margin-top:24px;">📦 Product Information</h3>
        ${table([
          ['Product Name', product.title], ['Category', product.category], ['Price', `₹${product.price}`],
          ['Quantity', product.quantity], ['Product ID', String(product._id)],
          ['Uploaded On', date(product.createdAt), true], ['Status', 'Pending Approval'],
        ])}
        <p style="margin-top:20px;">Please review this product and take the appropriate action from the admin dashboard.</p>
        <p>— <b>RebuZZar System</b></p>`,
    }),
  },
];

/* ---------- Admin decision (seller) ---------- */
const buildProductReviewed = ({ sellerName, sellerEmail, product, status }) => {
  const approved = status === 'approved';
  const details = table([
    ['Product', product.title], ['Category', product.category], ['Price', `₹${product.price}`],
    ['Status', `<b style="color:${approved ? '#198754' : '#dc3545'};">${approved ? 'Approved' : 'Rejected'}</b>`, true],
  ]);
  return [{
    label: `product-${status} (seller)`,
    to: sellerEmail,
    subject: approved
      ? 'Your product has been approved | RebuZZar'
      : 'Your product submission was not approved | RebuZZar',
    html: shell({
      headerBg: approved ? '#198754' : '#dc3545', title: 'RebuZZar',
      subtitle: approved ? 'Product Approval Notification' : 'Product Review Notification',
      footer: 'This is an automated message. Please do not reply to this email.',
      body: approved ? `
        <p>Hello <b>${e(sellerName)}</b>,</p>
        <p>Congratulations! 🎉</p>
        <p>Your product has been <b>approved</b> by the <b>RebuZZar Admin Team</b>.</p>
        <h3 style="margin-top:25px;">📦 Product Details</h3>${details}
        <p style="margin-top:20px;">Your product is now visible to all students and can receive orders.</p>
        <p>Thank you for choosing <b>RebuZZar</b>.</p>
        <p style="margin-top:25px;">Regards,<br/><b>RebuZZar Seller Support</b></p>` : `
        <p>Hello <b>${e(sellerName)}</b>,</p>
        <p>Thank you for submitting your product to RebuZZar.</p>
        <p>After review, we are unable to approve the following product at this time.</p>
        <h3 style="margin-top:25px;">📦 Product Details</h3>${details}
        <p style="margin-top:20px;">Please review your product information and upload it again if required.</p>
        <p style="margin-top:25px;">Regards,<br/><b>RebuZZar Seller Support</b></p>`,
    }),
  }];
};

/* ---------- Deletion (not booked: seller + admin / booked: buyer + seller + admin) ---------- */
const buildProductRemoved = ({ seller, product, booking, buyer }) => {
  if (!booking) {
    return [
      {
        label: 'product-removed (seller)',
        to: seller.email,
        subject: 'Product removed from RebuZZar | Seller Notification',
        html: shell({
          headerBg: '#0d6efd', title: 'RebuZZar Seller Panel', subtitle: 'Product Removal Confirmation', pad: 32, maxWidth: 700,
          footer: 'This is a system-generated email. Please do not reply.',
          body: `
            <p>Dear <b>${e(seller.name)}</b>,</p>
            <p>This email is to confirm that the following product has been <b>successfully removed</b> from the RebuZZar marketplace as per your request.</p>
            <h3 style="margin-top:24px;">📦 Product Details</h3>
            ${table([['Product Name', product.title], ['Category', product.category], ['Price', `₹${product.price}`], ['Product ID', String(product._id)]])}
            <p style="margin-top:20px;">The product is no longer visible to buyers and will not be available for purchase.</p>
            <p>If this action was unintentional, you may re-list the product from your seller dashboard.</p>
            <p style="margin-top:28px;">Regards,<br/><b>RebuZZar Seller Support</b></p>`,
        }),
      },
      {
        label: 'product-removed (admin)',
        to: adminTo(),
        subject: 'Product removed by seller | RebuZZar Admin',
        html: shell({
          headerBg: '#6c757d', title: 'RebuZZar Admin Alert', pad: 32, maxWidth: 700,
          body: `
            <h3>🧾 Product Removal Summary</h3>
            ${table([['Seller Name', seller.name], ['Seller Email', seller.email], ['Product Name', product.title], ['Product ID', String(product._id)], ['Action', 'Deleted by seller']])}
            <p style="margin-top:20px;">No buyer impact detected. No further action required.</p>
            <p>— <b>RebuZZar System</b></p>`,
        }),
      },
    ];
  }

  return [
    {
      label: 'product-removed-booked (buyer)',
      to: buyer && buyer.email,
      subject: 'Important update regarding your order | RebuZZar',
      html: shell({
        headerBg: '#dc3545', title: 'RebuZZar', subtitle: 'Order Update', pad: 32, maxWidth: 700,
        body: `
          <p>Dear <b>${e(buyer && buyer.name)}</b>,</p>
          <p>We regret to inform you that one of the items in your order is <b>no longer available</b> as it has been removed by the seller.</p>
          <h3>🧾 Order & Product Details</h3>
          ${table([['Order ID', String(booking._id)], ['Product', product.title], ['Status', 'Item removed by seller']])}
          <p style="margin-top:20px;">Our support team will assist you in accordance with RebuZZar’s order and refund policies.</p>
          <p>We apologize for the inconvenience caused and appreciate your understanding.</p>
          <p style="margin-top:28px;">Sincerely,<br/><b>RebuZZar Customer Support</b></p>`,
      }),
    },
    {
      label: 'product-removed-booked (seller)',
      to: seller.email,
      subject: 'Booked product removed | RebuZZar Seller Notice',
      html: shell({
        headerBg: '#ffc107', headerColor: '#000', title: 'RebuZZar Seller Panel', subtitle: 'Compliance Notification', pad: 32, maxWidth: 700,
        body: `
          <p>Dear <b>${e(seller.name)}</b>,</p>
          <p>You have removed a product that was part of an active customer order.</p>
          <h3>📦 Product & Order Reference</h3>
          ${table([['Product', product.title], ['Order ID', String(booking._id)]])}
          <p style="margin-top:20px;">Please ensure compliance with RebuZZar’s seller policies to avoid future disruptions.</p>
          <p>— <b>RebuZZar Seller Compliance Team</b></p>`,
      }),
    },
    {
      label: 'product-removed-booked (admin)',
      to: adminTo(),
      subject: 'Booked product removed by seller | RebuZZar Admin',
      html: shell({
        headerBg: '#343a40', title: 'RebuZZar Admin Alert', pad: 32, maxWidth: 700,
        body: `
          <h3>🚨 Policy Impact Event</h3>
          ${table([
            ['Seller', `${seller.name} (${seller.email})`],
            ['Buyer', `${buyer && buyer.name} (${buyer && buyer.email})`],
            ['Product', product.title], ['Order ID', String(booking._id)], ['Action', 'Deleted after booking'],
          ])}
          <p style="margin-top:20px;">Administrative review may be required.</p>
          <p>— <b>RebuZZar System</b></p>`,
      }),
    },
  ];
};

module.exports = {
  buildProductSubmitted,
  buildProductReviewed,
  buildProductRemoved,
  // Notification senders: independent, never throw, never fail the request.
  notifyProductSubmitted: (args) => dispatch(buildProductSubmitted(args)),
  notifyProductReviewed: (args) => dispatch(buildProductReviewed(args)),
  notifyProductRemoved: (args) => dispatch(buildProductRemoved(args)),
};
