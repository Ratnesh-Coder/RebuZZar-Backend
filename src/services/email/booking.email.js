const { dispatch } = require('./email.service');
const { shell, table, date, e } = require('./layout');

const adminTo = () => process.env.ADMIN_EMAIL;

/** Group booking lines per seller so a seller with several items gets ALL of them (previously only the last was listed). */
const groupBySeller = (items) => {
  const map = new Map();
  for (const item of items) {
    const key = item.sellerEmail || String(item.sellerId || '');
    if (!map.has(key)) map.set(key, { email: item.sellerEmail, name: item.sellerName, items: [] });
    map.get(key).items.push(item);
  }
  return [...map.values()];
};

const itemsTable = (items, withPrice) => `
<table style="width:100%; border-collapse:collapse; font-size:14px;">
  <tr><td><b>Product</b></td><td><b>Quantity</b></td>${withPrice ? '<td><b>Price</b></td>' : ''}</tr>
  ${items.map((i) => `<tr><td>${e(i.title)}</td><td>${e(i.quantity)}</td>${withPrice ? `<td>₹${e(i.price)}</td>` : ''}</tr>`).join('\n  ')}
</table>`;

const buildBookingCreated = ({ buyer, booking }) => [
  {
    label: 'booking-created (buyer)',
    to: buyer.email,
    subject: 'Your order is confirmed | RebuZZar',
    html: shell({
      headerBg: '#0d6efd', title: 'RebuZZar', subtitle: 'Order Confirmation',
      footer: 'This is an automated message. Please do not reply to this email.',
      body: `
        <p>Hello <b>${e(buyer.name)}</b>,</p>
        <p>Thank you for shopping with <b>RebuZZar</b>. Your order has been <b>successfully placed</b>.</p>
        <h3 style="margin-top:25px;">📦 Order Details</h3>
        ${table([['Order ID', String(booking._id)], ['Order Date', date(booking.createdAt), true], ['Total Amount', `₹${booking.totalPrice}`], ['Status', 'Confirmed']])}
        <p style="margin-top:20px;">You can view your order details and track status from your account dashboard.</p>
        <p>We appreciate your trust in us.</p>
        <p style="margin-top:25px;">Regards,<br/><b>RebuZZar Customer Support</b></p>`,
    }),
  },
  ...groupBySeller(booking.products).map((seller) => ({
    label: 'booking-created (seller)',
    to: seller.email,
    subject: 'New order received for your product | RebuZZar',
    html: shell({
      headerBg: '#198754', title: 'RebuZZar Seller Panel', subtitle: 'New Order Notification', footer: 'Seller system notification.',
      body: `
        <p>Hello <b>${e(seller.name)}</b>,</p>
        <p>You have received a <b>new order</b> for your product.</p>
        <h3>📦 Order Information</h3>
        ${itemsTable(seller.items, true)}
        ${table([['Order ID', String(booking._id)]])}
        <p style="margin-top:20px;">Please prepare the item for fulfillment according to platform guidelines.</p>
        <p style="margin-top:25px;">Regards,<br/><b>RebuZZar Seller Support</b></p>`,
    }),
  })),
  {
    label: 'booking-created (admin)',
    to: adminTo(),
    subject: 'New order placed | RebuZZar Admin',
    html: shell({
      headerBg: '#6c757d', title: 'RebuZZar Admin Alert', footer: 'Internal notification. Do not reply.',
      body: `
        <h3>🧾 Order Summary</h3>
        ${table([
          ['Order ID', String(booking._id)], ['Buyer Name', buyer.name], ['Buyer Email', buyer.email],
          ['Total Amount', `₹${booking.totalPrice}`], ['Items', booking.products.length], ['Date', date(booking.createdAt), true],
        ])}
        <p style="margin-top:20px;">Order has been successfully recorded in the system.</p>
        <p>— RebuZZar System</p>`,
    }),
  },
];

const buildBookingCancelled = ({ buyer, booking }) => [
  {
    label: 'booking-cancelled (buyer)',
    to: buyer.email,
    subject: 'Your order has been cancelled | RebuZZar',
    html: shell({
      headerBg: '#dc3545', title: 'RebuZZar', subtitle: 'Order Cancellation', pad: 32, maxWidth: 680,
      footer: 'This is a system-generated email. Please do not reply.',
      body: `
        <p>Dear <b>${e(buyer.name)}</b>,</p>
        <p>This is to confirm that your order has been <b>successfully cancelled</b> as per your request.</p>
        <h3 style="margin-top:24px;">🧾 Order Summary</h3>
        ${table([['Order ID', String(booking._id)], ['Order Status', 'Cancelled'], ['Total Amount', `₹${booking.totalPrice}`]])}
        <p style="margin-top:20px;">If any refund is applicable, it will be processed to your original payment method as per RebuZZar’s refund policy.</p>
        <p>You can view order details anytime from your account dashboard.</p>
        <p style="margin-top:28px;">Sincerely,<br/><b>RebuZZar Customer Support</b></p>`,
    }),
  },
  ...groupBySeller(booking.products).map((seller) => ({
    label: 'booking-cancelled (seller)',
    to: seller.email,
    subject: 'Order cancelled for your product | RebuZZar',
    html: shell({
      headerBg: '#ffc107', headerColor: '#000', title: 'RebuZZar Seller Panel', subtitle: 'Order Cancellation Notice', pad: 32, maxWidth: 680,
      footer: 'Seller system notification.',
      body: `
        <p>Dear <b>${e(seller.name)}</b>,</p>
        <p>We would like to inform you that the following order has been <b>cancelled by the buyer</b>.</p>
        <h3 style="margin-top:24px;">📦 Order Details</h3>
        ${table([['Order ID', String(booking._id)]])}
        ${itemsTable(seller.items, false)}
        <p style="margin-top:20px;">No further action is required from your side. Inventory has been updated automatically.</p>
        <p style="margin-top:28px;">Regards,<br/><b>RebuZZar Seller Support</b></p>`,
    }),
  })),
  {
    label: 'booking-cancelled (admin)',
    to: adminTo(),
    subject: 'Order cancelled | RebuZZar Admin',
    html: shell({
      headerBg: '#6c757d', title: 'RebuZZar Admin Alert', pad: 32, maxWidth: 680, footer: 'Internal administrative notification.',
      body: `
        <h3>🧾 Cancellation Summary</h3>
        ${table([['Order ID', String(booking._id)], ['Buyer Name', buyer.name], ['Buyer Email', buyer.email], ['Total Amount', `₹${booking.totalPrice}`], ['Status', 'Cancelled']])}
        <p style="margin-top:20px;">The order has been cancelled and inventory has been restored.</p>
        <p>— <b>RebuZZar System</b></p>`,
    }),
  },
];

module.exports = {
  buildBookingCreated,
  buildBookingCancelled,
  groupBySeller,
  notifyBookingCreated: (args) => dispatch(buildBookingCreated(args)),
  notifyBookingCancelled: (args) => dispatch(buildBookingCancelled(args)),
};
