// Sanity limits shared by cart and booking validation.
module.exports = {
  MAX_ITEM_QUANTITY: 100, // per line item
  MAX_BOOKING_ITEMS: 20, // distinct products per booking
};
