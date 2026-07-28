const mongoose = require('mongoose');

const orderItemSchema = new mongoose.Schema(
  {
    productId: Number,
    name: String,
    price: Number,
    qty: Number,
    size: String,
    color: String,
    product_number: Number,
    item_id: String,
    letter_code: String,
    variant_code: String,
    estimated_delivery: String,
  },
  { _id: false }
);

const orderSchema = new mongoose.Schema({
  order_id: { type: String, required: true, unique: true },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  customer_name: { type: String, required: true, trim: true },
  phone: { type: String, required: true, trim: true },
  address: { type: String, required: true, trim: true },
  payment_method: { type: String, required: true },
  customer_notes: { type: String, default: '' },
  items: { type: [orderItemSchema], required: true },
  total_amount: { type: Number, required: true },
  receipt_image: { type: String, default: null },
  status: { type: String, enum: ['pending', 'approved', 'shipped', 'cancelled'], default: 'pending' },
  created_at: { type: Date, default: Date.now },
});

orderSchema.set('toJSON', {
  transform: (doc, ret) => {
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

module.exports = mongoose.model('Order', orderSchema);
