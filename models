const mongoose = require('mongoose');
const validator = require('validator');

// One entry per (product, category) the customer has looked at, used by the
// recommendation engine to score what to show them first on their next visit.
const viewHistorySchema = new mongoose.Schema(
  {
    productId: { type: Number, required: true },
    category: { type: String, default: '' },
    score: { type: Number, default: 1 },
    lastViewedAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    validate: { validator: (v) => validator.isEmail(v), message: 'Invalid email address.' },
  },
  phone: {
    type: String,
    trim: true,
    default: '',
    validate: {
      validator: (v) => !v || validator.isMobilePhone(v, 'any', { strictMode: false }),
      message: 'Invalid phone number.',
    },
  },
  name: { type: String, trim: true, default: '' },
  // Hashed with bcryptjs before saving — see server.js. Optional because
  // Google-OAuth-only accounts never set a local password.
  password: { type: String, select: false },
  googleId: { type: String, default: null, index: true },
  customer_number: { type: Number },
  isBlocked: { type: Boolean, default: false },
  role: { type: String, enum: ['customer', 'admin'], default: 'customer' },
  viewHistory: { type: [viewHistorySchema], default: [] },
  created_at: { type: Date, default: Date.now },
});

// Legacy code across the app expects a plain `id` (matching the old
// data.json numeric ids) — expose Mongo's _id as a string under `id` too,
// so JWT payloads / API responses stay compatible with existing frontend code.
userSchema.set('toJSON', {
  virtuals: true,
  transform: (doc, ret) => {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    delete ret.password;
    return ret;
  },
});

module.exports = mongoose.model('User', userSchema);
