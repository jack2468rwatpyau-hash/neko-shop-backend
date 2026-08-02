const mongoose = require('mongoose');

const reviewSchema = new mongoose.Schema({
  product_id: { type: Number, required: true, index: true },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  order_id: { type: String, required: true }, // proof of purchase
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: { type: String, default: '', trim: true, maxlength: 500 },
  images: { type: [String], default: [] }, // Cloudinary URLs
  created_at: { type: Date, default: Date.now },
});

reviewSchema.set('toJSON', {
  transform: (doc, ret) => {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

module.exports = mongoose.model('Review', reviewSchema);
