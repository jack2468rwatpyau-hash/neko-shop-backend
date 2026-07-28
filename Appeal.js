const mongoose = require('mongoose');

const appealSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  ban_id: { type: mongoose.Schema.Types.ObjectId, ref: 'BanRecord', required: true },
  message: { type: String, required: true, trim: true, maxlength: 1000 },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  created_at: { type: Date, default: Date.now, expires: 60 * 60 * 24 * 30 }, // TTL: auto-delete after 30 days
});

appealSchema.set('toJSON', {
  transform: (doc, ret) => {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

module.exports = mongoose.model('Appeal', appealSchema);
