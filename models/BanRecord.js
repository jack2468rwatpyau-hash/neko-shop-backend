const mongoose = require('mongoose');

const banRecordSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  reason: { type: String, required: true, trim: true },
  banned_by: { type: String, default: 'admin' },
  status: { type: String, enum: ['active', 'appealed', 'lifted'], default: 'active' },
  created_at: { type: Date, default: Date.now, expires: 60 * 60 * 24 * 30 }, // TTL: auto-delete after 30 days
});

banRecordSchema.set('toJSON', {
  transform: (doc, ret) => {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

module.exports = mongoose.model('BanRecord', banRecordSchema);
