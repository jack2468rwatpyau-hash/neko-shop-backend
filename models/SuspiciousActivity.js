const mongoose = require('mongoose');

const suspiciousActivitySchema = new mongoose.Schema({
  ip: { type: String, default: '' },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  field: { type: String, required: true }, // e.g. "address", "customer_notes", "phone"
  matched_pattern: { type: String, required: true },
  value_snippet: { type: String, default: '' }, // truncated, for review — never store full payloads
  created_at: { type: Date, default: Date.now },
});

suspiciousActivitySchema.set('toJSON', {
  transform: (doc, ret) => {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

module.exports = mongoose.model('SuspiciousActivity', suspiciousActivitySchema);
