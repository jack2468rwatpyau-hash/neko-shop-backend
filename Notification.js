const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  order_id: { type: String, required: true },
  status: { type: String, required: true },
  message: { type: String, required: true },
  read: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now },
});

notificationSchema.set('toJSON', {
  transform: (doc, ret) => {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

module.exports = mongoose.model('Notification', notificationSchema);
