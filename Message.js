const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  sender: { type: String, enum: ['customer', 'admin'], required: true },
  text: { type: String, required: true, trim: true, maxlength: 2000 },
  read_by_admin: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now },
});

messageSchema.set('toJSON', {
  transform: (doc, ret) => {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

module.exports = mongoose.model('Message', messageSchema);
