const mongoose = require('mongoose');
const Product = require('./Product');

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  avatar: { type: String, default: null },
  joinDate: { type: Date, default: Date.now },
  programType: { type: String, required: true, enum: ['Diploma', 'UG', 'PG', 'PhD'] },
  department: { type: String, required: true },
  year: { type: String, required: true },
  // Used by EditProfile / Profile / Google login on the frontend. Optional and
  // without a default so existing documents are untouched (no backfill needed).
  studentCode: { type: String, trim: true },
  phoneNumber: { type: String, default: null, trim: true },
  contactPreference: { type: String, enum: ['call', 'whatsapp', 'both'], default: 'both' },

  isVerified: { type: Boolean, default: false },
  emailOTP: { type: String },
  emailOTPExpires: { type: Date },
  // OTP abuse protection (optional fields; absent on existing documents).
  emailOTPAttempts: { type: Number, default: 0 },
  emailOTPLastSentAt: { type: Date },

  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },

  role: { type: String, enum: ['student', 'admin'], default: 'student' },
}, { timestamps: true });

// Defence in depth: even if a controller forgets to serialize, secrets never leave via res.json(user).
UserSchema.set('toJSON', {
  transform: (doc, ret) => {
    delete ret.password;
    delete ret.emailOTP;
    delete ret.emailOTPExpires;
    delete ret.emailOTPAttempts;
    delete ret.emailOTPLastSentAt;
    delete ret.resetPasswordToken;
    delete ret.resetPasswordExpires;
    return ret;
  },
});

UserSchema.pre('findOneAndDelete', async function (next) {
  try {
    const user = await this.model.findOne(this.getFilter());
    if (user) {
      await Product.deleteMany({ sellerId: user._id });
    }
    next();
  } catch (error) {
    next(error);
  }
});

module.exports = mongoose.model('User', UserSchema);
