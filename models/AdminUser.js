import mongoose from 'mongoose';

// Check if model exists before defining it
let AdminUser;

try {
  // Try to get the existing model
  AdminUser = mongoose.model('AdminUser');
} catch (e) {
  // If model doesn't exist, define it
  const adminUserSchema = new mongoose.Schema(
    {
      name: { type: String, required: true, trim: true },
      email: {
        type: String,
        required: true,
        lowercase: true,
        unique: true,
        trim: true,
      },
      passwordHash: { type: String, required: true },
      role: {
        type: String,
        enum: ['super_admin', 'hr_mode', 'business_mode'],
        default: 'super_admin',
      },
      location: { type: String, default: '' },
      color: { type: String, default: '#3B82F6' },
      isActive: { type: Boolean, default: true },
    },
    { timestamps: true }
  );

  // Add indexes
  adminUserSchema.index({ email: 1 }, { unique: true });
  adminUserSchema.index({ role: 1 });

  AdminUser = mongoose.model('AdminUser', adminUserSchema);
}

export default AdminUser;
