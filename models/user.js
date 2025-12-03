// backend/models/user.js
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

// Check if model already exists
let User;
try {
  User = mongoose.model('User');
} catch {
  const userSchema = new mongoose.Schema({
    name: { 
      type: String, 
      required: [true, 'Name is required'], 
      trim: true 
    },
    email: { 
      type: String, 
      required: [true, 'Email is required'], 
      unique: true, 
      trim: true, 
      lowercase: true,
      match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address']
    },
    password: { 
      type: String, 
      required: [true, 'Password is required'],
      minlength: [6, 'Password must be at least 6 characters long']
    },
    role: { 
      type: String, 
      enum: {
        values: ['admin', 'manager', 'user'],
        message: 'Role must be either admin, manager, or user'
      }, 
      default: 'user' 
    },
    location: { 
      type: String, 
      default: '' 
    },
    color: { 
      type: String, 
      default: '#3B82F6' 
    },
    isActive: { 
      type: Boolean, 
      default: true 
    },
    lastLogin: { 
      type: Date 
    },
    isSocialLogin: { 
      type: Boolean, 
      default: false 
    }
  }, { 
    timestamps: true,
    toJSON: {
      transform: function(doc, ret) {
        delete ret.password;
        delete ret.__v;
        return ret;
      }
    }
  });

  // Hash password before saving
  userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
      const salt = await bcrypt.genSalt(10);
      this.password = await bcrypt.hash(this.password, salt);
      next();
    } catch (error) {
      next(error);
    }
  });

  // Method to compare password
  userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
  };

  // Create indexes
  userSchema.index({ email: 1 }, { unique: true });
  userSchema.index({ role: 1 });
  userSchema.index({ isActive: 1 });

  User = mongoose.model('User', userSchema);
}

export default User;
