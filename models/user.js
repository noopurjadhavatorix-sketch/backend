// backend/models/user.js
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

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
    // From integrated file - username field
    username: {
      type: String,
      unique: true,
      trim: true,
      sparse: true // Allows multiple null values
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
      minlength: [6, 'Password must be at least 6 characters long'],
      select: false // From integrated file - don't select password by default
    },
    role: { 
      type: String, 
      enum: {
        values: ['admin', 'manager', 'user'], // Keep existing values
        message: 'Role must be either admin, manager, or user'
      }, 
      default: 'user' 
    },
    // From integrated file - status field
    status: {
      type: String,
      enum: ['Active', 'Inactive'],
      default: 'Active'
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
      console.error('Error hashing password:', error); // From integrated file
      next(error);
    }
  });

  // Ensure name is populated before validation/save (needed for legacy records without name)
  userSchema.pre('validate', function(next) {
    if (!this.name) {
      this.name = this.username || this.email || 'User';
    }
    next();
  });

  // Method to compare password
  userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
  };

  // From integrated file - Alternative method name for password comparison
  userSchema.methods.matchPassword = async function(enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
  };

  // From integrated file - Sign JWT and return
  userSchema.methods.getSignedJwtToken = function() {
    return jwt.sign(
      { id: this._id, role: this.role },
      process.env.JWT_SECRET || 'your_jwt_secret_key',
      { expiresIn: process.env.JWT_EXPIRE || '30d' }
    );
  };

  // Create indexes
  userSchema.index({ email: 1 }, { unique: true });
  userSchema.index({ username: 1 }, { unique: true, sparse: true }); // From integrated file
  userSchema.index({ role: 1 });
  userSchema.index({ isActive: 1 });
  userSchema.index({ status: 1 }); // From integrated file

  User = mongoose.model('User', userSchema);
}

export default User;
