import mongoose from 'mongoose';
import { connectLeadsDB } from '../config/database.js';

// Create schema using mongoose
const leadSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [100, 'Name cannot be longer than 100 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    trim: true,
    lowercase: true,
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please enter a valid email address']
  },
  phone: {
    type: String,
    required: [true, 'Phone number is required'],
    trim: true,
    match: [/^[\+\d\s\(\)\-]{7,20}$/, 'Please enter a valid phone number']
  },
  company: {
    type: String,
    trim: true,
    default: '',
    maxlength: [200, 'Company name cannot be longer than 200 characters']
  },
  role: {
    type: String,
    trim: true,
    default: '',
    maxlength: [100, 'Role cannot be longer than 100 characters']
  },
  interests: {
    type: [String],
    // Make interests optional so leads created from job applications
    // are valid even if they don't provide interests
    validate: {
      validator: function(v) {
        // Allow undefined/null or an empty array
        if (v === undefined || v === null) return true;
        return Array.isArray(v);
      },
      message: 'Interests must be an array of strings'
    }
  },
  message: {
    type: String,
    trim: true,
    default: '',
    maxlength: [2000, 'Message cannot be longer than 2000 characters']
  },
  notes: {
    type: String,
    trim: true,
    default: ''
  },
  source: {
    type: String,
    default: 'website',
    trim: true,
    lowercase: true,
    validate: {
      validator: function(v) {
        // Allow any non-empty string, but normalize common values
        if (!v || typeof v !== 'string' || v.trim() === '') {
          return false;
        }
        return true;
      },
      message: 'Source is required and must be a non-empty string'
    },
    set: function(v) {
      // Normalize common source values
      if (!v) return 'website';
      const val = v.toString().toLowerCase().trim();
      
      // Map common variations to standard values
      const sourceMap = {
        'web': 'website',
        'site': 'website',
        'form': 'website',
        'rest': 'api',
        'restapi': 'api',
        'rest-api': 'api',
        'csv': 'import',
        'excel': 'import',
        'spreadsheet': 'import',
        'manual': 'manual',
        'admin': 'manual',
        'dashboard': 'manual'
      };
      
      return sourceMap[val] || val;
    }
  },
  status: {
    type: String,
    default: 'new',
    enum: {
      values: ['new', 'contacted', 'qualified', 'unqualified', 'converted', 'archived'],
      message: 'Invalid status'
    }
  },
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed,
    default: {}
  },
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Indexes
leadSchema.index({ email: 1 }, { unique: true });
leadSchema.index({ status: 1 });
leadSchema.index({ createdAt: -1 });

// Static method to get leads by status
leadSchema.statics.getLeadsByStatus = async function(status) {
  return this.aggregate([
    { $match: { status } },
    { $sort: { createdAt: -1 } },
    {
      $project: {
        name: 1,
        email: 1,
        phone: 1,
        company: 1,
        status: 1,
        createdAt: 1,
        interests: 1
      }
    }
  ]);
};

// Pre-save hooks
leadSchema.pre('save', function(next) {
  // Ensure interests is an array
  if (this.interests && !Array.isArray(this.interests)) {
    this.interests = [this.interests];
  }
  
  // Set submittedAt if not set
  if (!this.metadata.submittedAt) {
    this.metadata = this.metadata || {};
    this.metadata.submittedAt = new Date();
  }
  
  next();
});

// Create the model
let Lead;

try {
  // Try to get the model if it exists
  Lead = mongoose.model('Lead');
} catch (e) {
  // If it doesn't exist, create it
  Lead = mongoose.model('Lead', leadSchema);
}

export default Lead;
