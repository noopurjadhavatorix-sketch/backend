import mongoose from 'mongoose';

const submissionSchema = new mongoose.Schema({
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
    match: [/^[\+\d\s\-\(\)]{7,20}$/, 'Please enter a valid phone number']
  },
  company: {
    type: String,
    trim: true,
    default: '',
    required: [true, 'Company name is required'],
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
    required: [true, 'At least one interest is required'],
    validate: {
      validator: function(v) {
        return Array.isArray(v) && v.length > 0;
      },
      message: 'At least one interest is required'
    }
  },
  message: {
    type: String,
    trim: true,
    default: '',
    maxlength: [2000, 'Message cannot be longer than 2000 characters']
  },
  source: {
    type: String,
    required: true,
    default: 'website',
    enum: ['website', 'demo', 'contact', 'hiring', 'other']
  },
  status: {
    type: String,
    enum: ['new', 'contacted', 'qualified', 'proposal', 'closed', 'lost'],
    default: 'new'
  },
  metadata: {
    location: {
      type: String,
      default: 'N/A',
      trim: true
    },
    priority: {
      type: String,
      enum: ['high', 'medium', 'low'],
      default: 'medium'
    },
    value: {
      type: String,
      default: '$0',
      match: [/^\$?\d+(?:,\d{3})*(?:\.\d{2})?(?:[kKmMbB]?)$/, 'Please enter a valid value (e.g., $1,000 or 50K)']
    },
    lastContacted: {
      type: Date,
      default: null
    },
    notes: {
      type: [String],
      default: []
    },
    ipAddress: String,
    userAgent: String,
    referrer: String,
    submittedAt: {
      type: Date,
      default: Date.now
    }
  }
}, {
  timestamps: true
});

// Add text index for search functionality
submissionSchema.index({
  name: 'text',
  email: 'text',
  company: 'text',
  role: 'text',
  message: 'text'
});

// Add a compound index to prevent duplicate submissions within a 24-hour window
submissionSchema.index(
  { 
    email: 1, 
    company: 1, 
    'metadata.submittedAt': -1 
  },
  { 
    name: 'unique_submission',
    unique: true,
    partialFilterExpression: {
      email: { $exists: true, $ne: null },
      company: { $exists: true, $ne: '' },
      'metadata.submittedAt': { 
        $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
      }
    }
  }
);

// Static method to get leads by status
submissionSchema.statics.getLeadsByStatus = async function() {
  return this.aggregate([
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 },
        leads: { $push: '$$ROOT' }
      }
    }
  ]);
};

// Pre-save hooks
submissionSchema.pre('save', function(next) {
  // Ensure interests is an array
  if (this.interests && !Array.isArray(this.interests)) {
    this.interests = [this.interests];
  }
  
  // Trim all string fields
  const stringFields = ['name', 'email', 'phone', 'company', 'role', 'message'];
  stringFields.forEach(field => {
    if (this[field] && typeof this[field] === 'string') {
      this[field] = this[field].trim();
    }
  });
  
  // Set default metadata if not provided
  if (!this.metadata) {
    this.metadata = {};
  }
  
  // Set created date if new
  if (this.isNew) {
    this.createdAt = new Date();
  }
  
  next();
});

const Submission = mongoose.model('Submission', submissionSchema);

export default Submission;
