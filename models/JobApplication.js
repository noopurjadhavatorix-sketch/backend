import mongoose from 'mongoose';

const jobApplicationSchema = new mongoose.Schema({
  // Personal Information
  fullName: {
    type: String,
    required: [true, 'Full name is required'],
    trim: true
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    lowercase: true,
    trim: true
  },
  phone: {
    type: String,
    required: [true, 'Phone is required'],
    trim: true
  },
  
  // Position Details
  position: {
    type: String,
    required: [true, 'Position is required']
  },
  experience: {
    type: String,
    default: ''
  },
  currentCompany: {
    type: String,
    default: ''
  },
  expectedSalary: {
    type: Number,
    default: null
  },
  noticePeriod: {
    type: String,
    default: ''
  },
  coverLetter: {
    type: String,
    default: ''
  },
  startDate: {
    type: Date,
    default: null
  },
  
  // Education & Experience
  education: {
    type: String,
    default: ''
  },
  skills: {
    type: [String],
    default: []
  },
  
  // Resume file path
  resumePath: {
    type: String,
    default: ''
  },
  
  // Source of application
  source: {
    type: String,
    default: 'Career Portal',
    trim: true
  },
  
  // Status
  status: {
    type: String,
    enum: ['applied', 'review', 'interview', 'hired', 'rejected'],
    default: 'applied'
  },
  
  // Timestamps
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { 
  timestamps: true,
  // Add text indexes for search
  autoIndex: true
});

// Create indexes for search
jobApplicationSchema.index({ fullName: 'text', email: 'text', position: 'text' });

// Use existing model if it exists, otherwise create a new one
const JobApplication = mongoose.models.JobApplication || mongoose.model('JobApplication', jobApplicationSchema);

export default JobApplication;
