import mongoose from 'mongoose';

const demoRequestSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
    },
    phone: {
      type: String,
      required: true,
      trim: true,
    },
    company: {
      type: String,
      required: true,
      trim: true,
    },
    role: {
      type: String,
      required: true,
      trim: true,
    },
    interests: {
      type: [String],
      default: [],
    },
    message: {
      type: String,
      default: '',
    },
    status: {
      type: String,
      enum: ['new', 'contacted', 'scheduled', 'completed', 'cancelled'],
      default: 'new',
    },
    source: {
      type: String,
      default: 'website',
    },
    metadata: {
      priority: {
        type: String,
        enum: ['low', 'medium', 'high'],
        default: 'medium',
      },
      scheduledDate: Date,
      notes: String,
    },
  },
  {
    timestamps: true, // Adds createdAt and updatedAt automatically
  }
);

// Create indexes for better query performance
demoRequestSchema.index({ email: 1 });
demoRequestSchema.index({ createdAt: -1 });
demoRequestSchema.index({ status: 1 });

const DemoRequest = mongoose.models.DemoRequest || mongoose.model('DemoRequest', demoRequestSchema);

export default DemoRequest;
