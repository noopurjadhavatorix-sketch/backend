import mongoose from 'mongoose';

const blogPostSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true
  },
  slug: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  content: {
    type: String,
    required: [true, 'Content is required']
  },
  category: {
    type: String,
    required: [true, 'Category is required']
  },
  subcategory: {
    type: String,
    default: 'Article'
  },
  authorName: {
    type: String,
    required: [true, 'Author name is required']
  },
  status: {
    type: String,
    enum: ['draft', 'published', 'archived'],
    default: 'draft'
  },
  tags: [{
    type: String,
    trim: true
  }],
  keywords: [{
    type: String,
    trim: true
  }],
  featuredImage: {
    url: String,
    publicId: String
  },
  bannerImage: {
    url: String,
    publicId: String
  },
  views: {
    type: Number,
    default: 0
  },
  seoDescription: String,
  seoKeywords: String
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Create text index for search
blogPostSchema.index({
  title: 'text',
  content: 'text',
  tags: 'text',
  keywords: 'text'
});

// Generate slug from title if not provided
blogPostSchema.pre('save', function(next) {
  if (!this.slug && this.title) {
    this.slug = this.title
      .toLowerCase()
      .replace(/[^\w\s-]/g, '') // remove special chars
      .replace(/\s+/g, '-') // replace spaces with -
      .replace(/--+/g, '-') // replace multiple - with single -
      .trim();
  }
  next();
});

export default mongoose.model('BlogPost', blogPostSchema);
