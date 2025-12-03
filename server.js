// server.js
import dotenv from 'dotenv';
import express from "express";
import { createServer } from 'http';
import mongoose from "mongoose";
import DemoRequest from './models/DemoRequest.js';
import cors from "cors";
import path from 'path';
import { promises as fs } from 'fs';
import multer from 'multer';
import bcrypt from "bcrypt";
import { fileURLToPath } from 'url';
import { dirname } from 'path';

import Submission from './models/Submission.js';
import { initWebSocket, getWebSocketService } from './services/websocket.js';

// --- ES MODULE __dirname ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// --- ENV SETUP ---
dotenv.config({ path: path.join(__dirname, '.env') });

if (!process.env.MONGODB_URI) {
  console.error("ERROR: MONGODB_URI environment variable not set.");
  process.exit(1);
}

// --- EXPRESS + HTTP SERVER ---
const app = express();
const server = createServer(app);

// --- WEBSOCKET ---
initWebSocket(server);

// --- FILE UPLOAD (MULTER) ---
const uploadsDir = path.join(__dirname, 'uploads');

const initializeUploadsDir = async () => {
  try {
    await fs.access(uploadsDir);
  } catch (error) {
    if (error.code === 'ENOENT') {
      await fs.mkdir(uploadsDir, { recursive: true });
      console.log(`Created uploads directory at: ${uploadsDir}`);
    }
  }
};
initializeUploadsDir().catch(console.error);

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const filetypes = /pdf|doc|docx/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = filetypes.test(file.mimetype);
  if (mimetype && extname) cb(null, true);
  else cb(new Error('Only PDF, DOC, and DOCX files are allowed!'));
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// --- CORS ---
const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, true);

    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:5001',
      'http://localhost:3001',
      'https://your-production-frontend-url.com'
    ];

    if (
      process.env.NODE_ENV === 'development' ||
      allowedOrigins.some(allowedOrigin =>
        origin === allowedOrigin ||
        origin.startsWith(allowedOrigin.replace('*', ''))
      )
    ) {
      return callback(null, true);
    }

    console.log('CORS blocked for origin:', origin);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  exposedHeaders: ['Content-Disposition'],
  optionsSuccessStatus: 200,
  preflightContinue: false,
  maxAge: 600
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // preflight

// --- BODY PARSERS ---
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const jsonParser = express.json({ limit: '10mb' });
const urlencodedParser = express.urlencoded({ extended: true, limit: '10mb' });

const shouldSkipBodyParsing = (req) => {
  const contentType = req.headers['content-type'] || '';
  return contentType.startsWith('multipart/form-data');
};

app.use((req, res, next) => {
  if (shouldSkipBodyParsing(req)) return next();
  return jsonParser(req, res, next);
});

app.use((req, res, next) => {
  if (shouldSkipBodyParsing(req)) return next();
  return urlencodedParser(req, res, next);
});

// --- LOGGING ---
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    console.log('Body:', req.body);
  }
  next();
});

// --- STATIC FILES ---
app.set('trust proxy', 1);
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  setHeaders: (res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  }
}));

// --- MONGODB CONNECTIONS ---
const connectDB = async () => {
  try {
    console.log('=== Starting MongoDB Connection ===');
    
    // Connect to main database
    console.log('Connecting to main MongoDB...');
    console.log('URI:', process.env.MONGODB_URI.replace(/:[^:@]+@/, ':****@')); // Hide password
    
    await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    
    console.log('✓ Successfully connected to main MongoDB');
    console.log('Main DB Name:', mongoose.connection.db.databaseName);

    // Check if leads MongoDB URI is provided
    if (!process.env.LEADS_MONGODB_URI) {
      console.warn('⚠ LEADS_MONGODB_URI not set, using main database for demo requests');
      
      // Register DemoRequest model on main connection if not already registered
      if (!mongoose.models.DemoRequest) {
        try {
          // Make sure the model is registered with the correct schema
          const DemoRequestSchema = DemoRequest.schema || new mongoose.Schema({
            name: String,
            email: String,
            phone: String,
            company: String,
            role: String,
            interests: [String],
            message: String,
            source: { type: String, default: 'website' }
          }, { timestamps: true });
          
          mongoose.model('DemoRequest', DemoRequestSchema);
          console.log('✓ DemoRequest model registered on main database');
        } catch (modelError) {
          console.error('Error registering DemoRequest model:', modelError.message);
        }
      }
      
      return;
    }

    // Connect to leads database
    console.log('Connecting to leads MongoDB...');
    console.log('Leads URI:', process.env.LEADS_MONGODB_URI.replace(/:[^:@]+@/, ':****@'));
    
    const leadsConnection = mongoose.createConnection(process.env.LEADS_MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });

    // Wait for leads connection
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Leads database connection timeout after 10 seconds'));
      }, 10000);

      leadsConnection.on('connected', () => {
        clearTimeout(timeout);
        console.log('✓ Successfully connected to leads MongoDB');
        console.log('Leads DB Name:', leadsConnection.db.databaseName);
        resolve();
      });

      leadsConnection.on('error', (err) => {
        clearTimeout(timeout);
        console.error('❌ Leads MongoDB connection error:', err.message);
        reject(err);
      });
    });

    // Register DemoRequest model on leads connection
    try {
      // Define the schema for the leads database
      const DemoRequestSchema = new mongoose.Schema({
        name: { type: String, required: true },
        email: { type: String, required: true, lowercase: true },
        phone: { type: String, required: true },
        company: { type: String, required: true },
        role: { type: String, required: true },
        interests: { 
          type: [String], 
          required: true,
          validate: {
            validator: function(v) {
              return v && v.length > 0;
            },
            message: 'At least one interest is required'
          }
        },
        message: String,
        source: { type: String, default: 'website' },
        status: { type: String, default: 'new' }
      }, { 
        timestamps: true,
        collection: 'demo_requests' 
      });
      
      // Create the model for the leads database
      const DemoRequestLeads = leadsConnection.model('DemoRequest', DemoRequestSchema);
      global.DemoRequestLeads = DemoRequestLeads;
      
      console.log('✓ DemoRequest model registered on leads database');
      console.log('Collection name:', DemoRequestLeads.collection.name);
    } catch (modelError) {
      console.error('❌ Error registering DemoRequest model on leads DB:', modelError.message);
      // Don't throw the error to allow the server to start
      console.warn('⚠️ Continuing with main database for demo requests');
    }

    console.log('=== Database Connections Complete ===');

  } catch (error) {
    console.error('❌ FATAL: Error initializing database connections');
    console.error('Error:', error.message);
    console.error('Stack:', error.stack);
    
    // Don't exit in development, allow fallback to main DB
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    } else {
      console.warn('⚠ Continuing in development mode with main database only');
    }
  }
};

// Call connectDB
connectDB();

// --- SCHEMAS & MODELS ---

// Job Application
const JobApplicationSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true, lowercase: true },
  phone: { type: String, required: true, trim: true },
  position: { type: String, required: true },
  experience: { type: String },
  currentCompany: { type: String },
  expectedSalary: { type: Number },
  noticePeriod: { type: String },
  coverLetter: { type: String },
  source: { type: String },
  resumePath: { type: String },
  createdAt: { type: Date, default: Date.now }
});
const JobApplication = mongoose.models.JobApplication || mongoose.model('JobApplication', JobApplicationSchema);

// Old contact user
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, lowercase: true },
  phone: { type: String, required: true },
  company: String,
  role: String,
  interestedIn: [String],
  message: String,
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model("User", userSchema);

// Admin login account
const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const Admin = mongoose.model("Admin", adminSchema);

// Admin panel users for /api/users
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
  },
  { timestamps: true }
);

const AdminUser =
  mongoose.models.AdminUser || mongoose.model('AdminUser', adminUserSchema);

// --- BASIC ROUTES ---
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Server is running',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

app.get('/api/ping', (req, res) => {
  res.status(200).json({ message: 'pong' });
});

// --- USER MANAGEMENT ROUTES (for frontend /api/users) ---

// GET /api/users
app.get('/api/users', async (req, res) => {
  try {
    const users = await AdminUser.find().sort({ createdAt: -1 });
    const safeUsers = users.map(u => {
      const obj = u.toObject();
      delete obj.passwordHash;
      return obj;
    });
    res.json({ success: true, data: safeUsers });
  } catch (err) {
    console.error('Error fetching admin users:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch users' });
  }
});

// POST /api/users
app.post('/api/users', async (req, res) => {
  try {
    const { name, email, password, role, location, color } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ success: false, message: 'Name, email, password required' });
    }

    const existing = await AdminUser.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res
        .status(400)
        .json({ success: false, message: 'User with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await AdminUser.create({
      name,
      email: email.toLowerCase(),
      passwordHash,
      role: role || 'super_admin',
      location: location || '',
      color: color || '#3B82F6',
    });

    const { passwordHash: _, ...safeUser } = user.toObject();

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: safeUser,
    });
  } catch (err) {
    console.error('Error creating admin user:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to create user',
      error: err.message,
    });
  }
});

// --- JOB APPLICATIONS (file upload) ---
app.post('/api/job-applications', (req, res) => {
  upload.single('resume')(req, res, async (err) => {
    if (err) {
      console.error('Multer File Upload Error:', err);
      return res.status(400).json({
        success: false,
        message: 'File upload failed',
        error: err.message,
      });
    }

    try {
      if (!req.body.fullName || !req.body.email || !req.body.phone) {
        throw new Error('Required fields missing: Full Name, Email, or Phone is empty.');
      }

      const resumePath = req.file ? `/uploads/${req.file.filename}` : '';

      const application = new JobApplication({
        fullName: req.body.fullName,
        email: req.body.email,
        phone: req.body.phone,
        position: req.body.position || 'Not Specified',
        experience: req.body.experience,
        currentCompany: req.body.currentCompany,
        expectedSalary: req.body.expectedSalary,
        noticePeriod: req.body.noticePeriod,
        coverLetter: req.body.coverLetter,
        source: req.body.source || 'Career Portal',
        resumePath,
      });

      await application.save();

      try {
        const wss = getWebSocketService && getWebSocketService();
        if (wss && typeof wss.broadcast === 'function') {
          wss.broadcast('new_application', application);
        }
      } catch (wsError) {
        console.log('WebSocket notification skipped:', wsError.message);
      }

      res.status(201).json({
        success: true,
        message: 'Application submitted successfully',
        data: application,
      });
    } catch (error) {
      console.error('Job application error:', error);
      res.status(400).json({
        success: false,
        message: 'Submission Failed',
        error: error.message,
      });
    }
  });
});

app.get('/api/job-applications', async (req, res) => {
  try {
    const applications = await JobApplication.find().sort({ createdAt: -1 });
    res.json({ success: true, data: applications });
  } catch (error) {
    console.error('Error fetching job applications:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch applications' });
  }
});

// --- DEMO REQUESTS ---
// DemoRequest is already imported at the top of the file

app.post('/api/demo-requests', async (req, res) => {
  console.log('=== Demo Request Received ===');
  console.log('Request body:', JSON.stringify(req.body, null, 2));
  
  // Log database connection state
  console.log('Mongoose connection state:', mongoose.connection.readyState);
  console.log('Mongoose models:', Object.keys(mongoose.models));
  
  try {
    // Validate required fields
    const requiredFields = ['name', 'email', 'phone', 'company', 'role'];
    const missingFields = requiredFields.filter(field => !req.body[field]);
    
    if (missingFields.length > 0) {
      const errorMsg = `Missing required fields: ${missingFields.join(', ')}`;
      console.error('Validation error:', errorMsg);
      return res.status(400).json({
        success: false,
        message: errorMsg,
        receivedFields: Object.keys(req.body)
      });
    }
    
    // Extract fields from request body
    const { name, email, phone, company, role, interests = [], message, source } = req.body;
    
    // Process interests to ensure it's an array
    const interestsArray = Array.isArray(interests) 
      ? interests 
      : (interests ? [interests] : []);
    
    console.log('Processed interests:', interestsArray);
    
    // Prepare the document to save
    const demoRequestData = {
      name: name.trim(),
      email: email.trim().toLowerCase(),
      phone: phone.trim(),
      company: company.trim(),
      role: role.trim(),
      interests: interestsArray,
      message: message ? message.trim() : '',
      status: 'new',
      source: source || 'website_demo',
      metadata: {
        priority: 'medium',
        submittedAt: new Date()
      }
    };
    
    console.log('Attempting to save demo request:', JSON.stringify(demoRequestData, null, 2));
    
    // Save to database using the imported model
    console.log('Creating demo request document...');
    
    // Use insertOne directly on the model's collection to avoid any session/transaction issues
    const result = await mongoose.connection.db.collection('demorequests').insertOne(demoRequestData);
    
    if (!result.acknowledged || !result.insertedId) {
      throw new Error('Failed to save demo request: No acknowledgment from database');
    }
    
    console.log('Demo request saved successfully with ID:', result.insertedId);
    
    // Get the saved document
    const savedRequest = await mongoose.connection.db.collection('demorequests').findOne({ _id: result.insertedId });
    
    // Try to broadcast via WebSocket if available
    if (getWebSocketService) {
      try {
        const wss = getWebSocketService();
        if (wss && typeof wss.broadcast === 'function') {
          wss.broadcast('new_demo_request', savedRequest);
          console.log('WebSocket broadcast sent');
        }
      } catch (wsError) {
        console.error('WebSocket broadcast failed (non-fatal):', wsError.message);
        // Don't fail the request if WebSocket fails
      }
    }
    
    return res.status(201).json({
      success: true,
      message: 'Demo request submitted successfully',
      data: savedRequest
    });
    
  } catch (error) {
    console.error('=== DEMO REQUEST ERROR ===');
    console.error('Error:', error.message);
    console.error('Error stack:', error.stack);
    console.error('Error name:', error.name);
    
    // Check for MongoDB validation errors
    if (error.name === 'ValidationError') {
      console.error('Validation errors:', error.errors);
      return res.status(400).json({
        success: false,
        message: 'Validation failed: ' + Object.values(error.errors).map(e => e.message).join(', '),
        error: error.message,
        errors: error.errors
      });
    }
    
    // Check for MongoDB duplicate key error
    if (error.code === 11000) {
      console.error('Duplicate key error:', error.keyValue);
      return res.status(400).json({
        success: false,
        message: 'Duplicate entry',
        field: Object.keys(error.keyValue || {})[0],
        value: Object.values(error.keyValue || {})[0]
      });
    }
    
    // Generic error response
    return res.status(500).json({
      success: false,
      message: 'Failed to process demo request',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
      ...(process.env.NODE_ENV === 'development' && { 
        stack: error.stack,
        errorType: error.name 
      })
    });
  }
});

// --- BUSINESS LEADS ---
app.post('/api/business-leads', async (req, res) => {
  try {
    const { name, email, phone, company, role, interests, message, source } = req.body;

    const submission = new Submission({
      name,
      email,
      phone,
      company: company || '',
      role: role || '',
      interests: Array.isArray(interests) ? interests : [interests].filter(Boolean),
      message: message || '',
      source: source || 'website',
      status: 'new',
      metadata: {
        priority: 'medium',
        value: 0,
        submittedAt: new Date(),
      },
    });

    const savedSubmission = await submission.save();

    const wsService = getWebSocketService();
    if (wsService) {
      wsService.broadcast('new_lead', savedSubmission);
    }

    res.status(201).json({
      success: true,
      message: 'Form submitted successfully',
      data: savedSubmission,
    });
  } catch (error) {
    console.error('Error submitting form:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit form',
      error: error.message,
    });
  }
});

app.get('/api/business-leads', async (req, res) => {
  try {
    const leads = await Submission.find({}).sort({ createdAt: -1 });
    res.status(200).json({
      success: true,
      count: leads.length,
      data: leads,
    });
  } catch (error) {
    console.error('Error fetching leads:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch leads',
      error: error.message,
    });
  }
});

// --- CONTACT FORM /api/submit ---
app.post('/api/submit', async (req, res) => {
  try {
    const { name, email, phone, company, role, interestedIn, message } = req.body;

    if (!name || !email || !phone) {
      return res.status(400).json({
        success: false,
        message: 'Name, Email, Phone required.',
      });
    }

    const submission = new Submission({
      name,
      email,
      phone,
      company,
      role,
      interests: Array.isArray(interestedIn) ? interestedIn : [interestedIn],
      message,
      source: 'website-form',
      status: 'new',
    });

    const savedSubmission = await submission.save();

    const wss = getWebSocketService();
    if (wss && typeof wss.broadcastNewSubmission === 'function') {
      wss.broadcastNewSubmission(savedSubmission);
    }

    res.status(201).json({
      success: true,
      message: 'Submitted successfully!',
      data: savedSubmission,
    });
  } catch (error) {
    console.error('Error submitting form:', error);
    res.status(500).json({
      success: false,
      message: 'Submission failed',
      error: error.message,
    });
  }
});

// --- ADMIN LOGIN /api/admin/login ---
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username: username?.toLowerCase() });

    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = `atorix_dashboard_${Date.now()}_${Buffer.from(username).toString('base64')}`;
    res.status(200).json({ success: true, token, message: 'Login successful' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// --- DEFAULT ADMIN SEED ---
async function initializeAdmin() {
  try {
    if (await Admin.countDocuments() === 0) {
      const hashedPassword = await bcrypt.hash('Noopur123', 10);
      await new Admin({ username: 'Noopur', password: hashedPassword }).save();
      console.log('Default admin user created.');
    }
  } catch (error) {
    console.error('Admin init error:', error);
  }
}
initializeAdmin();

// --- GET DEMO REQUESTS ---
app.get('/api/demo-requests', async (req, res) => {
  try {
    let requests;
    
    if (global.DemoRequestLeads) {
      requests = await global.DemoRequestLeads.find().sort({ createdAt: -1 }).limit(50);
    } else {
      const DemoRequestMain = mongoose.model('DemoRequest');
      requests = await DemoRequestMain.find().sort({ createdAt: -1 }).limit(50);
    }
    
    res.json({ 
      success: true, 
      count: requests.length,
      data: requests 
    });
  } catch (error) {
    console.error('Error fetching demo requests:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch demo requests',
      error: error.message 
    });
  }
});

// --- GLOBAL ERROR HANDLER ---
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err);
  if (err.name === 'MulterError') {
    return res.status(400).json({ success: false, message: `File upload error: ${err.message}` });
  }
  res.status(500).json({ success: false, message: err.message || 'Internal server error' });
});

// --- START SERVER ---
const PORT = process.env.PORT || 5001;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});