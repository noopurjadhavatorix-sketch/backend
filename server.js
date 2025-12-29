// server.js
import dotenv from 'dotenv';
import express from "express";
import { createServer } from 'http';
import mongoose from "mongoose";
// We will define the model inline to keep everything in one file as requested
// import DemoRequest from './models/DemoRequest.js'; 
import cors from "cors";
import path from 'path';
import { promises as fs } from 'fs';
import multer from 'multer';
import bcrypt from "bcrypt";
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// You likely have other imports like Submission.js, websocket.js. 
// If you want EVERYTHING in one file, you'd need to move those too.
// For now, I will assume Submission and websocket are external dependencies 
// that are working fine, and focus on fixing the MongoDB connection/Schema logic for DemoRequest.
import DemoRequest from './models/DemoRequest.js';
import { initWebSocket, getWebSocketService } from './services/websocket.js';
import authRoutes from './routes/auth.js';
import usersRouter from './routes/users.js';
import demoRequestsRouter from './routes/demoRequests.js';
import auditLogsRouter from './routes/auditLogs.js';

// --- ES MODULE __dirname ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// --- ENV SETUP ---
dotenv.config({ path: path.join(__dirname, '.env') });

// Single MongoDB URI for the entire application (dashboard + blog + leads)
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://dmatorixit:atorixitsaperp@cluster0.anmzzu9.mongodb.net/atorix?retryWrites=true&w=majority&appName=Cluster0';

if (!MONGODB_URI) {
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
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5001',
  'http://localhost:3001',
  'https://your-production-frontend-url.com'
];

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (process.env.NODE_ENV === 'development' || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'cache-control'],
  exposedHeaders: ['Content-Disposition'],
  credentials: true,
  optionsSuccessStatus: 200,
  preflightContinue: false,
  maxAge: 86400, // 24 hours
};

// --- MIDDLEWARE ---
// CORS
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Enable preflight for all routes

// Body parsers with appropriate limits
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Helper to skip body parsing for multipart/form-data
const shouldSkipBodyParsing = (req) => {
  const contentType = req.headers['content-type'] || '';
  return contentType.startsWith('multipart/form-data');
};

// Apply body parsing middleware conditionally
app.use((req, res, next) => {
  if (shouldSkipBodyParsing(req)) {
    return next();
  }
  
  // Parse JSON bodies
  if (req.headers['content-type']?.includes('application/json')) {
    return express.json({ limit: '50mb' })(req, res, next);
  }
  
  // Parse URL-encoded bodies
  if (req.headers['content-type']?.includes('application/x-www-form-urlencoded')) {
    return express.urlencoded({ extended: true, limit: '50mb' })(req, res, next);
  }
  
  // For other content types, continue
  next();
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

// --- MONGODB CONNECTIONS & SCHEMAS ---

// Define DemoRequest Schema locally (Single source of truth)
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
  status: { type: String, default: 'new' },
  metadata: { type: mongoose.Schema.Types.Mixed }
}, { 
  timestamps: true,
  // Explicitly naming the collection ensures both DBs use the same name
  collection: 'demo_requests' 
});


const connectDB = async () => {
  try {
    console.log('=== Starting MongoDB Connection ===');
    
    // Connect to single MongoDB database
    console.log('Connecting to MongoDB...');
    console.log('URI:', MONGODB_URI.replace(/:[^:@]+@/, ':****@')); // Hide password
    
    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    
    console.log('✓ Successfully connected to MongoDB');
    console.log('Main DB Name:', mongoose.connection.db.databaseName);

    // Register DemoRequest model on single connection
    if (!mongoose.models.DemoRequest) {
      mongoose.model('DemoRequest', DemoRequestSchema);
      console.log('✓ DemoRequest model registered on MongoDB');
    }

    console.log('=== Database Connection Complete ===');

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

// --- ROUTES ---
app.use('/api/demo-requests', demoRequestsRouter);
app.use('/api/admin', authRoutes);
app.use('/api/users', usersRouter);
app.use('/api/demo-requests', demoRequestsRouter);
app.use('/api/audit-logs', auditLogsRouter);


// --- OTHER SCHEMAS & MODELS ---

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

// Import User model from models directory
import User from './models/user.js';

// Import Admin model from models directory
import Admin from './models/Admin.js';

// Import AdminUser model from models directory
import AdminUser from './models/AdminUser.js';

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

app.post('/api/demo-requests', async (req, res) => {
  console.log('=== Demo Request Received ===');
  console.log('Request body:', JSON.stringify(req.body, null, 2));
  
  // Log database connection state
  console.log('Mongoose connection state:', mongoose.connection.readyState);
  
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
    
    // Prepare the data
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

    // determine model (Leads DB vs Main DB)
    let DemoRequestModel;
    if (global.DemoRequestLeads) {
      console.log('Using LEADS database model');
      DemoRequestModel = global.DemoRequestLeads;
    } else {
      console.log('Using MAIN database model');
      // Ensure model is registered if not using leads db
      if (mongoose.models.DemoRequest) {
         DemoRequestModel = mongoose.model('DemoRequest');
      } else {
         // Fallback schema registration just in case
         DemoRequestModel = mongoose.model('DemoRequest', DemoRequestSchema);
      }
    }

    // Create and save using the Mongoose Model
    // This ensures validation, timestamps, and correct collection/database usage
    const newRequest = new DemoRequestModel(demoRequestData);
    const savedRequest = await newRequest.save();
    
    console.log('Demo request saved successfully with ID:', savedRequest._id);
    
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
    
    // Check for MongoDB validation errors
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation failed: ' + Object.values(error.errors).map(e => e.message).join(', '),
        errors: error.errors
      });
    }
    
    // Check for MongoDB duplicate key error
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'Duplicate entry',
        field: Object.keys(error.keyValue || {})[0]
      });
    }
    
    // Generic error response
    return res.status(500).json({
      success: false,
      message: 'Failed to process demo request',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// --- BUSINESS LEADS ---
app.post('/api/business-leads', async (req, res) => {
  try {
    const { name, email, phone, company, role, interests, message, source } = req.body;

    const demoRequest = new DemoRequest({
      name,
      email,
      phone,
      company: company || '',
      role: role || 'Website Visitor',
      interests: Array.isArray(interests) ? interests : [interests].filter(Boolean),
      message: message || 'No message provided',
      source: source || 'website',
      status: 'new',
      metadata: {
        priority: 'medium',
        submittedAt: new Date(),
      },
    });

    const savedRequest = await demoRequest.save();

    const wsService = getWebSocketService();
    if (wsService) {
      wsService.broadcastNewDemoRequest(savedRequest);
    }

    res.status(201).json({
      success: true,
      message: 'Demo request submitted successfully',
      data: savedRequest,
    });
  } catch (error) {
    console.error('Error submitting demo request:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit demo request',
      error: error.message,
    });
  }
});

app.get('/api/business-leads', async (req, res) => {
  try {
    const leads = await DemoRequest.find({}).sort({ createdAt: -1 });
    res.status(200).json({
      success: true,
      count: leads.length,
      data: leads,
    });
  } catch (error) {
    console.error('Error fetching demo requests:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch demo requests',
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
        message: 'Name, Email, and Phone are required.',
      });
    }

    const demoRequest = new DemoRequest({
      name,
      email,
      phone,
      company: company || 'N/A',
      role: role || 'Website Visitor',
      interests: Array.isArray(interestedIn) ? interestedIn : [interestedIn].filter(Boolean),
      message: message || 'No message provided',
      source: 'website-form',
      status: 'new',
      metadata: {
        priority: 'medium',
        submittedAt: new Date(),
      },
    });

    const savedRequest = await demoRequest.save();

    const wsService = getWebSocketService();
    if (wsService) {
      wsService.broadcastNewDemoRequest(savedRequest);
    }

    res.status(201).json({
      success: true,
      message: 'Demo request submitted successfully!',
      data: savedRequest,
    });
  } catch (error) {
    console.error('Error submitting demo request:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit demo request',
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

// --- GET DEMO REQUESTS COUNT ---
app.get('/api/demo-requests/count', async (req, res) => {
  try {
    let requests;
    
    // --- CORRECTED LOGIC TO MATCH POST ROUTE ---
    if (global.DemoRequestLeads) {
      requests = await global.DemoRequestLeads.find().select('status');
    } else {
      // ensure model is registered
      const DemoRequestMain = mongoose.models.DemoRequest || mongoose.model('DemoRequest', DemoRequestSchema);
      requests = await DemoRequestMain.find().select('status');
    }

    // Calculate counts
    const total = requests.length;
    const newCount = requests.filter(lead => !lead.status || lead.status === 'new').length;
    const contactedCount = requests.filter(lead => lead.status === 'contacted').length;
    const qualifiedCount = requests.filter(lead => lead.status === 'qualified').length;

    res.json({
      success: true,
      count: total,
      newCount,
      contactedCount,
      qualifiedCount
    });
  } catch (error) {
    console.error('Error getting demo request counts:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching demo request counts',
      count: 0,
      newCount: 0,
      contactedCount: 0,
      qualifiedCount: 0
    });
  }
});

// --- GET DEMO REQUESTS ---
app.get('/api/demo-requests', async (req, res) => {
  console.log('Fetching demo requests...');
  try {
    // Check database connection
    if (mongoose.connection.readyState !== 1) {
      console.error('Database not connected!');
      return res.status(500).json({
        success: false,
        message: 'Database connection error',
        data: []
      });
    }

    let requests = [];
    
    try {
      // --- CORRECTED LOGIC TO MATCH POST ROUTE ---
      if (global.DemoRequestLeads) {
        requests = await global.DemoRequestLeads.find()
          .sort({ createdAt: -1 })
          .limit(50)
          .lean();
      } else {
        const DemoRequestMain = mongoose.models.DemoRequest || mongoose.model('DemoRequest', DemoRequestSchema);
        requests = await DemoRequestMain.find()
          .sort({ createdAt: -1 })
          .limit(50)
          .lean();
      }
      
      console.log(`Found ${requests.length} demo requests`);
      
      return res.json({ 
        success: true, 
        count: requests.length,
        data: requests 
      });
    } catch (dbError) {
      console.error('Database query error:', dbError);
      return res.status(500).json({
        success: false,
        message: 'Database query error',
        error: dbError.message,
        data: []
      });
    }
  } catch (error) {
    console.error('Error in /api/demo-requests:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Server error while fetching demo requests',
      error: error.message,
      data: []
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
