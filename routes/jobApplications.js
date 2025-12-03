import express from "express";
import mongoose from "mongoose";
import path from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer';
import { mkdir, unlink } from 'fs/promises';
import { existsSync } from 'fs';
import nodemailer from 'nodemailer';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configure uploads directory
const uploadsDir = path.join(__dirname, '../../uploads/resumes');
const router = express.Router();

// Ensure uploads directory exists
if (!existsSync(uploadsDir)) {
  await mkdir(uploadsDir, { recursive: true });
  console.log(`Created uploads directory at: ${uploadsDir}`);
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, 'resume-' + uniqueSuffix + ext);
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF, DOC, and DOCX files are allowed.'));
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// File access helper
const fileAccess = {
  getResumeUrl: (filename) => {
    if (!filename) return null;
    return `/api/resumes/${path.basename(filename)}`;
  }
};

// Import models and utilities
import JobApplication from "../models/JobApplication.js";
import Lead from "../models/lead.js";

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Email sending function
async function sendEmailWithAttachment(to, { subject, text, html, attachments }) {
  const mailOptions = {
    from: process.env.EMAIL_USER || 'no-reply@atorix.com',
    to,
    subject,
    text,
    html,
    attachments: attachments || []
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Email notification sent successfully');
  } catch (error) {
    console.error('Failed to send email notification:', error);
    // Don't throw error to prevent affecting the main application flow
  }
}

console.log("✓ Models imported successfully");

// Request logging
router.use((req, res, next) => {
  console.log(`\n[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

// POST - Create a new job application (saved as lead in hiring section)
router.post("/", async (req, res) => {
  console.log("\n=== POST /job-applications ===");
  console.log("Request body:", req.body);
  
  if (!req.body) {
    return res.status(400).json({
      success: false,
      message: 'Request body is required'
    });
  }
  
  try {
    if (!Lead) {
      throw new Error("Lead model not initialized");
    }

    if (mongoose.connection.readyState !== 1) {
      throw new Error(`Database not connected. State: ${mongoose.connection.readyState}`);
    }

    const session = await mongoose.startSession();
    session.startTransaction();
    console.log("✓ Transaction started");

    // Validate required fields
    const requiredFields = [
      { field: 'fullName', message: 'Full name is required' },
      { field: 'email', message: 'Email is required' },
      { field: 'phone', message: 'Phone number is required' },
      { field: 'position', message: 'Position is required' }
    ];

    const validationErrors = requiredFields
      .filter(({ field }) => !req.body[field]?.trim())
      .map(({ message }) => message);

    // Email validation
    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    if (req.body.email && !emailRegex.test(req.body.email)) {
      validationErrors.push('Please enter a valid email address');
    }

    if (validationErrors.length > 0) {
      if (req.file?.path) await unlink(req.file.path);
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: validationErrors
      });
    }

    // Create lead data
    const leadData = {
      name: req.body.fullName.trim(),
      email: req.body.email.toLowerCase().trim(),
      phone: req.body.phone.trim(),
      company: req.body.currentCompany?.trim() || '',
      role: req.body.position.trim(),
      source: 'Career Portal',
      status: 'New Application',
      type: 'Job Application',
      notes: `Applied for position: ${req.body.position || 'Not specified'}
      
      Experience: ${req.body.experience || 'Not specified'}
      Notice Period: ${req.body.noticePeriod || 'Not specified'}
      Expected Salary: ${req.body.expectedSalary || 'Not specified'}
      
      Cover Letter:
      ${req.body.coverLetter || 'No cover letter provided'}`,
      metadata: {
        position: req.body.position,
        experience: req.body.experience,
        currentCompany: req.body.currentCompany,
        expectedSalary: req.body.expectedSalary,
        noticePeriod: req.body.noticePeriod,
        source: 'Career Portal',
        applicationDate: new Date()
      }
    };

    // Save to leads collection
    const lead = new Lead(leadData);
    await lead.save({ session });
    console.log("Lead saved to database");

    await session.commitTransaction();
    console.log("✓ Transaction committed");
    
    res.status(201).json({
      success: true,
      message: "Application submitted successfully. Our team will review your application and get back to you soon.",
      data: {
        id: lead._id,
        name: lead.name,
        email: lead.email,
        position: lead.role,
        submittedAt: new Date()
      }
    });
    
  } catch (error) {
    console.error("\n=== ERROR ===");
    console.error("Timestamp:", new Date().toISOString());
    console.error("Error:", error);
    console.error("=============");
    
    if (session) {
      try {
        await session.abortTransaction();
      } catch (abortError) {
        console.error("Error aborting transaction:", abortError);
      }
    }

    // Clean up file if there was an error
    if (req.file?.path) {
      try {
        await unlink(req.file.path);
      } catch (cleanupError) {
        console.error("Error cleaning up file:", cleanupError);
      }
    }

    // Handle specific error types
    // Handle validation errors
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(val => val.message);
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors: messages
      });
    }
    
    // Handle duplicate key errors (unique constraint violations)
    if (error.name === 'MongoServerError' && error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: 'Duplicate entry',
        error: 'This email has already been used for an application',
        field: Object.keys(error.keyPattern)[0] || 'email'
      });
    }

    // Handle file size limit errors
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: 'File too large',
        error: 'File size must be less than 5MB'
      });
    }

    // Handle invalid file type errors
    if (error.message && error.message.includes('Invalid file type')) {
      return res.status(400).json({
        success: false,
        message: 'Invalid file type',
        error: 'Only PDF, DOC, and DOCX files are allowed'
      });
    }

    // Generic error response
    const errorResponse = {
      success: false,
      message: 'An error occurred while processing your request',
      error: process.env.NODE_ENV === 'development' ? {
        message: error.message,
        name: error.name,
        ...(error.code && { code: error.code }),
        ...(error.stack && { stack: error.stack })
      } : undefined
    };
    
    res.status(500).json(errorResponse);
  } finally {
    if (session) {
      try {
        await session.endSession();
      } catch (sessionError) {
        console.error('Error ending session:', sessionError);
      }
    }
  }
});

// GET all applications
router.get("/", async (req, res) => {
  console.log("GET /job-applications - Fetching applications");
  
  try {
    if (!JobApplication) {
      throw new Error("JobApplication model not loaded");
    }

    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.pageSize) || 10;
    const search = req.query.search || '';
    const skip = (page - 1) * pageSize;

    // Build search query
    let query = {};
    if (search.trim()) {
      query = {
        $or: [
          { fullName: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
          { position: { $regex: search, $options: 'i' } },
        ]
      };
    }

    // Get paginated results
    const [total, applications] = await Promise.all([
      JobApplication.countDocuments(query),
      JobApplication.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(pageSize)
        .lean()
    ]);

    const totalPages = Math.ceil(total / pageSize);

    // Add resume URLs
    const applicationsWithUrls = applications.map(app => {
      if (!app.resume) return { ...app, resume: null };
      
      const resumeFilename = app.resume.filename || path.basename(app.resume.path || '');
      const resumeUrl = resumeFilename ? fileAccess.getResumeUrl(resumeFilename) : null;
      
      return {
        ...app,
        resume: {
          ...app.resume,
          url: resumeUrl
        }
      };
    });

    res.status(200).json({
      success: true,
      items: applicationsWithUrls,
      total,
      totalPages,
      page,
      pageSize,
      hasMore: page < totalPages
    });
    
  } catch (error) {
    console.error("ERROR in GET /job-applications:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch applications",
      error: error.message,
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    });
  }
});

export default router;