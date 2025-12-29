import express from 'express';
import mongoose from 'mongoose';
import DemoRequest from '../models/DemoRequest.js';

const router = express.Router();

// Create a new demo request
router.post('/', async (req, res) => {
  console.log('=== Demo Request Received ===');
  console.log('Request body:', JSON.stringify(req.body, null, 2));
  
  // Check MongoDB connection state
  const dbState = mongoose.connection.readyState;
  console.log('Mongoose connection state:', dbState);
  
  if (dbState !== 1) { // 1 = connected
    console.error('Database not connected. State:', dbState);
    return res.status(503).json({
      success: false,
      message: 'Database not ready. Please try again in a moment.',
      dbState: dbState
    });
  }

  try {
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

    const { name, email, company, phone, role, message, interests } = req.body;
    
    const demoRequest = new DemoRequest({
      name,
      email,
      company,
      phone,
      role,
      message: message || '',
      interests: interests || [],
      status: 'new',
      source: 'website',
      metadata: {
        priority: 'medium',
        submittedAt: new Date()
      }
    });

    await demoRequest.save();
    
    console.log('Demo request saved successfully:', demoRequest._id);
    
    res.status(201).json({
      success: true,
      message: 'Demo request submitted successfully',
      data: demoRequest
    });
  } catch (error) {
    console.error('Error saving demo request:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to save demo request',
      error: error.message,
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    });
  }
});

// Get all demo requests (for admin)
router.get('/', async (req, res) => {
  try {
    const requests = await DemoRequest.find().sort({ createdAt: -1 });
    res.status(200).json({
      success: true,
      count: requests.length,
      data: requests
    });
  } catch (error) {
    console.error('Error fetching demo requests:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching demo requests',
      error: error.message
    });
  }
});

// Get count of new demo requests
router.get('/count', async (req, res) => {
  try {
    const count = await DemoRequest.countDocuments({ status: 'new' });
    res.status(200).json({
      success: true,
      count
    });
  } catch (error) {
    console.error('Error counting demo requests:', error);
    res.status(500).json({
      success: false,
      message: 'Error counting demo requests',
      error: error.message
    });
  }
});

export default router;
