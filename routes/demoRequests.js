const express = require('express');
const router = express.Router();
const DemoRequest = require('../models/DemoRequest');

// Create a new demo request
router.post('/', async (req, res) => {
  try {
    const { name, email, company, phone, message } = req.body;
    
    const demoRequest = new DemoRequest({
      name,
      email,
      company,
      phone: phone || '',
      message: message || ''
    });

    await demoRequest.save();
    
    res.status(201).json({
      success: true,
      data: demoRequest
    });
  } catch (error) {
    console.error('Error creating demo request:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating demo request',
      error: error.message
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

module.exports = router;
