import express from "express";
import Lead from "../models/lead.js";

const router = express.Router();

// Create a new business lead
router.post("/", async (req, res) => {
  console.log('Received request to create new business lead');
  console.log('Request body:', req.body);
  
  try {
    const {
      name,
      email,
      phone,
      company = '',
      role = '',
      interests = [],
      message = '',
      source: sourceInput = 'website',
      status = 'new',
      metadata = {}
    } = req.body;
    
    console.log('Parsed fields:', { name, email, phone, company, role });
    
    // Normalize the source
    const validSources = ['website', 'api', 'import', 'manual'];
    const source = validSources.includes(sourceInput?.toLowerCase()?.trim()) 
      ? sourceInput.toLowerCase().trim() 
      : 'website';

    // Basic validation
    if (!name || !email || !phone) {
      const errorMsg = `Missing required fields: ${!name ? 'name ' : ''}${!email ? 'email ' : ''}${!phone ? 'phone' : ''}`.trim();
      console.error('Validation error:', errorMsg);
      return res.status(400).json({
        success: false,
        message: errorMsg || 'Name, email, and phone are required fields',
        receivedData: { name, email, phone, company, role }
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.error('Invalid email format:', email);
      return res.status(400).json({
        success: false,
        message: 'Please enter a valid email address'
      });
    }

    // Create new lead
    const newLead = new Lead({
      name: name?.trim(),
      email: email?.toLowerCase()?.trim(),
      phone: phone?.trim(),
      company: company?.trim(),
      role: role?.trim(),
      interests: Array.isArray(interests) ? interests : [interests],
      message: message?.trim(),
      source,
      status,
      metadata: {
        ...metadata,
        submittedAt: new Date(),
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      }
    });

    // Save to database
    await newLead.save();

    res.status(201).json({
      success: true,
      message: 'Lead submitted successfully',
      data: newLead
    });
  } catch (error) {
    console.error('Error creating lead:', {
      error: error.message,
      stack: error.stack
    });
    
    // Handle duplicate key errors
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'A lead with this email already exists'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Error creating lead',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get all business leads
router.get("/", async (req, res) => {
  try {
    console.log('Fetching all business leads...');
    const leads = await Lead.find()
      .sort({ createdAt: -1 })
      .select('-__v')
      .lean();
    
    console.log(`Found ${leads.length} leads`);
    res.json(leads);
  } catch (error) {
    console.error('Error in GET /api/business-leads:', {
      message: error.message,
      name: error.name,
      stack: error.stack,
      code: error.code,
      keyPattern: error.keyPattern,
      keyValue: error.keyValue
    });
    
    res.status(500).json({ 
      success: false,
      message: "Failed to fetch business leads",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get a single business lead by ID
router.get("/:id", async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid lead ID format'
      });
    }

    const lead = await Lead.findById(req.params.id)
      .select('-__v')
      .lean();

    if (!lead) {
      return res.status(404).json({ 
        success: false,
        message: 'Lead not found' 
      });
    }

    res.json(lead);
  } catch (error) {
    console.error('Error fetching lead:', {
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({ 
      message: "Error fetching lead", 
      error: process.env.NODE_ENV === 'development' ? error.message : undefined 
    });
  }
});

// Update lead status
router.patch("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid lead ID format'
      });
    }

    if (!status || !['new', 'contacted', 'qualified', 'lost'].includes(status)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid status value. Must be one of: new, contacted, qualified, lost'
      });
    }

    const updatedLead = await Lead.findByIdAndUpdate(
      id,
      { status },
      { new: true, runValidators: true }
    ).select('-__v').lean();

    if (!updatedLead) {
      return res.status(404).json({ 
        success: false,
        message: 'Lead not found' 
      });
    }

    res.json({
      success: true,
      message: 'Lead status updated successfully',
      lead: updatedLead
    });
  } catch (error) {
    console.error('Error updating lead status:', {
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({ 
      success: false,
      message: "Error updating lead status", 
      error: process.env.NODE_ENV === 'development' ? error.message : undefined 
    });
  }
});

// Get all business leads

export default router;
