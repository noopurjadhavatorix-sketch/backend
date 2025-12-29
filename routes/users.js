import express from 'express';
import bcrypt from 'bcrypt';
import AdminUser from '../models/AdminUser.js';

const router = express.Router();

// Middleware to ensure JSON content type for specific routes
const requireJsonContent = (req, res, next) => {
  if (req.headers['content-type'] !== 'application/json') {
    return res.status(400).json({ 
      message: 'Content-Type must be application/json' 
    });
  }
  next();
};

// Get all users
router.get('/', async (req, res) => {
  try {
    console.log('GET /api/users - Fetching all users');
    const users = await AdminUser.find().select('-passwordHash').sort({ createdAt: -1 });
    console.log(`Found ${users.length} users`);
    res.status(200).json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Failed to fetch users', error: error.message });
  }
});

// Get single user by ID
router.get('/:id', async (req, res) => {
  try {
    console.log(`GET /api/users/${req.params.id}`);
    const user = await AdminUser.findById(req.params.id).select('-passwordHash');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json(user);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Failed to fetch user', error: error.message });
  }
});

// Create new user
router.post('/', requireJsonContent, async (req, res) => {
  try {
    console.log('POST /api/users - Creating new user');
    console.log('Request headers:', JSON.stringify(req.headers, null, 2));
    console.log('Request body:', JSON.stringify(req.body, null, 2));
    
    const { name, email, password, role, location, color, isActive } = req.body;

    // Enhanced validation with detailed error messages
    const missingFields = [];
    if (!name) missingFields.push('name');
    if (!email) missingFields.push('email');
    if (!password) missingFields.push('password');

    if (missingFields.length > 0) {
      const errorMsg = `Missing required fields: ${missingFields.join(', ')}`;
      console.log('Validation failed:', errorMsg);
      return res.status(400).json({ 
        success: false,
        message: errorMsg,
        missingFields,
        receivedData: { name: !!name, email: !!email, password: '***' }
      });
    }

    if (password.length < 6) {
      console.log('Validation failed: password too short');
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    // Check if email already exists
    console.log('Checking for existing user with email:', email.toLowerCase());
    const existingUser = await AdminUser.findOne({ email: email.toLowerCase() });
    console.log('Existing user check result:', existingUser ? 'Found' : 'Not found');
    if (existingUser) {
      console.log('Email already exists:', email);
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Hash password
    console.log('Hashing password...');
    const passwordHash = await bcrypt.hash(password, 10);

    // Create new admin user
    const newUser = new AdminUser({
      name: name.trim(),
      email: email.trim().toLowerCase(),
      passwordHash,
      role: role || 'business_mode',
      location: location || '',
      color: color || '#3B82F6',
      isActive: isActive !== undefined ? isActive : true
    });

    console.log('Saving user to database...');
    const savedUser = await newUser.save();
    console.log('User saved successfully:', { 
      id: savedUser._id, 
      email: savedUser.email,
      role: savedUser.role 
    });

    // Return user without password hash
    const userResponse = savedUser.toObject();
    delete userResponse.passwordHash;

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: userResponse
    });
  } catch (error) {
    console.error('Error creating user:', {
      message: error.message,
      stack: error.stack,
      name: error.name,
      ...(error.errors && { errors: error.errors })
    });
    
    // Handle duplicate key errors specifically (e.g., unique email)
    if (error.name === 'MongoServerError' && error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'Email already exists',
        field: 'email',
        error: error.message
      });
    }
    
    // Handle validation errors
    if (error.name === 'ValidationError') {
      const errors = {};
      Object.keys(error.errors).forEach(key => {
        errors[key] = error.errors[key].message;
      });
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors
      });
    }
    
    // Generic error response
    res.status(500).json({
      success: false,
      message: 'Failed to create user',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    });
  }
});

// Update user
router.put('/:id', async (req, res) => {
  try {
    console.log(`PUT /api/users/${req.params.id}`);
    console.log('Request body:', req.body);
    
    const { name, email, password, role, location, color, isActive } = req.body;
    const userId = req.params.id;

    // Find user
    const user = await AdminUser.findById(userId);
    if (!user) {
      console.log('User not found:', userId);
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if email is being changed and if it already exists
    if (email && email.toLowerCase() !== user.email) {
      const existingUser = await AdminUser.findOne({ 
        email: email.toLowerCase(),
        _id: { $ne: userId }
      });
      if (existingUser) {
        console.log('Email already exists:', email);
        return res.status(400).json({ message: 'Email already exists' });
      }
      user.email = email.toLowerCase();
    }

    // Update fields
    if (name) user.name = name.trim();
    if (role) user.role = role;
    if (location !== undefined) user.location = location;
    if (color) user.color = color;
    if (isActive !== undefined) user.isActive = isActive;

    // Update password if provided
    if (password) {
      if (password.length < 6) {
        return res.status(400).json({ message: 'Password must be at least 6 characters' });
      }
      console.log('Updating password...');
      user.passwordHash = await bcrypt.hash(password, 10);
    }

    user.updatedAt = Date.now();

    console.log('Saving updated user...');
    const updatedUser = await user.save();
    console.log('User updated successfully');

    // Return user without password
    const userResponse = updatedUser.toObject();
    delete userResponse.passwordHash;

    res.status(200).json(userResponse);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Failed to update user', error: error.message });
  }
});

// Delete user
router.delete('/:id', async (req, res) => {
  try {
    console.log(`DELETE /api/users/${req.params.id}`);
    const userId = req.params.id;

    const deletedUser = await AdminUser.findByIdAndDelete(userId);
    
    if (!deletedUser) {
      console.log('User not found:', userId);
      return res.status(404).json({ message: 'User not found' });
    }

    console.log('User deleted successfully:', userId);
    res.status(200).json({ message: 'User deleted successfully', userId });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Failed to delete user', error: error.message });
  }
});

export default router;