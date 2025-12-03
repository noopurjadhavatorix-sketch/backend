import express from 'express';
import bcrypt from 'bcrypt';
import User from '../models/user.js';

const router = express.Router();

// Get all users
router.get('/', async (req, res) => {
  try {
    console.log('GET /api/users - Fetching all users');
    const users = await User.find().select('-password').sort({ createdAt: -1 });
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
    const user = await User.findById(req.params.id).select('-password');
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
router.post('/', async (req, res) => {
  try {
    console.log('POST /api/users - Creating new user');
    console.log('Request body:', req.body);
    
    const { name, email, password, role, location, color, isActive } = req.body;

    // Validation
    if (!name || !email || !password) {
      console.log('Validation failed: missing required fields');
      return res.status(400).json({ message: 'Name, email, and password are required' });
    }

    if (password.length < 6) {
      console.log('Validation failed: password too short');
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    // Check if email already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      console.log('Email already exists:', email);
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Hash password
    console.log('Hashing password...');
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      name: name.trim(),
      email: email.trim().toLowerCase(),
      password: hashedPassword,
      role: role || 'user',
      location: location || '',
      color: color || '#3B82F6',
      isActive: isActive !== undefined ? isActive : true
    });

    console.log('Saving user to database...');
    const savedUser = await newUser.save();
    console.log('User saved successfully:', savedUser._id);

    // Return user without password
    const userResponse = savedUser.toObject();
    delete userResponse.password;

    res.status(201).json(userResponse);
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Failed to create user', error: error.message });
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
    const user = await User.findById(userId);
    if (!user) {
      console.log('User not found:', userId);
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if email is being changed and if it already exists
    if (email && email.toLowerCase() !== user.email) {
      const existingUser = await User.findOne({ 
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
      user.password = await bcrypt.hash(password, 10);
    }

    user.updatedAt = Date.now();

    console.log('Saving updated user...');
    const updatedUser = await user.save();
    console.log('User updated successfully');

    // Return user without password
    const userResponse = updatedUser.toObject();
    delete userResponse.password;

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

    const deletedUser = await User.findByIdAndDelete(userId);
    
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