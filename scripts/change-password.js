/**
 * Admin Password Change Script
 *
 * This script updates the password for an existing admin user in the MongoDB database.
 *
 * Usage:
 * node change-password.js <username> <current-password> <new-password>
 *
 * Example:
 * node change-password.js admin@example.com CurrentPassword123 NewPassword456
 */

const mongoose = require('mongoose');
const bcrypt = require('bcrypt'); 
require('dotenv').config({ path: '../.env' });

// Check for command line arguments
const username = process.argv[2];
const currentPassword = process.argv[3];
const newPassword = process.argv[4];

if (!username || !currentPassword || !newPassword) {
  console.error('Error: Username, current password, and new password are required.');
  console.log('Usage: node change-password.js <username> <current-password> <new-password>');
  process.exit(1);
}

// Validate username format
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
if (!emailRegex.test(username)) {
  console.error('Error: Username must be a valid email address.');
  process.exit(1);
}

// Validate password strength
if (newPassword.length < 8) {
  console.error('Error: New password must be at least 8 characters long.');
  process.exit(1);
}

// Admin schema for MongoDB
const adminSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Connect to MongoDB and change password
async function changePassword() {
  try {
    // Get MongoDB connection string from environment variable (single DB)
    const mongoUri = process.env.MONGODB_URI || 'mongodb+srv://dmatorixit:atorixitsaperp@cluster0.anmzzu9.mongodb.net/atorix?retryWrites=true&w=majority&appName=Cluster0';

    if (!mongoUri) {
      console.error('Error: MONGODB_URI environment variable not set.');
      console.log('Please set the MONGODB_URI in your .env file.');
      process.exit(1);
    }

    console.log('Connecting to MongoDB...');

    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });

    console.log('Connected to MongoDB.');

    // Create Admin model
    const Admin = mongoose.model('Admin', adminSchema);

    // Find admin user
    const admin = await Admin.findOne({ username: username.toLowerCase() });

    if (!admin) {
      console.error(`Error: Admin user "${username}" not found.`);
      process.exit(1);
    }

    // Verify current password
    const passwordMatch = await bcrypt.compare(currentPassword, admin.password);

    if (!passwordMatch) {
      console.error('Error: Current password is incorrect.');
      process.exit(1);
    }

    // Hash the new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update the password
    admin.password = hashedPassword;
    await admin.save();

    console.log(`Success! Password for admin user "${username}" has been updated.`);

  } catch (error) {
    console.error('Error changing admin password:', error.message);
  } finally {
    // Close the MongoDB connection
    await mongoose.connection.close();
    console.log('MongoDB connection closed.');
  }
}

// Run the script
changePassword();
