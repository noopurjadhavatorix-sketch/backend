/**
 * Admin User Creation Script
 *
 * This script creates a new admin user in the MongoDB database.
 * It can be used to add additional admins or reset admin credentials.
 *
 * Usage:
 * node create-admin.js <username> <password>
 *
 * Example:
 * node create-admin.js admin@example.com SecurePassword123
 */

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

// Handle .env file path correctly
const envPath = path.resolve(__dirname, '../.env');
if (fs.existsSync(envPath)) {
  require('dotenv').config({ path: envPath });
} else {
  console.log('Note: .env file not found at:', envPath);
  require('dotenv').config();
}

// Check for command line arguments
const username = process.argv[2];
const password = process.argv[3];

if (!username || !password) {
  console.error('Error: Username and password are required.');
  console.log('Usage: node create-admin.js <username> <password>');
  process.exit(1);
}

// Username validation - allow any non-empty string
if (!username || username.trim().length === 0) {
  console.error('Error: Username is required.');
  process.exit(1);
}

// Validate password strength
if (password.length < 8) {
  console.error('Error: Password must be at least 8 characters long.');
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

// Connect to MongoDB
async function createAdmin() {
  try {
    // Get MongoDB connection string from environment variable
    const mongoUri = process.env.MONGODB_URI;

    if (!mongoUri) {
      console.error('Error: MONGODB_URI environment variable not set.');
      console.log('Please create a .env file in the backend directory with your MongoDB connection string.');
      console.log('Example: MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/dbname');
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

    // Check if admin with the same username already exists
    const existingAdmin = await Admin.findOne({ username: username.toLowerCase() });

    if (existingAdmin) {
      console.log(`Admin user "${username}" already exists.`);
      console.log('If you want to update the password, use the change-password endpoint.');
      process.exit(1);
    }

    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new admin
    const newAdmin = new Admin({
      username: username.toLowerCase(),
      password: hashedPassword
    });

    // Save admin to database
    await newAdmin.save();

    console.log(`Success! Admin user "${username}" has been created.`);

  } catch (error) {
    console.error('Error creating admin user:', error.message);
    if (error.code === 11000) {
      console.log(`Admin user "${username}" already exists.`);
    }
  } finally {
    // Close the MongoDB connection
    await mongoose.connection.close();
    console.log('MongoDB connection closed.');
  }
}

// Run the script
createAdmin();
