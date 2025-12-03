/**
 * List Admin Users Script
 *
 * This script lists all admin users stored in the MongoDB database.
 * It shows usernames and creation dates but not passwords.
 *
 * Usage:
 * node list-admins.js
 */

const mongoose = require('mongoose');
require('dotenv').config({ path: '../.env' });

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

// Connect to MongoDB and list admins
async function listAdmins() {
  try {
    // Get MongoDB connection string from environment variable
    const mongoUri = process.env.MONGODB_URI;

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

    // Find all admin users
    const admins = await Admin.find({}, 'username createdAt').sort({ createdAt: 1 });

    if (admins.length === 0) {
      console.log('No admin users found in the database.');
    } else {
      console.log(`Found ${admins.length} admin user(s):\n`);

      // Format and display the list
      admins.forEach((admin, index) => {
        const createdDate = new Date(admin.createdAt).toLocaleString();
        console.log(`${index + 1}. Username: ${admin.username}`);
        console.log(`   Created: ${createdDate}`);
        console.log(`   ID: ${admin._id}`);
        console.log('---');
      });
    }

  } catch (error) {
    console.error('Error listing admin users:', error.message);
  } finally {
    // Close the MongoDB connection
    await mongoose.connection.close();
    console.log('MongoDB connection closed.');
  }
}

// Run the script
listAdmins();
