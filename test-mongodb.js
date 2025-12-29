const mongoose = require('mongoose');
require('dotenv').config();

console.log('Testing MongoDB connection...');
const uri = process.env.MONGODB_URI || 'mongodb+srv://dmatorixit:atorixitsaperp@cluster0.anmzzu9.mongodb.net/atorix?retryWrites=true&w=majority&appName=Cluster0';
console.log('Connection string:', uri ? 'Found' : 'Missing');

// Connect to MongoDB with the connection string
mongoose.connect(uri, {
  // These options are now the default in Mongoose 7+
  // No need to set useNewUrlParser and useUnifiedTopology
})
  .then(() => {
    console.log('✅ MongoDB Connected Successfully!');
    console.log('Database Name:', mongoose.connection.name);
    
    // List all collections in the database
    mongoose.connection.db.listCollections().toArray((err, collections) => {
      if (err) {
        console.error('Error listing collections:', err);
        process.exit(1);
      }
      console.log('\nCollections in the database:');
      collections.forEach(collection => {
        console.log(`- ${collection.name}`);
      });
      
      // Close the connection
      mongoose.connection.close();
    });
  })
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
    console.error('Error name:', err.name);
    console.error('Error code:', err.code);
    console.error('Error code name:', err.codeName);
    if (err.code === 'ENOTFOUND') {
      console.error('\n⚠️  Network error: Could not resolve the hostname.');
      console.error('Please check your internet connection and try again.');
    } else if (err.code === 'EAUTH') {
      console.error('\n⚠️  Authentication failed.');
      console.error('Please check your MongoDB Atlas credentials and try again.');
    } else if (err.code === 'ETIMEOUT') {
      console.error('\n⚠️  Connection timeout.');
      console.error('Please check your internet connection and try again.');
    }
    process.exit(1);
  });
