import mongoose from 'mongoose';

// Main application database connection
export const connectDB = async () => {
  try {
    if (mongoose.connection.readyState === 0) { // 0 = disconnected
      const uri = process.env.MONGODB_URI || 'mongodb+srv://dmatorixit:atorixitsaperp@cluster0.anmzzu9.mongodb.net/atorix?retryWrites=true&w=majority&appName=Cluster0';

      await mongoose.connect(uri, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
      console.log('Main database connected successfully');
    }
    return mongoose.connection;
  } catch (error) {
    console.error('Main database connection error:', error);
    process.exit(1);
  }
};

// Leads database connection
export const connectLeadsDB = async () => {
  // Using the single connection; alias preserved for compatibility
  return connectDB();
};

// Export connections
export const dbConnections = {
  main: mongoose.connection,
  leads: mongoose.connection // Single connection reused
};

// Handle connection events
mongoose.connection.on('connected', () => {
  console.log('MongoDB connected successfully');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected');
});

// Close the Mongoose connection when the Node process ends
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  console.log('MongoDB connection closed through app termination');
  process.exit(0);
});
