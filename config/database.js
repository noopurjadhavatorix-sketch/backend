import mongoose from 'mongoose';

// Main application database connection
export const connectDB = async () => {
  try {
    if (mongoose.connection.readyState === 0) { // 0 = disconnected
      await mongoose.connect(process.env.MONGODB_URI, {
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
  try {
    // Use the main connection for now
    await connectDB();
    return mongoose.connection;
  } catch (error) {
    console.error('Leads database connection error:', error);
    process.exit(1);
  }
};

// Export connections
export const dbConnections = {
  main: mongoose.connection,
  leads: mongoose.connection // Using the same connection for now
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
