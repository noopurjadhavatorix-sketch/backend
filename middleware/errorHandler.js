const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);

  // Default error status and message
  let statusCode = err.statusCode || 500;
  let message = err.message || 'Internal Server Error';
  let errors = err.errors;

  // Handle specific error types
  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = 'Validation Error';
    errors = {};
    
    // Extract validation errors
    for (const field in err.errors) {
      errors[field] = err.errors[field].message;
    }
  } else if (err.name === 'MongoError' && err.code === 11000) {
    // Handle duplicate key error
    statusCode = 400;
    message = 'Duplicate field value entered';
    errors = { [Object.keys(err.keyPattern)[0]]: 'This value already exists' };
  } else if (err.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token';
  } else if (err.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token expired';
  }

  // Send error response
  res.status(statusCode).json({
    success: false,
    message,
    errors,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
};

export default errorHandler;
