// File upload configuration
const path = require('path');

module.exports = {
  // File upload directories
  uploads: {
    baseDir: process.env.UPLOAD_BASE_DIR || path.join(process.cwd(), 'uploads'),
    resumes: {
      dir: process.env.RESUMES_UPLOAD_DIR || 'resumes',
      maxFileSize: parseInt(process.env.MAX_RESUME_SIZE) || 5 * 1024 * 1024, // 5MB default
      allowedTypes: process.env.ALLOWED_RESUME_TYPES 
        ? process.env.ALLOWED_RESUME_TYPES.split(',').map(t => t.trim())
        : [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
          ],
      fileNaming: {
        prefix: process.env.RESUME_FILE_PREFIX || 'resume-',
        randomSuffix: true
      }
    }
  },
  
  // File access URLs
  fileAccess: {
    baseUrl: process.env.FILE_ACCESS_BASE_URL || '',
    getResumeUrl: function(filename) {
      return `${this.baseUrl}/uploads/resumes/${filename}`;
    }
  }
};
