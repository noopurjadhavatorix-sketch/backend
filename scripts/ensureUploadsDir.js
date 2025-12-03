import { existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const UPLOADS_DIR = join(__dirname, '../uploads');

const ensureUploadsDir = () => {
  try {
    if (!existsSync(UPLOADS_DIR)) {
      mkdirSync(UPLOADS_DIR, { recursive: true });
      console.log('Uploads directory created successfully');
    }
    return UPLOADS_DIR;
  } catch (error) {
    console.error('Error creating uploads directory:', error);
    throw error;
  }
};

export default ensureUploadsDir;
