// backend/utils/auditLogger.js
import { createAuditLog } from '../routes/auditLogs.js';

export const logAction = async (req, action, target, details = {}) => {
  if (!req.user) return; // Skip if no user (public routes)
  
  await createAuditLog({
    userEmail: req.user.email,
    role: req.user.role,
    action,
    target,
    details,
    ipAddress: req.ip,
    userAgent: req.get('user-agent')
  });
};
