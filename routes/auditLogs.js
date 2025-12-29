// backend/routes/auditLogs.js
import express from 'express';
import { authenticate } from '../middleware/auth.js';
import AuditLog from '../models/AuditLog.js';

const router = express.Router();

// Get all audit logs
router.get('/', authenticate, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'super_admin') {
      return res.status(403).json({ message: 'Unauthorized: Admin access required' });
    }

    const { 
      page = 1, 
      limit = 20, 
      search = '',
      startDate,
      endDate,
      action,
      user
    } = req.query;
    
    const skip = (page - 1) * limit;
    const query = {};

    // Text search
    if (search) {
      query.$or = [
        { userEmail: { $regex: search, $options: 'i' } },
        { action: { $regex: search, $options: 'i' } },
        { target: { $regex: search, $options: 'i' } }
      ];
    }

    // Date range filter
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) {
        const endOfDay = new Date(endDate);
        endOfDay.setHours(23, 59, 59, 999);
        query.createdAt.$lte = endOfDay;
      }
    }

    // Action filter
    if (action) {
      query.action = action;
    }

    // User filter
    if (user) {
      query.userEmail = user;
    }

    const [logs, total] = await Promise.all([
      AuditLog.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit)),
      AuditLog.countDocuments(query)
    ]);

    res.json({
      data: logs,
      pagination: {
        total,
        page: parseInt(page),
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching audit logs:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Export logs to CSV
router.get('/export', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'super_admin') {
      return res.status(403).json({ message: 'Unauthorized: Admin access required' });
    }

    const { 
      search = '',
      startDate,
      endDate,
      action,
      user
    } = req.query;

    const query = {};

    if (search) {
      query.$or = [
        { userEmail: { $regex: search, $options: 'i' } },
        { action: { $regex: search, $options: 'i' } },
        { target: { $regex: search, $options: 'i' } }
      ];
    }

    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) {
        const endOfDay = new Date(endDate);
        endOfDay.setHours(23, 59, 59, 999);
        query.createdAt.$lte = endOfDay;
      }
    }

    if (action) query.action = action;
    if (user) query.userEmail = user;

    const logs = await AuditLog.find(query).sort({ createdAt: -1 });

    // Convert to CSV
    const header = 'Timestamp,User Email,Role,Action,Target,Details\n';
    const csv = logs.map(log => {
      const details = typeof log.details === 'object' 
        ? JSON.stringify(log.details).replace(/"/g, '""') 
        : log.details;
      return `"${log.createdAt}","${log.userEmail}","${log.role}","${log.action}","${log.target}","${details}"`;
    }).join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=audit-logs.csv');
    res.send(header + csv);
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ message: 'Export failed' });
  }
});

// Create audit log (this would be called by other routes)
export const createAuditLog = async (logData) => {
  try {
    const log = new AuditLog(logData);
    await log.save();
  } catch (error) {
    console.error('Error creating audit log:', error);
  }
};

export default router;
