import { Router, Request, Response, NextFunction } from 'express';
import { query } from '../database/db.js';
import { authenticateToken } from '../middleware/authenticate.js';
import { requireRoles, enforceTenantIsolation } from '../middleware/authorize.js';
import { SystemRole } from '../security/rbac.js';

export const auditRouter = Router();

/**
 * @route GET /api/v1/audit/logs
 * @desc Search and filter audit trail logs
 */
auditRouter.get(
  '/logs',
  authenticateToken,
  requireRoles(SystemRole.SUPER_ADMIN, SystemRole.TENANT_ADMIN),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const isSuperAdmin = req.user?.roles.includes(SystemRole.SUPER_ADMIN);
      const tenantId = isSuperAdmin ? (req.query.tenantId as string || undefined) : req.user?.tenantId;
      const userId = req.query.userId as string || undefined;
      const action = req.query.action as string || undefined;
      const limit = Math.min(parseInt(req.query.limit as string || '50', 10), 200);
      const offset = parseInt(req.query.offset as string || '0', 10);

      const conditions: string[] = [];
      const params: any[] = [];
      let idx = 1;

      if (tenantId) {
        conditions.push(`tenant_id = $${idx++}`);
        params.push(tenantId);
      }
      if (userId) {
        conditions.push(`user_id = $${idx++}`);
        params.push(userId);
      }
      if (action) {
        conditions.push(`action ILIKE $${idx++}`);
        params.push(`%${action}%`);
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      params.push(limit);
      const limitIdx = idx++;
      params.push(offset);
      const offsetIdx = idx++;

      const result = await query(
        `SELECT id, tenant_id, user_id, ip_address, user_agent, action, resource,
                status_code, details, created_at
         FROM audit_logs
         ${whereClause}
         ORDER BY created_at DESC
         LIMIT $${limitIdx} OFFSET $${offsetIdx}`,
        params
      );

      const countResult = await query(
        `SELECT COUNT(*)::int as total FROM audit_logs ${whereClause}`,
        params.slice(0, conditions.length)
      );

      res.status(200).json({
        total: countResult.rows[0]?.total || 0,
        limit,
        offset,
        logs: result.rows
      });
    } catch (err) {
      next(err);
    }
  }
);
