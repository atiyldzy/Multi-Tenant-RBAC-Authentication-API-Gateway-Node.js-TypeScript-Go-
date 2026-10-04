import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { query } from '../database/db.js';
import { authenticateToken } from '../middleware/authenticate.js';
import { requireRoles, enforceTenantIsolation } from '../middleware/authorize.js';
import { SystemRole } from '../security/rbac.js';

export const tenantRouter = Router();

const createTenantSchema = z.object({
  name: z.string().min(2).max(100),
  slug: z.string().min(2).max(50).regex(/^[a-z0-9-]+$/, 'Slug must be alphanumeric lowercase with hyphens'),
  plan: z.enum(['starter', 'pro', 'enterprise']).default('starter'),
  metadata: z.record(z.any()).optional()
});

const updateTenantSchema = z.object({
  name: z.string().min(2).max(100).optional(),
  plan: z.enum(['starter', 'pro', 'enterprise']).optional(),
  isActive: z.boolean().optional(),
  metadata: z.record(z.any()).optional()
});

/**
 * @route GET /api/v1/tenants
 * @desc List all organizations (SuperAdmin only)
 */
tenantRouter.get(
  '/',
  authenticateToken,
  requireRoles(SystemRole.SUPER_ADMIN),
  async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const result = await query(
        `SELECT t.id, t.name, t.slug, t.plan, t.is_active, t.created_at, t.updated_at,
                COUNT(u.id)::int as user_count
         FROM tenants t
         LEFT JOIN users u ON u.tenant_id = t.id
         GROUP BY t.id
         ORDER BY t.created_at DESC`
      );

      res.status(200).json({
        tenants: result.rows
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route POST /api/v1/tenants
 * @desc Create a new organization/tenant (SuperAdmin only)
 */
tenantRouter.post(
  '/',
  authenticateToken,
  requireRoles(SystemRole.SUPER_ADMIN),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const data = createTenantSchema.parse(req.body);

      const result = await query(
        `INSERT INTO tenants (name, slug, plan, is_active, metadata)
         VALUES ($1, $2, $3, true, $4)
         RETURNING id, name, slug, plan, is_active, created_at`,
        [data.name, data.slug.toLowerCase(), data.plan, JSON.stringify(data.metadata || {})]
      );

      res.status(201).json({
        message: 'Tenant created successfully.',
        tenant: result.rows[0]
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route GET /api/v1/tenants/:tenantId
 * @desc Get tenant details (SuperAdmin or TenantAdmin)
 */
tenantRouter.get(
  '/:tenantId',
  authenticateToken,
  enforceTenantIsolation,
  requireRoles(SystemRole.SUPER_ADMIN, SystemRole.TENANT_ADMIN),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { tenantId } = req.params;

      const result = await query(
        `SELECT t.id, t.name, t.slug, t.plan, t.is_active, t.metadata, t.created_at, t.updated_at,
                COUNT(u.id)::int as user_count
         FROM tenants t
         LEFT JOIN users u ON u.tenant_id = t.id
         WHERE t.id = $1
         GROUP BY t.id`,
        [tenantId]
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Tenant not found.' });
        return;
      }

      res.status(200).json({
        tenant: result.rows[0]
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route PATCH /api/v1/tenants/:tenantId
 * @desc Update tenant details
 */
tenantRouter.patch(
  '/:tenantId',
  authenticateToken,
  enforceTenantIsolation,
  requireRoles(SystemRole.SUPER_ADMIN, SystemRole.TENANT_ADMIN),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { tenantId } = req.params;
      const data = updateTenantSchema.parse(req.body);

      const updates: string[] = [];
      const values: any[] = [];
      let idx = 1;

      if (data.name !== undefined) {
        updates.push(`name = $${idx++}`);
        values.push(data.name);
      }
      if (data.plan !== undefined && req.user?.roles.includes(SystemRole.SUPER_ADMIN)) {
        updates.push(`plan = $${idx++}`);
        values.push(data.plan);
      }
      if (data.isActive !== undefined && req.user?.roles.includes(SystemRole.SUPER_ADMIN)) {
        updates.push(`is_active = $${idx++}`);
        values.push(data.isActive);
      }
      if (data.metadata !== undefined) {
        updates.push(`metadata = $${idx++}`);
        values.push(JSON.stringify(data.metadata));
      }

      if (updates.length === 0) {
        res.status(400).json({ error: 'BAD_REQUEST', message: 'No valid update fields provided.' });
        return;
      }

      updates.push(`updated_at = NOW()`);
      values.push(tenantId);

      const result = await query(
        `UPDATE tenants
         SET ${updates.join(', ')}
         WHERE id = $${idx}
         RETURNING id, name, slug, plan, is_active, metadata, updated_at`,
        values
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Tenant not found.' });
        return;
      }

      res.status(200).json({
        message: 'Tenant updated successfully.',
        tenant: result.rows[0]
      });
    } catch (err) {
      next(err);
    }
  }
);
