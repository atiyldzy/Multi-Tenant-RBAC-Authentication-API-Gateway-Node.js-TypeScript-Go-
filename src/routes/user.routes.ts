import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { query } from '../database/db.js';
import { hashPassword } from '../security/crypto.js';
import { authenticateToken } from '../middleware/authenticate.js';
import { requireRoles, enforceTenantIsolation } from '../middleware/authorize.js';
import { SystemRole } from '../security/rbac.js';

export const userRouter = Router({ mergeParams: true });

const createUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  fullName: z.string().min(2),
  roles: z.array(z.string()).min(1).default([SystemRole.MEMBER])
});

const updateUserSchema = z.object({
  fullName: z.string().min(2).optional(),
  password: z.string().min(8).optional(),
  isActive: z.boolean().optional(),
  roles: z.array(z.string()).optional()
});

/**
 * @route GET /api/v1/tenants/:tenantId/users
 * @desc List all users within a tenant
 */
userRouter.get(
  '/',
  authenticateToken,
  enforceTenantIsolation,
  requireRoles(SystemRole.SUPER_ADMIN, SystemRole.TENANT_ADMIN, SystemRole.MEMBER),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { tenantId } = req.params;

      const result = await query(
        `SELECT u.id, u.tenant_id, u.email, u.full_name, u.is_active, u.created_at,
                COALESCE(json_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '[]') as roles
         FROM users u
         LEFT JOIN user_roles ur ON ur.user_id = u.id AND ur.tenant_id = u.tenant_id
         LEFT JOIN roles r ON r.id = ur.role_id
         WHERE u.tenant_id = $1
         GROUP BY u.id
         ORDER BY u.created_at ASC`,
        [tenantId]
      );

      res.status(200).json({
        users: result.rows
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route POST /api/v1/tenants/:tenantId/users
 * @desc Create a new user inside a tenant and assign roles
 */
userRouter.post(
  '/',
  authenticateToken,
  enforceTenantIsolation,
  requireRoles(SystemRole.SUPER_ADMIN, SystemRole.TENANT_ADMIN),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { tenantId } = req.params;
      const data = createUserSchema.parse(req.body);

      // Only SuperAdmin can assign SuperAdmin role
      if (data.roles.includes(SystemRole.SUPER_ADMIN) && !req.user?.roles.includes(SystemRole.SUPER_ADMIN)) {
        res.status(403).json({ error: 'FORBIDDEN', message: 'Only SuperAdmins can assign the SuperAdmin role.' });
        return;
      }

      const passwordHash = await hashPassword(data.password);

      const userRes = await query(
        `INSERT INTO users (tenant_id, email, password_hash, full_name, is_active)
         VALUES ($1, $2, $3, $4, true)
         RETURNING id, tenant_id, email, full_name, is_active, created_at`,
        [tenantId, data.email.toLowerCase(), passwordHash, data.fullName]
      );

      const newUser = userRes.rows[0];

      // Assign requested roles
      for (const roleName of data.roles) {
        const roleRes = await query('SELECT id FROM roles WHERE name = $1', [roleName]);
        if (roleRes.rows.length > 0) {
          await query(
            `INSERT INTO user_roles (user_id, role_id, tenant_id)
             VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING`,
            [newUser.id, roleRes.rows[0].id, tenantId]
          );
        }
      }

      res.status(201).json({
        message: 'User created successfully.',
        user: {
          ...newUser,
          roles: data.roles
        }
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route GET /api/v1/tenants/:tenantId/users/:userId
 * @desc Get user profile
 */
userRouter.get(
  '/:userId',
  authenticateToken,
  enforceTenantIsolation,
  requireRoles(SystemRole.SUPER_ADMIN, SystemRole.TENANT_ADMIN, SystemRole.MEMBER),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { tenantId, userId } = req.params;

      const result = await query(
        `SELECT u.id, u.tenant_id, u.email, u.full_name, u.is_active, u.created_at,
                COALESCE(json_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '[]') as roles
         FROM users u
         LEFT JOIN user_roles ur ON ur.user_id = u.id AND ur.tenant_id = u.tenant_id
         LEFT JOIN roles r ON r.id = ur.role_id
         WHERE u.id = $1 AND u.tenant_id = $2
         GROUP BY u.id`,
        [userId, tenantId]
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'User not found in this tenant.' });
        return;
      }

      res.status(200).json({
        user: result.rows[0]
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route PATCH /api/v1/tenants/:tenantId/users/:userId
 * @desc Update user profile / roles
 */
userRouter.patch(
  '/:userId',
  authenticateToken,
  enforceTenantIsolation,
  requireRoles(SystemRole.SUPER_ADMIN, SystemRole.TENANT_ADMIN),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { tenantId, userId } = req.params;
      const data = updateUserSchema.parse(req.body);

      const updates: string[] = [];
      const values: any[] = [];
      let idx = 1;

      if (data.fullName !== undefined) {
        updates.push(`full_name = $${idx++}`);
        values.push(data.fullName);
      }
      if (data.isActive !== undefined) {
        updates.push(`is_active = $${idx++}`);
        values.push(data.isActive);
      }
      if (data.password !== undefined) {
        const hash = await hashPassword(data.password);
        updates.push(`password_hash = $${idx++}`);
        values.push(hash);
      }

      if (updates.length > 0) {
        updates.push(`updated_at = NOW()`);
        values.push(userId);
        values.push(tenantId);

        await query(
          `UPDATE users SET ${updates.join(', ')} WHERE id = $${idx++} AND tenant_id = $${idx++}`,
          values
        );
      }

      // Update Roles if provided
      if (data.roles) {
        // Remove existing roles
        await query('DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2', [userId, tenantId]);

        // Insert new roles
        for (const roleName of data.roles) {
          const roleRes = await query('SELECT id FROM roles WHERE name = $1', [roleName]);
          if (roleRes.rows.length > 0) {
            await query(
              `INSERT INTO user_roles (user_id, role_id, tenant_id)
               VALUES ($1, $2, $3)
               ON CONFLICT DO NOTHING`,
              [userId, roleRes.rows[0].id, tenantId]
            );
          }
        }
      }

      res.status(200).json({
        message: 'User updated successfully.'
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route DELETE /api/v1/tenants/:tenantId/users/:userId
 * @desc Deactivate/Delete user from tenant
 */
userRouter.delete(
  '/:userId',
  authenticateToken,
  enforceTenantIsolation,
  requireRoles(SystemRole.SUPER_ADMIN, SystemRole.TENANT_ADMIN),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { tenantId, userId } = req.params;

      const result = await query(
        'DELETE FROM users WHERE id = $1 AND tenant_id = $2 RETURNING id',
        [userId, tenantId]
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'User not found.' });
        return;
      }

      res.status(200).json({
        message: 'User successfully removed from tenant.'
      });
    } catch (err) {
      next(err);
    }
  }
);
