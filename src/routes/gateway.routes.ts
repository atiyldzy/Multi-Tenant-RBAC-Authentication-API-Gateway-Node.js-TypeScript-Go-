import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { query } from '../database/db.js';
import { authenticateToken } from '../middleware/authenticate.js';
import { requireRoles } from '../middleware/authorize.js';
import { invalidateRouteCache } from '../proxy/proxyEngine.js';
import { SystemRole } from '../security/rbac.js';

export const gatewayConfigRouter = Router();

const routeSchema = z.object({
  pathPrefix: z.string().startsWith('/'),
  targetUrl: z.string().url(),
  isProtected: z.boolean().default(true),
  requiredRoles: z.array(z.string()).default([]),
  requiredPermissions: z.array(z.string()).default([]),
  rateLimitWindowSec: z.number().int().positive().default(60),
  rateLimitMax: z.number().int().positive().default(100),
  isActive: z.boolean().default(true),
  stripPrefix: z.boolean().default(false),
  customHeaders: z.record(z.string()).default({}),
  timeoutMs: z.number().int().positive().default(10000)
});

/**
 * @route GET /api/v1/gateway/routes
 * @desc List all configured dynamic gateway proxy routes
 */
gatewayConfigRouter.get(
  '/routes',
  authenticateToken,
  requireRoles(SystemRole.SUPER_ADMIN),
  async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const result = await query('SELECT * FROM gateway_routes ORDER BY created_at DESC');
      res.status(200).json({
        routes: result.rows
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route POST /api/v1/gateway/routes
 * @desc Register a new dynamic upstream microservice route
 */
gatewayConfigRouter.post(
  '/routes',
  authenticateToken,
  requireRoles(SystemRole.SUPER_ADMIN),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const data = routeSchema.parse(req.body);

      const result = await query(
        `INSERT INTO gateway_routes (
           path_prefix, target_url, is_protected, required_roles,
           required_permissions, rate_limit_window_sec, rate_limit_max,
           is_active, strip_prefix, custom_headers, timeout_ms
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING *`,
        [
          data.pathPrefix,
          data.targetUrl,
          data.isProtected,
          data.requiredRoles,
          data.requiredPermissions,
          data.rateLimitWindowSec,
          data.rateLimitMax,
          data.isActive,
          data.stripPrefix,
          JSON.stringify(data.customHeaders),
          data.timeoutMs
        ]
      );

      invalidateRouteCache();

      res.status(201).json({
        message: 'Gateway route created successfully.',
        route: result.rows[0]
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route PUT /api/v1/gateway/routes/:id
 * @desc Update dynamic route configuration
 */
gatewayConfigRouter.put(
  '/routes/:id',
  authenticateToken,
  requireRoles(SystemRole.SUPER_ADMIN),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { id } = req.params;
      const data = routeSchema.parse(req.body);

      const result = await query(
        `UPDATE gateway_routes
         SET path_prefix = $1, target_url = $2, is_protected = $3, required_roles = $4,
             required_permissions = $5, rate_limit_window_sec = $6, rate_limit_max = $7,
             is_active = $8, strip_prefix = $9, custom_headers = $10, timeout_ms = $11, updated_at = NOW()
         WHERE id = $12
         RETURNING *`,
        [
          data.pathPrefix,
          data.targetUrl,
          data.isProtected,
          data.requiredRoles,
          data.requiredPermissions,
          data.rateLimitWindowSec,
          data.rateLimitMax,
          data.isActive,
          data.stripPrefix,
          JSON.stringify(data.customHeaders),
          data.timeoutMs,
          id
        ]
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Route not found.' });
        return;
      }

      invalidateRouteCache();

      res.status(200).json({
        message: 'Gateway route updated successfully.',
        route: result.rows[0]
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route DELETE /api/v1/gateway/routes/:id
 * @desc Delete dynamic route configuration
 */
gatewayConfigRouter.delete(
  '/routes/:id',
  authenticateToken,
  requireRoles(SystemRole.SUPER_ADMIN),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { id } = req.params;

      const result = await query('DELETE FROM gateway_routes WHERE id = $1 RETURNING id', [id]);

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Route not found.' });
        return;
      }

      invalidateRouteCache();

      res.status(200).json({
        message: 'Gateway route deleted successfully.'
      });
    } catch (err) {
      next(err);
    }
  }
);
