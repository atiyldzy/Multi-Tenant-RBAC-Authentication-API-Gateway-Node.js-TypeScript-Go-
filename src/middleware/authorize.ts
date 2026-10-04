import { Request, Response, NextFunction } from 'express';
import { hasRequiredRoles, hasRequiredPermissions, SystemRole } from '../security/rbac.js';

/**
 * Require at least one of the specified roles
 */
export function requireRoles(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Authentication is required to access this resource.'
      });
      return;
    }

    if (!hasRequiredRoles(req.user.roles, roles)) {
      res.status(403).json({
        error: 'FORBIDDEN',
        message: `Insufficient role permissions. Required one of: [${roles.join(', ')}]`,
        userRoles: req.user.roles
      });
      return;
    }

    next();
  };
}

/**
 * Require all of the specified granular permissions
 */
export function requirePermissions(...permissions: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Authentication is required to access this resource.'
      });
      return;
    }

    // SuperAdmin bypasses permission restrictions
    if (req.user.roles.includes(SystemRole.SUPER_ADMIN)) {
      return next();
    }

    if (!hasRequiredPermissions(req.user.permissions, permissions)) {
      res.status(403).json({
        error: 'FORBIDDEN',
        message: `Missing required granular permissions: [${permissions.join(', ')}]`,
        userPermissions: req.user.permissions
      });
      return;
    }

    next();
  };
}

/**
 * Multi-Tenant Isolation Middleware:
 * Ensures non-SuperAdmin users cannot access or mutate resources outside their own tenant
 */
export function enforceTenantIsolation(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required.' });
    return;
  }

  // SuperAdmin has cross-tenant access privileges
  if (req.user.roles.includes(SystemRole.SUPER_ADMIN)) {
    return next();
  }

  const targetTenantId = req.params.tenantId || req.body?.tenantId || req.query?.tenantId;

  if (targetTenantId && targetTenantId !== req.user.tenantId) {
    res.status(403).json({
      error: 'TENANT_ACCESS_DENIED',
      message: 'Cross-tenant access prohibited. You cannot access data outside your organization.'
    });
    return;
  }

  next();
}
