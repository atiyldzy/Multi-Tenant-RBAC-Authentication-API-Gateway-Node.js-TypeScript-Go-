export enum SystemRole {
  SUPER_ADMIN = 'SuperAdmin',
  TENANT_ADMIN = 'TenantAdmin',
  MEMBER = 'Member',
  VIEWER = 'Viewer'
}

export enum SystemPermission {
  TENANTS_READ = 'tenants:read',
  TENANTS_WRITE = 'tenants:write',
  TENANTS_DELETE = 'tenants:delete',
  
  USERS_READ = 'users:read',
  USERS_WRITE = 'users:write',
  USERS_DELETE = 'users:delete',
  
  ROLES_ASSIGN = 'roles:assign',
  ROUTES_MANAGE = 'routes:manage',
  AUDIT_READ = 'audit:read',
  PROXIED_API_ACCESS = 'proxy:access'
}

export const ROLE_PERMISSION_MATRIX: Record<SystemRole, SystemPermission[]> = {
  [SystemRole.SUPER_ADMIN]: [
    SystemPermission.TENANTS_READ,
    SystemPermission.TENANTS_WRITE,
    SystemPermission.TENANTS_DELETE,
    SystemPermission.USERS_READ,
    SystemPermission.USERS_WRITE,
    SystemPermission.USERS_DELETE,
    SystemPermission.ROLES_ASSIGN,
    SystemPermission.ROUTES_MANAGE,
    SystemPermission.AUDIT_READ,
    SystemPermission.PROXIED_API_ACCESS
  ],
  [SystemRole.TENANT_ADMIN]: [
    SystemPermission.USERS_READ,
    SystemPermission.USERS_WRITE,
    SystemPermission.USERS_DELETE,
    SystemPermission.ROLES_ASSIGN,
    SystemPermission.AUDIT_READ,
    SystemPermission.PROXIED_API_ACCESS
  ],
  [SystemRole.MEMBER]: [
    SystemPermission.USERS_READ,
    SystemPermission.PROXIED_API_ACCESS
  ],
  [SystemRole.VIEWER]: [
    SystemPermission.USERS_READ,
    SystemPermission.PROXIED_API_ACCESS
  ]
};

/**
 * Check if a list of user roles or permissions satisfies required conditions
 */
export function hasRequiredRoles(userRoles: string[], requiredRoles: string[]): boolean {
  if (!requiredRoles || requiredRoles.length === 0) return true;
  if (userRoles.includes(SystemRole.SUPER_ADMIN)) return true;
  return requiredRoles.some(role => userRoles.includes(role));
}

export function hasRequiredPermissions(userPermissions: string[], requiredPermissions: string[]): boolean {
  if (!requiredPermissions || requiredPermissions.length === 0) return true;
  return requiredPermissions.every(perm => userPermissions.includes(perm));
}
