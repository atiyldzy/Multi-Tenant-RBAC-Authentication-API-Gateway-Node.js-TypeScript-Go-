import { hasRequiredRoles, hasRequiredPermissions, SystemRole, SystemPermission } from '../src/security/rbac.js';

describe('RBAC & Permission Evaluation Suite', () => {
  test('SuperAdmin should bypass role requirements', () => {
    const roles = [SystemRole.SUPER_ADMIN];
    expect(hasRequiredRoles(roles, [SystemRole.TENANT_ADMIN])).toBe(true);
    expect(hasRequiredRoles(roles, [SystemRole.VIEWER])).toBe(true);
  });

  test('TenantAdmin should fulfill TenantAdmin requirements but not unrelated arbitrary roles', () => {
    const roles = [SystemRole.TENANT_ADMIN];
    expect(hasRequiredRoles(roles, [SystemRole.TENANT_ADMIN])).toBe(true);
    expect(hasRequiredRoles(roles, ['CustomAuditorRole'])).toBe(false);
  });

  test('Should evaluate granular permissions strictly', () => {
    const permissions = [SystemPermission.USERS_READ, SystemPermission.PROXIED_API_ACCESS];

    expect(hasRequiredPermissions(permissions, [SystemPermission.USERS_READ])).toBe(true);
    expect(hasRequiredPermissions(permissions, [SystemPermission.USERS_READ, SystemPermission.PROXIED_API_ACCESS])).toBe(true);
    expect(hasRequiredPermissions(permissions, [SystemPermission.USERS_WRITE])).toBe(false);
  });
});
