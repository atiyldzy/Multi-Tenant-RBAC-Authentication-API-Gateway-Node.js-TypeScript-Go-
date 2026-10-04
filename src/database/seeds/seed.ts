import { query, pool } from '../db.js';
import { hashPassword } from '../../security/crypto.js';
import { SystemRole, SystemPermission, ROLE_PERMISSION_MATRIX } from '../../security/rbac.js';

export async function seedDatabase(): Promise<void> {
  console.log('[Seed] Starting database seeding...');

  // 1. Seed Permissions
  console.log('[Seed] Seeding permissions...');
  for (const perm of Object.values(SystemPermission)) {
    const [resource, action] = perm.split(':');
    await query(
      `INSERT INTO permissions (name, description, resource, action)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (name) DO NOTHING`,
      [perm, `Permission to ${action} ${resource}`, resource, action]
    );
  }

  // 2. Seed Roles
  console.log('[Seed] Seeding roles...');
  for (const roleName of Object.values(SystemRole)) {
    await query(
      `INSERT INTO roles (name, description, is_system)
       VALUES ($1, $2, $3)
       ON CONFLICT (name) DO NOTHING`,
      [roleName, `System role: ${roleName}`, true]
    );
  }

  // 3. Link Roles to Permissions
  console.log('[Seed] Linking roles and permissions...');
  for (const [roleName, permissions] of Object.entries(ROLE_PERMISSION_MATRIX)) {
    const roleRes = await query('SELECT id FROM roles WHERE name = $1', [roleName]);
    if (roleRes.rows.length === 0) continue;
    const roleId = roleRes.rows[0].id;

    for (const permName of permissions) {
      const permRes = await query('SELECT id FROM permissions WHERE name = $1', [permName]);
      if (permRes.rows.length === 0) continue;
      const permId = permRes.rows[0].id;

      await query(
        `INSERT INTO role_permissions (role_id, permission_id)
         VALUES ($1, $2)
         ON CONFLICT (role_id, permission_id) DO NOTHING`,
        [roleId, permId]
      );
    }
  }

  // 4. Seed Default Tenants
  console.log('[Seed] Seeding default organizations/tenants...');
  const tenantRes = await query(
    `INSERT INTO tenants (name, slug, plan, is_active)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
     RETURNING id`,
    ['Acme Global Corp', 'acme-corp', 'enterprise', true]
  );
  const acmeTenantId = tenantRes.rows[0].id;

  const tenant2Res = await query(
    `INSERT INTO tenants (name, slug, plan, is_active)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
     RETURNING id`,
    ['Beta Innovations', 'beta-innovations', 'starter', true]
  );
  const betaTenantId = tenant2Res.rows[0].id;

  // 5. Seed Users
  console.log('[Seed] Seeding default users...');
  const defaultPasswordHash = await hashPassword('Password123!');

  const usersToSeed = [
    {
      tenantId: acmeTenantId,
      email: 'superadmin@acme.com',
      fullName: 'Atlas SuperAdmin',
      role: SystemRole.SUPER_ADMIN
    },
    {
      tenantId: acmeTenantId,
      email: 'admin@acme.com',
      fullName: 'Alice TenantAdmin',
      role: SystemRole.TENANT_ADMIN
    },
    {
      tenantId: acmeTenantId,
      email: 'member@acme.com',
      fullName: 'Bob Member',
      role: SystemRole.MEMBER
    },
    {
      tenantId: acmeTenantId,
      email: 'viewer@acme.com',
      fullName: 'Charlie Viewer',
      role: SystemRole.VIEWER
    },
    {
      tenantId: betaTenantId,
      email: 'admin@beta.com',
      fullName: 'Beta Admin',
      role: SystemRole.TENANT_ADMIN
    }
  ];

  for (const u of usersToSeed) {
    const userRes = await query(
      `INSERT INTO users (tenant_id, email, password_hash, full_name, is_active)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (tenant_id, email) DO UPDATE SET full_name = EXCLUDED.full_name
       RETURNING id`,
      [u.tenantId, u.email, defaultPasswordHash, u.fullName, true]
    );
    const userId = userRes.rows[0].id;

    const roleRes = await query('SELECT id FROM roles WHERE name = $1', [u.role]);
    if (roleRes.rows.length > 0) {
      const roleId = roleRes.rows[0].id;
      await query(
        `INSERT INTO user_roles (user_id, role_id, tenant_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, role_id, tenant_id) DO NOTHING`,
        [userId, roleId, u.tenantId]
      );
    }
  }

  // 6. Seed Sample Dynamic Gateway Routes
  console.log('[Seed] Seeding sample API gateway routes...');
  const sampleRoutes = [
    {
      pathPrefix: '/api/v1/echo',
      targetUrl: 'https://postman-echo.com/get',
      isProtected: true,
      requiredRoles: [SystemRole.MEMBER, SystemRole.TENANT_ADMIN, SystemRole.SUPER_ADMIN],
      requiredPermissions: [SystemPermission.PROXIED_API_ACCESS],
      rateLimitWindowSec: 60,
      rateLimitMax: 60,
      stripPrefix: true,
      customHeaders: { 'X-Gateway-Enriched': 'Enterprise-Auth-Gateway' }
    },
    {
      pathPrefix: '/api/v1/public-ping',
      targetUrl: 'https://postman-echo.com/ip',
      isProtected: false,
      requiredRoles: [],
      requiredPermissions: [],
      rateLimitWindowSec: 60,
      rateLimitMax: 120,
      stripPrefix: true,
      customHeaders: { 'X-Gateway-Public': 'true' }
    }
  ];

  for (const r of sampleRoutes) {
    await query(
      `INSERT INTO gateway_routes (
         path_prefix, target_url, is_protected, required_roles,
         required_permissions, rate_limit_window_sec, rate_limit_max,
         strip_prefix, custom_headers
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (path_prefix) DO UPDATE SET target_url = EXCLUDED.target_url`,
      [
        r.pathPrefix,
        r.targetUrl,
        r.isProtected,
        r.requiredRoles,
        r.requiredPermissions,
        r.rateLimitWindowSec,
        r.rateLimitMax,
        r.stripPrefix,
        JSON.stringify(r.customHeaders)
      ]
    );
  }

  console.log('[Seed] Database seeded successfully!');
}

if (process.argv[1] && process.argv[1].endsWith('seed.ts')) {
  seedDatabase()
    .then(() => pool.end())
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[Seed Fatal Error]', err);
      process.exit(1);
    });
}
