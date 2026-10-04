import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { query } from '../database/db.js';
import { verifyPassword, hashPassword } from '../security/crypto.js';
import { signAccessToken, createRefreshToken, rotateRefreshToken, revokeTokenSession } from '../security/jwt.js';
import { getJWKS, ensureKeyPair } from '../config/keys.js';
import { authenticateToken } from '../middleware/authenticate.js';
import { rateLimiter } from '../middleware/rateLimitMiddleware.js';
import { logAuditEvent } from '../middleware/auditLogger.js';
import { SystemRole } from '../security/rbac.js';

export const authRouter = Router();

// Validation Schemas
const registerSchema = z.object({
  tenantSlug: z.string().min(2).max(50),
  email: z.string().email(),
  password: z.string().min(8).max(100),
  fullName: z.string().min(2).max(100)
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
  tenantSlug: z.string().optional()
});

const refreshSchema = z.object({
  refreshToken: z.string().min(10)
});

const logoutSchema = z.object({
  refreshToken: z.string().optional()
});

/**
 * @route POST /api/v1/auth/register
 * @desc Self-serve user registration within a tenant (default role: Member)
 */
authRouter.post(
  '/register',
  rateLimiter({ windowSeconds: 60, maxRequests: 5, keyPrefix: 'auth:reg' }),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const data = registerSchema.parse(req.body);

      // 1. Verify Tenant exists
      const tenantRes = await query('SELECT id, is_active FROM tenants WHERE slug = $1', [data.tenantSlug]);
      if (tenantRes.rows.length === 0) {
        res.status(404).json({ error: 'TENANT_NOT_FOUND', message: `Organization '${data.tenantSlug}' does not exist.` });
        return;
      }

      const tenant = tenantRes.rows[0];
      if (!tenant.is_active) {
        res.status(403).json({ error: 'TENANT_INACTIVE', message: 'This organization account is currently inactive.' });
        return;
      }

      // 2. Hash Password
      const passwordHash = await hashPassword(data.password);

      // 3. Create User
      const userRes = await query(
        `INSERT INTO users (tenant_id, email, password_hash, full_name, is_active)
         VALUES ($1, $2, $3, $4, true)
         RETURNING id, tenant_id, email, full_name, created_at`,
        [tenant.id, data.email.toLowerCase(), passwordHash, data.fullName]
      );
      const newUser = userRes.rows[0];

      // 4. Assign default 'Member' role
      const roleRes = await query('SELECT id FROM roles WHERE name = $1', [SystemRole.MEMBER]);
      if (roleRes.rows.length > 0) {
        await query(
          `INSERT INTO user_roles (user_id, role_id, tenant_id)
           VALUES ($1, $2, $3)
           ON CONFLICT DO NOTHING`,
          [newUser.id, roleRes.rows[0].id, tenant.id]
        );
      }

      // 5. Generate Initial Tokens
      const { token: accessToken } = signAccessToken({
        sub: newUser.id,
        tenantId: newUser.tenant_id,
        email: newUser.email,
        roles: [SystemRole.MEMBER],
        permissions: ['users:read', 'proxy:access']
      });

      const refreshToken = await createRefreshToken(newUser.id, newUser.tenant_id);

      await logAuditEvent({
        tenantId: newUser.tenant_id,
        userId: newUser.id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        action: 'USER_REGISTER',
        resource: '/api/v1/auth/register',
        statusCode: 201,
        details: { email: newUser.email }
      });

      res.status(201).json({
        message: 'User successfully registered.',
        user: {
          id: newUser.id,
          email: newUser.email,
          fullName: newUser.full_name,
          tenantId: newUser.tenant_id,
          roles: [SystemRole.MEMBER]
        },
        tokens: {
          tokenType: 'Bearer',
          accessToken,
          refreshToken,
          expiresIn: 900
        }
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route POST /api/v1/auth/login
 * @desc Authenticate user and issue RS256 JWT access token + refresh token
 */
authRouter.post(
  '/login',
  rateLimiter({ windowSeconds: 60, maxRequests: 10, keyPrefix: 'auth:login' }),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const data = loginSchema.parse(req.body);
      const email = data.email.toLowerCase();

      let queryStr = `
        SELECT u.id, u.tenant_id, u.email, u.password_hash, u.full_name, u.is_active as user_active,
               t.is_active as tenant_active, t.name as tenant_name, t.slug as tenant_slug
        FROM users u
        JOIN tenants t ON t.id = u.tenant_id
        WHERE u.email = $1
      `;
      const queryParams: any[] = [email];

      if (data.tenantSlug) {
        queryStr += ` AND t.slug = $2`;
        queryParams.push(data.tenantSlug);
      }

      const resUsers = await query(queryStr, queryParams);

      if (resUsers.rows.length === 0) {
        res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' });
        return;
      }

      const user = resUsers.rows[0];

      if (!user.user_active || !user.tenant_active) {
        res.status(403).json({ error: 'ACCOUNT_INACTIVE', message: 'User or Organization account is deactivated.' });
        return;
      }

      const isValidPassword = await verifyPassword(data.password, user.password_hash);
      if (!isValidPassword) {
        await logAuditEvent({
          tenantId: user.tenant_id,
          userId: user.id,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
          action: 'LOGIN_FAILED',
          resource: '/api/v1/auth/login',
          statusCode: 401,
          details: { email }
        });
        res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' });
        return;
      }

      // Fetch User Roles
      const rolesRes = await query(
        `SELECT r.name as role_name
         FROM user_roles ur
         JOIN roles r ON r.id = ur.role_id
         WHERE ur.user_id = $1 AND ur.tenant_id = $2`,
        [user.id, user.tenant_id]
      );
      const roles = rolesRes.rows.map(r => r.role_name);

      // Fetch Granular Permissions
      const permRes = await query(
        `SELECT DISTINCT p.name as perm_name
         FROM user_roles ur
         JOIN role_permissions rp ON rp.role_id = ur.role_id
         JOIN permissions p ON p.id = rp.permission_id
         WHERE ur.user_id = $1 AND ur.tenant_id = $2`,
        [user.id, user.tenant_id]
      );
      const permissions = permRes.rows.map(p => p.perm_name);

      // Issue RS256 Access Token and Refresh Token
      const { token: accessToken, jti } = signAccessToken({
        sub: user.id,
        tenantId: user.tenant_id,
        email: user.email,
        roles,
        permissions
      });

      const refreshToken = await createRefreshToken(user.id, user.tenant_id);

      await logAuditEvent({
        tenantId: user.tenant_id,
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        action: 'LOGIN_SUCCESS',
        resource: '/api/v1/auth/login',
        statusCode: 200,
        details: { email, jti }
      });

      res.status(200).json({
        message: 'Authentication successful.',
        user: {
          id: user.id,
          email: user.email,
          fullName: user.full_name,
          tenant: {
            id: user.tenant_id,
            name: user.tenant_name,
            slug: user.tenant_slug
          },
          roles,
          permissions
        },
        tokens: {
          tokenType: 'Bearer',
          accessToken,
          refreshToken,
          expiresIn: 900
        }
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route POST /api/v1/auth/refresh
 * @desc Refresh access token with rotation and automatic reuse-attack family revocation
 */
authRouter.post(
  '/refresh',
  rateLimiter({ windowSeconds: 60, maxRequests: 20, keyPrefix: 'auth:refresh' }),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const data = refreshSchema.parse(req.body);

      try {
        const rotated = await rotateRefreshToken(data.refreshToken);

        res.status(200).json({
          message: 'Token rotation successful.',
          tokens: {
            tokenType: 'Bearer',
            accessToken: rotated.accessToken,
            refreshToken: rotated.refreshToken,
            expiresIn: 900
          }
        });
      } catch (err: any) {
        if (err.message === 'TOKEN_REUSE_DETECTED') {
          res.status(401).json({
            error: 'SECURITY_TOKEN_REUSE',
            message: 'Suspicious token reuse detected. All active sessions in this family have been invalidated.'
          });
          return;
        }
        res.status(401).json({
          error: 'INVALID_REFRESH_TOKEN',
          message: err.message || 'Refresh token is expired or invalid.'
        });
      }
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route POST /api/v1/auth/logout
 * @desc Revoke refresh token and add current access token JTI to Redis blacklist
 */
authRouter.post(
  '/logout',
  authenticateToken,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { refreshToken } = logoutSchema.parse(req.body || {});
      const jti = req.user?.jti;

      await revokeTokenSession(jti, refreshToken);

      await logAuditEvent({
        tenantId: req.user?.tenantId,
        userId: req.user?.sub,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        action: 'LOGOUT',
        resource: '/api/v1/auth/logout',
        statusCode: 200,
        details: { jti }
      });

      res.status(200).json({
        message: 'Successfully logged out. Access token blacklisted and refresh session terminated.'
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route GET /api/v1/auth/me
 * @desc Get currently authenticated user profile, roles, and tenant information
 */
authRouter.get(
  '/me',
  authenticateToken,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const userId = req.user!.sub;
      const resUser = await query(
        `SELECT u.id, u.email, u.full_name, u.is_active, u.created_at,
                t.id as tenant_id, t.name as tenant_name, t.slug as tenant_slug, t.plan as tenant_plan
         FROM users u
         JOIN tenants t ON t.id = u.tenant_id
         WHERE u.id = $1`,
        [userId]
      );

      if (resUser.rows.length === 0) {
        res.status(404).json({ error: 'USER_NOT_FOUND', message: 'User record not found.' });
        return;
      }

      const user = resUser.rows[0];

      res.status(200).json({
        user: {
          id: user.id,
          email: user.email,
          fullName: user.full_name,
          isActive: user.is_active,
          createdAt: user.created_at,
          tenant: {
            id: user.tenant_id,
            name: user.tenant_name,
            slug: user.tenant_slug,
            plan: user.tenant_plan
          },
          roles: req.user!.roles,
          permissions: req.user!.permissions
        }
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * @route GET /api/v1/auth/jwks.json
 * @desc Standard JSON Web Key Set (JWKS) endpoint for downstream microservices token validation
 */
authRouter.get('/jwks.json', (_req: Request, res: Response): void => {
  const jwks = getJWKS();
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.status(200).json(jwks);
});

/**
 * @route GET /api/v1/auth/public-key
 * @desc Raw RSA Public Key in PEM format
 */
authRouter.get('/public-key', (_req: Request, res: Response): void => {
  const { publicKey } = ensureKeyPair();
  res.setHeader('Content-Type', 'text/plain');
  res.status(200).send(publicKey);
});
