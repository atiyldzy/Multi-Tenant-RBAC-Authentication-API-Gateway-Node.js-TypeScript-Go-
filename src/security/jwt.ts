import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config/index.js';
import { ensureKeyPair } from '../config/keys.js';
import { blacklistToken, isTokenBlacklisted } from '../redis/tokenBlacklist.js';
import { query } from '../database/db.js';
import { generateSecureToken, hashToken } from './crypto.js';

export interface TokenPayload {
  sub: string;             // User ID
  tenantId: string;        // Organization / Tenant ID
  email: string;
  roles: string[];
  permissions: string[];
  jti: string;             // JWT ID for revocation
  iat?: number;
  exp?: number;
  iss?: string;
  aud?: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresIn: number;
}

/**
 * Generate RS256 Signed Access Token
 */
export function signAccessToken(payload: Omit<TokenPayload, 'jti' | 'iat' | 'exp' | 'iss' | 'aud'>): { token: string; jti: string } {
  const { privateKey } = ensureKeyPair();
  const jti = uuidv4();

  const fullPayload: TokenPayload = {
    ...payload,
    jti
  };

  const token = jwt.sign(fullPayload, privateKey, {
    algorithm: 'RS256',
    expiresIn: config.jwt.accessExpirationSec,
    issuer: config.jwt.issuer,
    audience: config.jwt.audience,
    keyid: 'auth-gateway-primary-key'
  });

  return { token, jti };
}

/**
 * Verify RS256 Signed Access Token & Check Blacklist
 */
export async function verifyAccessToken(token: string): Promise<TokenPayload> {
  const { publicKey } = ensureKeyPair();

  const decoded = jwt.verify(token, publicKey, {
    algorithms: ['RS256'],
    issuer: config.jwt.issuer,
    audience: config.jwt.audience
  }) as TokenPayload;

  if (decoded.jti && await isTokenBlacklisted(decoded.jti)) {
    throw new Error('TOKEN_REVOKED');
  }

  return decoded;
}

/**
 * Create a new Refresh Token in Database with Token Family ID
 */
export async function createRefreshToken(
  userId: string,
  tenantId: string,
  existingFamilyId?: string
): Promise<string> {
  const rawToken = generateSecureToken(40);
  const tokenHashed = hashToken(rawToken);
  const familyId = existingFamilyId || uuidv4();
  const expiresAt = new Date(Date.now() + config.jwt.refreshExpirationSec * 1000);

  await query(
    `INSERT INTO refresh_tokens (user_id, tenant_id, token_hash, family_id, expires_at)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, tenantId, tokenHashed, familyId, expiresAt]
  );

  return rawToken;
}

/**
 * Rotate Refresh Token with Reuse Detection (Family Invalidation)
 */
export async function rotateRefreshToken(
  rawRefreshToken: string
): Promise<{ accessToken: string; refreshToken: string; userId: string; tenantId: string; roles: string[]; permissions: string[] }> {
  const tokenHashed = hashToken(rawRefreshToken);

  const res = await query(
    `SELECT rt.*, u.email, u.is_active as user_active, t.is_active as tenant_active
     FROM refresh_tokens rt
     JOIN users u ON u.id = rt.user_id
     JOIN tenants t ON t.id = rt.tenant_id
     WHERE rt.token_hash = $1`,
    [tokenHashed]
  );

  if (res.rows.length === 0) {
    throw new Error('INVALID_REFRESH_TOKEN');
  }

  const record = res.rows[0];

  // Token reuse attack detection: If token was already revoked, revoke the ENTIRE token family!
  if (record.is_revoked) {
    console.warn(`[Security Alert] Refresh token reuse detected for family ${record.family_id}. Revoking entire family.`);
    await query(
      `UPDATE refresh_tokens SET is_revoked = TRUE WHERE family_id = $1`,
      [record.family_id]
    );
    throw new Error('TOKEN_REUSE_DETECTED');
  }

  if (new Date() > new Date(record.expires_at)) {
    throw new Error('REFRESH_TOKEN_EXPIRED');
  }

  if (!record.user_active || !record.tenant_active) {
    throw new Error('ACCOUNT_INACTIVE');
  }

  // Revoke current refresh token
  await query(
    `UPDATE refresh_tokens SET is_revoked = TRUE, last_used_at = NOW() WHERE id = $1`,
    [record.id]
  );

  // Fetch updated user roles and permissions
  const rolesRes = await query(
    `SELECT r.name as role_name
     FROM user_roles ur
     JOIN roles r ON r.id = ur.role_id
     WHERE ur.user_id = $1 AND ur.tenant_id = $2`,
    [record.user_id, record.tenant_id]
  );
  const roles = rolesRes.rows.map(r => r.role_name);

  const permRes = await query(
    `SELECT DISTINCT p.name as permission_name
     FROM user_roles ur
     JOIN role_permissions rp ON rp.role_id = ur.role_id
     JOIN permissions p ON p.id = rp.permission_id
     WHERE ur.user_id = $1 AND ur.tenant_id = $2`,
    [record.user_id, record.tenant_id]
  );
  const permissions = permRes.rows.map(p => p.permission_name);

  // Generate new Access Token and new rotated Refresh Token in the same family
  const { token: accessToken } = signAccessToken({
    sub: record.user_id,
    tenantId: record.tenant_id,
    email: record.email,
    roles,
    permissions
  });

  const newRefreshToken = await createRefreshToken(record.user_id, record.tenant_id, record.family_id);

  return {
    accessToken,
    refreshToken: newRefreshToken,
    userId: record.user_id,
    tenantId: record.tenant_id,
    roles,
    permissions
  };
}

/**
 * Revoke user session / refresh token & blacklist current access token
 */
export async function revokeTokenSession(
  accessTokenJti?: string,
  rawRefreshToken?: string
): Promise<void> {
  if (accessTokenJti) {
    await blacklistToken(accessTokenJti, config.jwt.accessExpirationSec);
  }

  if (rawRefreshToken) {
    const tokenHashed = hashToken(rawRefreshToken);
    await query(
      `UPDATE refresh_tokens SET is_revoked = TRUE WHERE token_hash = $1`,
      [tokenHashed]
    );
  }
}
