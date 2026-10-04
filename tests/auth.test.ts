import { signAccessToken, verifyAccessToken } from '../src/security/jwt.js';
import { blacklistToken, isTokenBlacklisted } from '../src/redis/tokenBlacklist.js';
import { hashPassword, verifyPassword } from '../src/security/crypto.js';

describe('Authentication & RS256 Cryptography Suite', () => {
  const mockUser = {
    sub: '11111111-1111-1111-1111-111111111111',
    tenantId: '22222222-2222-2222-2222-222222222222',
    email: 'architect@enterprise.io',
    roles: ['TenantAdmin'],
    permissions: ['users:read', 'users:write', 'proxy:access']
  };

  test('Should sign and verify RS256 token successfully', async () => {
    const { token, jti } = signAccessToken(mockUser);
    expect(token).toBeDefined();
    expect(typeof token).toBe('string');
    expect(jti).toBeDefined();

    const decoded = await verifyAccessToken(token);
    expect(decoded.sub).toBe(mockUser.sub);
    expect(decoded.tenantId).toBe(mockUser.tenantId);
    expect(decoded.roles).toContain('TenantAdmin');
    expect(decoded.permissions).toContain('proxy:access');
    expect(decoded.jti).toBe(jti);
  });

  test('Should reject tampered token signature', async () => {
    const { token } = signAccessToken(mockUser);
    const tamperedToken = token.slice(0, -5) + 'AAAAA';

    await expect(verifyAccessToken(tamperedToken)).rejects.toThrow();
  });

  test('Should enforce token revocation blacklist via JTI', async () => {
    const { token, jti } = signAccessToken(mockUser);
    
    // Ensure token works before revocation
    const decodedBefore = await verifyAccessToken(token);
    expect(decodedBefore.jti).toBe(jti);

    // Blacklist token
    await blacklistToken(jti, 60);
    const isRevoked = await isTokenBlacklisted(jti);
    expect(isRevoked).toBe(true);

    // Verification should now fail
    await expect(verifyAccessToken(token)).rejects.toThrow('TOKEN_REVOKED');
  });

  test('Should correctly hash and verify passwords using bcrypt', async () => {
    const password = 'SuperSecurePassword2026!';
    const hash = await hashPassword(password);

    expect(hash).not.toBe(password);
    expect(await verifyPassword(password, hash)).toBe(true);
    expect(await verifyPassword('WrongPassword', hash)).toBe(false);
  });
});
