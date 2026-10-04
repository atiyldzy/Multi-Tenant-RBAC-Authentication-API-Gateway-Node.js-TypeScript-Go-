import { redis, isRedisConnected } from './client.js';

// Fallback in-memory revocation map with TTL expiration
const inMemoryBlacklist = new Map<string, number>();

export async function blacklistToken(jti: string, ttlSeconds: number): Promise<void> {
  const key = `blacklist:${jti}`;
  if (isRedisConnected()) {
    try {
      await redis.set(key, 'revoked', 'EX', Math.max(ttlSeconds, 1));
      return;
    } catch (err) {
      console.warn('[TokenBlacklist] Redis blacklist failed, saving to fallback:', err);
    }
  }

  const expiresAt = Date.now() + (ttlSeconds * 1000);
  inMemoryBlacklist.set(key, expiresAt);
}

export async function isTokenBlacklisted(jti: string): Promise<boolean> {
  const key = `blacklist:${jti}`;
  if (isRedisConnected()) {
    try {
      const exists = await redis.exists(key);
      return exists === 1;
    } catch (err) {
      console.warn('[TokenBlacklist] Redis check failed, checking fallback:', err);
    }
  }

  const expiresAt = inMemoryBlacklist.get(key);
  if (!expiresAt) return false;

  if (Date.now() > expiresAt) {
    inMemoryBlacklist.delete(key);
    return false;
  }

  return true;
}
