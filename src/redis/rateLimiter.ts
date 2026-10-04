import { redis, isRedisConnected } from './client.js';

export interface RateLimitResult {
  allowed: boolean;
  totalHits: number;
  remaining: number;
  resetTimeMs: number;
}

// In-memory fallback sliding window store for testing or offline Redis scenarios
const inMemoryStore = new Map<string, number[]>();

// Redis Lua script for atomic sliding window rate limiting
const SLIDING_WINDOW_LUA = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local maxRequests = tonumber(ARGV[3])

local clearBefore = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', clearBefore)

local currentRequests = redis.call('ZCARD', key)
if currentRequests < maxRequests then
    redis.call('ZADD', key, now, now .. '-' .. math.random(100000, 999999))
    redis.call('PEXPIRE', key, window)
    return {1, maxRequests - currentRequests - 1, currentRequests + 1}
else
    return {0, 0, currentRequests}
end
`;

export async function checkRateLimit(
  key: string,
  limit: number,
  windowSeconds: number
): Promise<RateLimitResult> {
  const windowMs = windowSeconds * 1000;
  const now = Date.now();
  const resetTimeMs = now + windowMs;

  if (isRedisConnected()) {
    try {
      const fullKey = `rl:${key}`;
      const res = await redis.eval(
        SLIDING_WINDOW_LUA,
        1,
        fullKey,
        now,
        windowMs,
        limit
      ) as [number, number, number];

      const allowed = res[0] === 1;
      const remaining = Math.max(0, res[1]);
      const totalHits = res[2];

      return {
        allowed,
        totalHits,
        remaining,
        resetTimeMs
      };
    } catch (err) {
      console.warn('[RateLimiter] Redis rate check failed, using fallback:', err);
    }
  }

  // Fallback sliding window in-memory implementation
  const timestamps = inMemoryStore.get(key) || [];
  const cutoff = now - windowMs;
  const activeTimestamps = timestamps.filter(t => t > cutoff);

  if (activeTimestamps.length < limit) {
    activeTimestamps.push(now);
    inMemoryStore.set(key, activeTimestamps);
    return {
      allowed: true,
      totalHits: activeTimestamps.length,
      remaining: limit - activeTimestamps.length,
      resetTimeMs
    };
  }

  inMemoryStore.set(key, activeTimestamps);
  return {
    allowed: false,
    totalHits: activeTimestamps.length,
    remaining: 0,
    resetTimeMs
  };
}
