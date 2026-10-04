import { checkRateLimit } from '../src/redis/rateLimiter.js';

describe('Distributed Sliding-Window Rate Limiter Suite', () => {
  const testKey = `test-client-${Date.now()}`;
  const limit = 5;
  const windowSec = 2;

  test('Should allow requests within configured limit', async () => {
    for (let i = 0; i < limit; i++) {
      const res = await checkRateLimit(testKey, limit, windowSec);
      expect(res.allowed).toBe(true);
      expect(res.totalHits).toBe(i + 1);
      expect(res.remaining).toBe(limit - (i + 1));
    }
  });

  test('Should reject requests when limit is exceeded', async () => {
    const res = await checkRateLimit(testKey, limit, windowSec);
    expect(res.allowed).toBe(false);
    expect(res.remaining).toBe(0);
  });

  test('Should reset and allow requests after sliding window passes', async () => {
    // Wait for the 2-second window to expire
    await new Promise((resolve) => setTimeout(resolve, 2100));

    const res = await checkRateLimit(testKey, limit, windowSec);
    expect(res.allowed).toBe(true);
    expect(res.totalHits).toBe(1);
    expect(res.remaining).toBe(limit - 1);
  }, 10000);
});
