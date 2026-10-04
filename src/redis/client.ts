import { Redis } from 'ioredis';
import { config } from '../config/index.js';

export const redis = new Redis({
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password || undefined,
  db: config.redis.db,
  retryStrategy(times) {
    const delay = Math.min(times * 100, 3000);
    return delay;
  },
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  lazyConnect: true
});

let isConnected = false;

redis.on('connect', () => {
  isConnected = true;
  console.log('[Redis] Connected successfully.');
});

redis.on('error', (err) => {
  isConnected = false;
  // Log once in dev without crashing
  if (config.env === 'development') {
    // console.warn('[Redis] Connection warning:', err.message);
  }
});

export async function connectRedis(): Promise<void> {
  try {
    await redis.connect();
  } catch (err: any) {
    console.warn('[Redis] Could not establish immediate connection:', err?.message || err);
  }
}

export function isRedisConnected(): boolean {
  return isConnected && redis.status === 'ready';
}
