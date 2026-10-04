import { Request, Response, NextFunction } from 'express';
import { checkRateLimit } from '../redis/rateLimiter.js';

export interface RateLimitOptions {
  windowSeconds?: number;
  maxRequests?: number;
  keyPrefix?: string;
  scope?: 'ip' | 'user' | 'tenant' | 'global';
}

export function rateLimiter(options: RateLimitOptions = {}) {
  const windowSec = options.windowSeconds || 60;
  const maxReq = options.maxRequests || 100;
  const prefix = options.keyPrefix || 'route';
  const scope = options.scope || 'ip';

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    let identifier: string;

    if (scope === 'user' && req.user?.sub) {
      identifier = `user:${req.user.sub}`;
    } else if (scope === 'tenant' && req.user?.tenantId) {
      identifier = `tenant:${req.user.tenantId}`;
    } else {
      const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
      identifier = `ip:${clientIp.split(',')[0].trim()}`;
    }

    const routePath = req.baseUrl + (req.route?.path || req.path);
    const rateKey = `${prefix}:${routePath}:${identifier}`;

    try {
      const result = await checkRateLimit(rateKey, maxReq, windowSec);

      res.setHeader('X-RateLimit-Limit', maxReq);
      res.setHeader('X-RateLimit-Remaining', result.remaining);
      res.setHeader('X-RateLimit-Reset', Math.ceil(result.resetTimeMs / 1000));

      if (!result.allowed) {
        const retryAfterSec = Math.max(1, Math.ceil((result.resetTimeMs - Date.now()) / 1000));
        res.setHeader('Retry-After', retryAfterSec);
        res.status(429).json({
          error: 'TOO_MANY_REQUESTS',
          message: 'Rate limit exceeded. Please try again later.',
          retryAfterSeconds: retryAfterSec
        });
        return;
      }

      next();
    } catch (err) {
      console.error('[RateLimitMiddleware] Unexpected error:', err);
      // In case of rate limiter catastrophic failure, allow request to proceed (fail-open)
      next();
    }
  };
}
