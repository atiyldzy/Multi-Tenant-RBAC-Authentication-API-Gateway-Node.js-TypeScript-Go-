import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from '../security/jwt.js';

export async function authenticateToken(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Missing or malformed Authorization header. Expected Bearer token.'
    });
    return;
  }

  const token = authHeader.split(' ')[1];

  try {
    const payload = await verifyAccessToken(token);
    req.user = {
      sub: payload.sub,
      tenantId: payload.tenantId,
      email: payload.email,
      roles: payload.roles,
      permissions: payload.permissions,
      jti: payload.jti
    };
    req.tenantId = payload.tenantId;
    next();
  } catch (err: any) {
    if (err.message === 'TOKEN_REVOKED') {
      res.status(401).json({
        error: 'TOKEN_REVOKED',
        message: 'This access token has been revoked / blacklisted.'
      });
      return;
    }
    if (err.name === 'TokenExpiredError') {
      res.status(401).json({
        error: 'TOKEN_EXPIRED',
        message: 'Access token has expired. Please refresh your session.'
      });
      return;
    }
    res.status(401).json({
      error: 'INVALID_TOKEN',
      message: 'Cryptographic validation failed or invalid token signature.'
    });
  }
}

/**
 * Optional authentication middleware for endpoints that can be accessed anonymously or authenticated
 */
export async function optionalAuthenticate(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next();
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = await verifyAccessToken(token);
    req.user = {
      sub: payload.sub,
      tenantId: payload.tenantId,
      email: payload.email,
      roles: payload.roles,
      permissions: payload.permissions,
      jti: payload.jti
    };
    req.tenantId = payload.tenantId;
  } catch {
    // Ignore invalid tokens on optional routes
  }
  next();
}
