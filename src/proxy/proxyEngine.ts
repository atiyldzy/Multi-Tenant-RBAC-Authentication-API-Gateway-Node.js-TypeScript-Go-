import { Request, Response, NextFunction } from 'express';
import http from 'http';
import https from 'https';
import { URL } from 'url';
import { query } from '../database/db.js';
import { verifyAccessToken } from '../security/jwt.js';
import { hasRequiredRoles, hasRequiredPermissions } from '../security/rbac.js';
import { checkRateLimit } from '../redis/rateLimiter.js';

export interface GatewayRouteRecord {
  id: string;
  path_prefix: string;
  target_url: string;
  is_protected: boolean;
  required_roles: string[];
  required_permissions: string[];
  rate_limit_window_sec: number;
  rate_limit_max: number;
  is_active: boolean;
  strip_prefix: boolean;
  custom_headers: Record<string, string>;
  timeout_ms: number;
}

let routeCache: GatewayRouteRecord[] = [];
let lastRouteFetch = 0;
const CACHE_TTL_MS = 10000; // Refresh dynamic routes from DB every 10s

export async function getActiveGatewayRoutes(): Promise<GatewayRouteRecord[]> {
  const now = Date.now();
  if (now - lastRouteFetch < CACHE_TTL_MS && routeCache.length > 0) {
    return routeCache;
  }

  try {
    const res = await query<GatewayRouteRecord>(
      'SELECT * FROM gateway_routes WHERE is_active = TRUE ORDER BY LENGTH(path_prefix) DESC'
    );
    routeCache = res.rows;
    lastRouteFetch = now;
  } catch (err) {
    console.error('[ProxyEngine] Failed to load gateway routes from database:', err);
  }
  return routeCache;
}

export function invalidateRouteCache(): void {
  lastRouteFetch = 0;
}

/**
 * Dynamic Reverse Proxy Dispatcher
 */
export async function proxyRequestHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  const incomingPath = req.path;
  const routes = await getActiveGatewayRoutes();

  // Find longest matching prefix
  const matchedRoute = routes.find(r => incomingPath.startsWith(r.path_prefix));

  if (!matchedRoute) {
    res.status(404).json({
      error: 'ROUTE_NOT_FOUND',
      message: `No active gateway upstream route configured for path: ${incomingPath}`
    });
    return;
  }

  // 1. Authentication Check
  let authUser: any = null;
  if (matchedRoute.is_protected) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'This gateway endpoint requires a valid Bearer token.'
      });
      return;
    }

    try {
      const token = authHeader.split(' ')[1];
      authUser = await verifyAccessToken(token);
      req.user = authUser;
    } catch (err: any) {
      res.status(401).json({
        error: 'INVALID_TOKEN',
        message: err.message === 'TOKEN_REVOKED' ? 'Token revoked.' : 'Token validation failed.'
      });
      return;
    }

    // 2. Role & Permission Authorization
    if (matchedRoute.required_roles?.length > 0) {
      if (!hasRequiredRoles(authUser.roles, matchedRoute.required_roles)) {
        res.status(403).json({
          error: 'FORBIDDEN',
          message: `Insufficient role. Required: [${matchedRoute.required_roles.join(', ')}]`
        });
        return;
      }
    }

    if (matchedRoute.required_permissions?.length > 0) {
      if (!hasRequiredPermissions(authUser.permissions, matchedRoute.required_permissions)) {
        res.status(403).json({
          error: 'FORBIDDEN',
          message: `Insufficient permissions. Required: [${matchedRoute.required_permissions.join(', ')}]`
        });
        return;
      }
    }
  }

  // 3. Rate Limiting Check
  const rateLimitKey = authUser
    ? `proxy:${matchedRoute.id}:user:${authUser.sub}`
    : `proxy:${matchedRoute.id}:ip:${(req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim()}`;

  const rateResult = await checkRateLimit(
    rateLimitKey,
    matchedRoute.rate_limit_max,
    matchedRoute.rate_limit_window_sec
  );

  res.setHeader('X-RateLimit-Limit', matchedRoute.rate_limit_max);
  res.setHeader('X-RateLimit-Remaining', rateResult.remaining);
  res.setHeader('X-RateLimit-Reset', Math.ceil(rateResult.resetTimeMs / 1000));

  if (!rateResult.allowed) {
    const retrySec = Math.max(1, Math.ceil((rateResult.resetTimeMs - Date.now()) / 1000));
    res.setHeader('Retry-After', retrySec);
    res.status(429).json({
      error: 'TOO_MANY_REQUESTS',
      message: 'Rate limit exceeded for gateway route.',
      retryAfterSeconds: retrySec
    });
    return;
  }

  // 4. Construct Target URL
  let targetPath = incomingPath;
  if (matchedRoute.strip_prefix) {
    targetPath = incomingPath.substring(matchedRoute.path_prefix.length);
    if (!targetPath.startsWith('/')) {
      targetPath = '/' + targetPath;
    }
  }

  let fullTargetUrlStr = matchedRoute.target_url;
  if (fullTargetUrlStr.endsWith('/')) {
    fullTargetUrlStr = fullTargetUrlStr.slice(0, -1);
  }

  // Append remaining path if target is a base host
  let targetUrlObj: URL;
  try {
    targetUrlObj = new URL(fullTargetUrlStr);
    if (matchedRoute.strip_prefix && targetPath !== '/') {
      targetUrlObj.pathname = (targetUrlObj.pathname.endsWith('/') ? targetUrlObj.pathname.slice(0, -1) : targetUrlObj.pathname) + targetPath;
    }
    // Append query params
    const queryKeys = Object.keys(req.query);
    if (queryKeys.length > 0) {
      for (const k of queryKeys) {
        targetUrlObj.searchParams.set(k, String(req.query[k]));
      }
    }
  } catch (err) {
    res.status(500).json({ error: 'INVALID_TARGET_URL', message: 'Target URL configuration is invalid.' });
    return;
  }

  // 5. Prepare Forwarding Headers
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '';
  const forwardHeaders: Record<string, string | string[]> = {
    ...req.headers,
    host: targetUrlObj.host,
    'x-forwarded-for': clientIp.split(',')[0].trim(),
    'x-forwarded-proto': req.protocol,
    'x-correlation-id': req.correlationId || '',
    'x-gateway-source': 'Enterprise-Auth-Gateway'
  };

  if (authUser) {
    forwardHeaders['x-user-id'] = authUser.sub;
    forwardHeaders['x-tenant-id'] = authUser.tenantId;
    forwardHeaders['x-user-email'] = authUser.email;
    forwardHeaders['x-user-roles'] = (authUser.roles || []).join(',');
  }

  // Merge custom route headers
  if (matchedRoute.custom_headers) {
    for (const [k, v] of Object.entries(matchedRoute.custom_headers)) {
      forwardHeaders[k.toLowerCase()] = v;
    }
  }

  // 6. Forward Request
  const isHttps = targetUrlObj.protocol === 'https:';
  const transport = isHttps ? https : http;

  const proxyReq = transport.request(
    targetUrlObj.toString(),
    {
      method: req.method,
      headers: forwardHeaders as http.OutgoingHttpHeaders,
      timeout: matchedRoute.timeout_ms || 10000
    },
    (proxyRes) => {
      res.status(proxyRes.statusCode || 200);
      for (const [headerKey, headerVal] of Object.entries(proxyRes.headers)) {
        if (headerVal !== undefined) {
          res.setHeader(headerKey, headerVal);
        }
      }
      proxyRes.pipe(res);
    }
  );

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    if (!res.headersSent) {
      res.status(504).json({
        error: 'GATEWAY_TIMEOUT',
        message: `Downstream service did not respond within ${matchedRoute.timeout_ms}ms timeout window.`
      });
    }
  });

  proxyReq.on('error', (err) => {
    if (!res.headersSent) {
      res.status(502).json({
        error: 'BAD_GATEWAY',
        message: 'Unable to reach downstream microservice.',
        details: err.message
      });
    }
  });

  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && req.body) {
    const bodyData = typeof req.body === 'object' ? JSON.stringify(req.body) : req.body;
    proxyReq.write(bodyData);
  }

  proxyReq.end();
}
