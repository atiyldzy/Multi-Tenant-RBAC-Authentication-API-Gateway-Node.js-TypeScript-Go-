import { Request, Response, NextFunction } from 'express';
import { query } from '../database/db.js';

export interface AuditRecord {
  tenantId?: string | null;
  userId?: string | null;
  ipAddress?: string;
  userAgent?: string;
  action: string;
  resource: string;
  statusCode?: number;
  details?: Record<string, any>;
}

export async function logAuditEvent(record: AuditRecord): Promise<void> {
  try {
    await query(
      `INSERT INTO audit_logs (tenant_id, user_id, ip_address, user_agent, action, resource, status_code, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        record.tenantId || null,
        record.userId || null,
        record.ipAddress || null,
        record.userAgent || null,
        record.action,
        record.resource,
        record.statusCode || 200,
        JSON.stringify(record.details || {})
      ]
    );
  } catch (err) {
    console.error('[AuditLogger] Failed to write audit record to database:', err);
  }
}

/**
 * Middleware that captures request lifecycle and records audit events for mutating actions
 */
export function auditLoggingMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Only auto-audit state-modifying requests or auth endpoints
  const isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
  const isAuth = req.originalUrl.includes('/auth/');

  if (!isMutating && !isAuth) {
    return next();
  }

  const startTime = Date.now();
  const originalEnd = res.end.bind(res);

  res.end = function (chunk?: any, encoding?: any, cb?: any): any {
    const duration = Date.now() - startTime;
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '';
    const userAgent = req.headers['user-agent'] || '';

    // Fire and forget audit insertion
    logAuditEvent({
      tenantId: req.user?.tenantId || req.body?.tenantId,
      userId: req.user?.sub,
      ipAddress: clientIp.split(',')[0].trim(),
      userAgent,
      action: `${req.method} ${req.baseUrl}${req.path}`,
      resource: req.baseUrl || req.path,
      statusCode: res.statusCode,
      details: {
        correlationId: req.correlationId,
        method: req.method,
        url: req.originalUrl,
        durationMs: duration,
        params: req.params,
        query: req.query
      }
    });

    return originalEnd(chunk, encoding, cb);
  } as any;

  next();
}
