import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';

export interface AppError extends Error {
  statusCode?: number;
  code?: string;
  details?: any;
}

export function errorHandler(
  err: AppError,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  const correlationId = req.correlationId;

  // Zod Validation Error
  if (err instanceof ZodError) {
    res.status(400).json({
      type: 'https://tools.ietf.org/html/rfc7807',
      title: 'Validation Failed',
      status: 400,
      detail: 'The provided request payload failed schema validation.',
      errors: err.errors.map(e => ({ field: e.path.join('.'), message: e.message })),
      correlationId
    });
    return;
  }

  // Handle specific database errors (e.g. Postgres unique violations)
  if ((err as any).code === '23505') {
    res.status(409).json({
      type: 'https://tools.ietf.org/html/rfc7807',
      title: 'Conflict',
      status: 409,
      detail: 'A record with this identifier or unique field already exists.',
      correlationId
    });
    return;
  }

  const statusCode = err.statusCode || 500;
  const message = statusCode === 500 && process.env.NODE_ENV === 'production'
    ? 'Internal Server Error'
    : err.message;

  console.error(`[Error] [Correlation: ${correlationId}]`, err);

  res.status(statusCode).json({
    type: 'https://tools.ietf.org/html/rfc7807',
    title: err.code || 'Internal Error',
    status: statusCode,
    detail: message,
    correlationId
  });
}
