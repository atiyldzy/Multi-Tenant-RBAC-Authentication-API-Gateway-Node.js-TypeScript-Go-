import express, { Express, Request, Response } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import swaggerUi from 'swagger-ui-express';
import fs from 'fs';
import path from 'path';

import { config } from './config/index.js';
import { requestContextMiddleware } from './middleware/requestContext.js';
import { auditLoggingMiddleware } from './middleware/auditLogger.js';
import { errorHandler } from './middleware/errorHandler.js';
import { checkDbHealth } from './database/db.js';
import { isRedisConnected } from './redis/client.js';

import { authRouter } from './routes/auth.routes.js';
import { tenantRouter } from './routes/tenant.routes.js';
import { userRouter } from './routes/user.routes.js';
import { gatewayConfigRouter } from './routes/gateway.routes.js';
import { auditRouter } from './routes/audit.routes.js';
import { proxyRouter } from './routes/proxy.routes.js';



export function createApp(): Express {
  const app = express();

  // 1. Security & Core Middlewares
  app.use(helmet({
    contentSecurityPolicy: false // Allows Swagger UI to render assets cleanly
  }));
  app.use(cors({
    origin: config.security.corsOrigin,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Correlation-ID', 'X-Tenant-ID']
  }));
  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ extended: true }));

  // 2. Correlation Tracking & Logging
  app.use(requestContextMiddleware);
  if (config.env !== 'test') {
    app.use(morgan(':method :url :status :res[content-length] - :response-time ms [CID: :req[x-correlation-id]]'));
  }
  app.use(auditLoggingMiddleware);

  // 3. Health & Readiness Probes
  app.get('/health', async (_req: Request, res: Response) => {
    const dbHealthy = await checkDbHealth();
    const redisHealthy = isRedisConnected();
    const status = dbHealthy ? 'HEALTHY' : 'DEGRADED';

    res.status(dbHealthy ? 200 : 503).json({
      status,
      timestamp: new Date().toISOString(),
      services: {
        database: dbHealthy ? 'UP' : 'DOWN',
        redis: redisHealthy ? 'UP' : 'IN_MEMORY_FALLBACK'
      }
    });
  });

  // 4. OpenAPI / Swagger Documentation
  try {
    const openApiPath = path.resolve(process.cwd(), 'openapi.json');
    if (fs.existsSync(openApiPath)) {
      const swaggerDoc = JSON.parse(fs.readFileSync(openApiPath, 'utf8'));
      app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDoc));
      app.get('/openapi.json', (_req, res) => res.json(swaggerDoc));
    }
  } catch (err) {
    console.warn('[App] Could not load OpenAPI specification for Swagger UI:', err);
  }

  // 5. Register Microservice / Gateway Routes
  app.use(`${config.apiPrefix}/auth`, authRouter);
  app.use(`${config.apiPrefix}/tenants`, tenantRouter);
  app.use(`${config.apiPrefix}/tenants/:tenantId/users`, userRouter);
  app.use(`${config.apiPrefix}/gateway`, gatewayConfigRouter);
  app.use(`${config.apiPrefix}/audit`, auditRouter);

  // 6. Dynamic API Gateway Proxy Catch-All
  app.use(config.gatewayPrefix, proxyRouter);

  // 7. 404 Handler
  app.use((req: Request, res: Response) => {
    res.status(404).json({
      type: 'https://tools.ietf.org/html/rfc7807',
      title: 'Resource Not Found',
      status: 404,
      detail: `Path '${req.originalUrl}' does not exist on this gateway.`,
      correlationId: req.correlationId
    });
  });

  // 8. Global Error Handler
  app.use(errorHandler);

  return app;
}
