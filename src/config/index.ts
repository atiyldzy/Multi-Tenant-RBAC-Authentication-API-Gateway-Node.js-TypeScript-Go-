import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.resolve(process.cwd(), '.env') });

export const config = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '4000', 10),
  apiPrefix: process.env.API_PREFIX || '/api/v1',
  gatewayPrefix: process.env.GATEWAY_PREFIX || '/gateway',

  db: {
    connectionString: process.env.DATABASE_URL || `postgres://${process.env.DB_USER || 'postgres'}:${process.env.DB_PASSWORD || 'postgres'}@${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || '5432'}/${process.env.DB_NAME || 'auth_gateway_db'}`,
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: process.env.DB_NAME || 'auth_gateway_db',
    poolMin: parseInt(process.env.DB_POOL_MIN || '2', 10),
    poolMax: parseInt(process.env.DB_POOL_MAX || '20', 10),
    ssl: process.env.DB_SSL === 'true'
  },

  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    password: process.env.REDIS_PASSWORD || undefined,
    db: parseInt(process.env.REDIS_DB || '0', 10)
  },

  jwt: {
    issuer: process.env.JWT_ISSUER || 'auth.gateway.enterprise',
    audience: process.env.JWT_AUDIENCE || 'enterprise.api.gateway',
    accessExpirationSec: parseInt(process.env.JWT_ACCESS_EXPIRATION_SECONDS || '900', 10), // 15 mins
    refreshExpirationSec: parseInt(process.env.JWT_REFRESH_EXPIRATION_SECONDS || '604800', 10), // 7 days
    privateKeyPath: process.env.KEY_PATH_PRIVATE || path.resolve(process.cwd(), 'keys', 'private.pem'),
    publicKeyPath: process.env.KEY_PATH_PUBLIC || path.resolve(process.cwd(), 'keys', 'public.pem')
  },

  rateLimit: {
    globalWindowSec: parseInt(process.env.RATE_LIMIT_GLOBAL_WINDOW_SEC || '60', 10),
    globalMax: parseInt(process.env.RATE_LIMIT_GLOBAL_MAX || '100', 10),
    authWindowSec: parseInt(process.env.RATE_LIMIT_AUTH_WINDOW_SEC || '60', 10),
    authMax: parseInt(process.env.RATE_LIMIT_AUTH_MAX || '10', 10)
  },

  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '12', 10),
    corsOrigin: process.env.CORS_ORIGIN || '*'
  }
};
