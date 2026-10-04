import { createApp } from './app.js';
import { config } from './config/index.js';
import { ensureKeyPair } from './config/keys.js';
import { runMigrations } from './database/migrator.js';
import { pool } from './database/db.js';
import { connectRedis, redis } from './redis/client.js';

async function bootstrap() {
  console.log('=====================================================');
  console.log('   Enterprise Multi-Tenant Auth & API Gateway');
  console.log('=====================================================');

  // Ensure Cryptographic Keys
  ensureKeyPair();
  console.log('[Bootstrap] Cryptographic RS256 keys initialized.');

  // Connect Redis
  await connectRedis();

  // Run Migrations automatically on startup
  try {
    await runMigrations();
  } catch (err) {
    console.warn('[Bootstrap] Database migration failed or database offline. Continuing with existing schema.');
  }

  const app = createApp();

  const server = app.listen(config.port, () => {
    console.log(`[Server] Listening on http://localhost:${config.port}`);
    console.log(`[Server] OpenAPI Docs: http://localhost:${config.port}/docs`);
    console.log(`[Server] Health Check: http://localhost:${config.port}/health`);
    console.log(`[Server] Dynamic Gateway Route: http://localhost:${config.port}${config.gatewayPrefix}/*`);
  });

  // Graceful Shutdown Handler
  const shutdown = async (signal: string) => {
    console.log(`\n[Shutdown] Received ${signal}. Terminating connections gracefully...`);

    server.close(async () => {
      console.log('[Shutdown] HTTP server closed.');

      try {
        await pool.end();
        console.log('[Shutdown] Database connection pool drained.');
      } catch (e) {
        console.error('[Shutdown] Error draining DB pool:', e);
      }

      try {
        await redis.quit();
        console.log('[Shutdown] Redis connection closed.');
      } catch (e) {
        // Ignore redis disconnect errors
      }

      console.log('[Shutdown] Service terminated safely.');
      process.exit(0);
    });

    // Force exit after 10 seconds if shutdown hangs
    setTimeout(() => {
      console.error('[Shutdown] Forced shutdown timed out.');
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

bootstrap().catch((err) => {
  console.error('[Bootstrap Fatal Error]', err);
  process.exit(1);
});
