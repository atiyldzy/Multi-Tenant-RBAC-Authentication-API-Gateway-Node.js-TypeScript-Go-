import fs from 'fs';
import path from 'path';
import { pool, query } from './db.js';

export async function runMigrations(): Promise<void> {
  console.log('[Migrator] Initializing database migration runner...');

  // Ensure migrations tracking table exists
  await query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id SERIAL PRIMARY KEY,
      filename VARCHAR(255) NOT NULL UNIQUE,
      executed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
    );
  `);

  let migrationsDir = path.resolve(process.cwd(), 'src', 'database', 'migrations');
  if (!fs.existsSync(migrationsDir)) {
    migrationsDir = path.resolve(process.cwd(), 'dist', 'database', 'migrations');
  }
  if (!fs.existsSync(migrationsDir)) {
    console.log('[Migrator] No migrations folder found.');
    return;
  }

  const files = fs.readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  const appliedRes = await query('SELECT filename FROM schema_migrations');
  const appliedSet = new Set(appliedRes.rows.map(r => r.filename));

  for (const file of files) {
    if (appliedSet.has(file)) {
      continue;
    }

    console.log(`[Migrator] Applying migration: ${file}...`);
    const filePath = path.join(migrationsDir, file);
    const sqlContent = fs.readFileSync(filePath, 'utf8');

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(sqlContent);
      await client.query('INSERT INTO schema_migrations (filename) VALUES ($1)', [file]);
      await client.query('COMMIT');
      console.log(`[Migrator] Successfully applied ${file}`);
    } catch (error) {
      await client.query('ROLLBACK');
      console.error(`[Migrator] Failed to execute ${file}:`, error);
      throw error;
    } finally {
      client.release();
    }
  }

  console.log('[Migrator] All pending migrations executed successfully.');
}

if (process.argv[1] && process.argv[1].endsWith('migrator.ts')) {
  runMigrations()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[Migrator Fatal Error]', err);
      process.exit(1);
    });
}
