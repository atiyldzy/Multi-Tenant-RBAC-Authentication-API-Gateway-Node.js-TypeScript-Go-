import pg from 'pg';
import { config } from '../config/index.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: config.db.connectionString,
  min: config.db.poolMin,
  max: config.db.poolMax,
  ssl: config.db.ssl ? { rejectUnauthorized: false } : false
});

pool.on('error', (err) => {
  console.error('[PostgreSQL] Unexpected error on idle client:', err);
});

export async function query<T extends pg.QueryResultRow = any>(
  text: string,
  params?: any[]
): Promise<pg.QueryResult<T>> {
  const start = Date.now();
  const res = await pool.query<T>(text, params);
  const duration = Date.now() - start;
  if (config.env === 'development') {
    // console.log(`[PostgreSQL Query] (${duration}ms):`, text, params);
  }
  return res;
}

export async function getClient(): Promise<pg.PoolClient> {
  return await pool.connect();
}

export async function checkDbHealth(): Promise<boolean> {
  try {
    const res = await query('SELECT 1 as healthy');
    return res.rows[0]?.healthy === 1;
  } catch (err) {
    console.error('[PostgreSQL] Health check failed:', err);
    return false;
  }
}
