import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { config } from '../config/index.js';

export async function hashPassword(plainPassword: string): Promise<string> {
  return await bcrypt.hash(plainPassword, config.security.bcryptRounds);
}

export async function verifyPassword(plainPassword: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(plainPassword, hash);
}

export function generateSecureToken(byteLength: number = 32): string {
  return crypto.randomBytes(byteLength).toString('hex');
}

export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function generateUUID(): string {
  return crypto.randomUUID();
}
