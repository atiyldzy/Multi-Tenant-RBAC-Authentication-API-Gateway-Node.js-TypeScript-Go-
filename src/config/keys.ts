import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { config } from './index.js';

let cachedPrivateKey: string | null = null;
let cachedPublicKey: string | null = null;

export function ensureKeyPair(): { privateKey: string; publicKey: string } {
  if (cachedPrivateKey && cachedPublicKey) {
    return { privateKey: cachedPrivateKey, publicKey: cachedPublicKey };
  }

  const privPath = config.jwt.privateKeyPath;
  const pubPath = config.jwt.publicKeyPath;

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    cachedPrivateKey = fs.readFileSync(privPath, 'utf8');
    cachedPublicKey = fs.readFileSync(pubPath, 'utf8');
    return { privateKey: cachedPrivateKey, publicKey: cachedPublicKey };
  }

  // If keys do not exist on disk, generate an in-memory 2048-bit RSA pair and save to directory
  const keysDir = path.dirname(privPath);
  if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir, { recursive: true });
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  try {
    fs.writeFileSync(privPath, privateKey, { mode: 0o600 });
    fs.writeFileSync(pubPath, publicKey, { mode: 0o644 });
  } catch {
    // In read-only filesystems, fallback to memory
  }

  cachedPrivateKey = privateKey;
  cachedPublicKey = publicKey;
  return { privateKey, publicKey };
}

export function getJWKS(): { keys: Array<Record<string, unknown>> } {
  const { publicKey } = ensureKeyPair();
  const keyObject = crypto.createPublicKey(publicKey);
  const jwk = keyObject.export({ format: 'jwk' });

  return {
    keys: [
      {
        ...jwk,
        use: 'sig',
        alg: 'RS256',
        kid: 'auth-gateway-primary-key'
      }
    ]
  };
}
