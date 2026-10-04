import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const keysDir = path.resolve(process.cwd(), 'keys');
const privPath = path.join(keysDir, 'private.pem');
const pubPath = path.join(keysDir, 'public.pem');

console.log('Generating 2048-bit RSA Keypair for RS256 JWT Signing...');

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

fs.writeFileSync(privPath, privateKey, { mode: 0o600 });
fs.writeFileSync(pubPath, publicKey, { mode: 0o644 });

console.log(`RSA Private Key written to: ${privPath}`);
console.log(`RSA Public Key written to: ${pubPath}`);
console.log('Key generation complete.');
