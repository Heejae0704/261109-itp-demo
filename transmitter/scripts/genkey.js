// Generate a persistent RS256 signing key for the transmitter.
// Prints a single-line value you can paste into Railway as SIGNING_KEY_PEM.
import crypto from 'node:crypto';

const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });

console.log('# Paste this into Railway > Variables as SIGNING_KEY_PEM (one line, \\n escaped):\n');
console.log(pem.trim().replace(/\n/g, '\\n'));
