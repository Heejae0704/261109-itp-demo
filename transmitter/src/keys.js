// Signing key management.
//
// Okta verifies every SET against the JWKS the transmitter publishes, so the key
// must stay the same across restarts and redeploys. Set SIGNING_KEY_PEM (PKCS#8 PEM,
// generated with `npm run genkey`) in Railway. Without it, a throwaway key is created
// at boot, which is fine locally but breaks verification after every redeploy.
import crypto from 'node:crypto';
import { importPKCS8, exportJWK, calculateJwkThumbprint } from 'jose';

export const ALG = 'RS256'; // Okta requires RS256 for SET signatures.

export async function loadSigningKey() {
  let pem = process.env.SIGNING_KEY_PEM;
  if (pem) {
    // Railway variables often hold the PEM with literal "\n" sequences.
    pem = pem.includes('\\n') ? pem.replace(/\\n/g, '\n') : pem;
  } else {
    console.warn(
      '[keys] SIGNING_KEY_PEM is not set. Generating an ephemeral RSA key. ' +
        'Okta will reject SETs after a restart. Run `npm run genkey` and set SIGNING_KEY_PEM.'
    );
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  }

  const privateKey = await importPKCS8(pem, ALG, { extractable: true });

  // Derive the public JWK from the private key.
  const publicKeyObj = crypto.createPublicKey(crypto.createPrivateKey(pem));
  const publicJwk = await exportJWK(publicKeyObj);
  const kid = process.env.SIGNING_KEY_ID || (await calculateJwkThumbprint(publicJwk));

  return {
    privateKey,
    kid,
    publicJwk: { ...publicJwk, kid, use: 'sig', alg: ALG },
  };
}
