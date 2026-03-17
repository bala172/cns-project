/** RSA (Rivest–Shamir–Adleman) Encryption
 *  Asymmetric encryption using public/private key pair.
 *  Uses Node.js crypto generateKeyPairSync for real RSA-2048 keys.
 *  Encryption uses OAEP padding for security.
 *
 *  NOTE: RSA encrypts small data (max ~214 bytes for 2048-bit key with OAEP).
 */

const crypto = require('crypto');

// In-memory key store per session (in production, use a database)
let currentKeyPair = null;

function rsaGenKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding:  { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
  });
  currentKeyPair = { publicKey, privateKey };
  return {
    publicKey,
    privateKey,
    keySize: 2048,
    message: 'RSA-2048 key pair generated successfully'
  };
}

function rsaEncrypt(plaintext) {
  // Auto-generate keys if none exist
  if (!currentKeyPair) rsaGenKeys();

  if (Buffer.byteLength(plaintext, 'utf8') > 200) {
    throw new Error('RSA input too long. Max ~200 characters for RSA-2048/OAEP.');
  }

  const encrypted = crypto.publicEncrypt(
    { key: currentKeyPair.publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    Buffer.from(plaintext, 'utf8')
  );
  return {
    plaintext,
    ciphertext: encrypted.toString('base64'),
    publicKey: currentKeyPair.publicKey,
    privateKey: currentKeyPair.privateKey,
    keySize: 2048
  };
}

function rsaDecrypt(ciphertext, privateKeyPem) {
  const pk = privateKeyPem || (currentKeyPair && currentKeyPair.privateKey);
  if (!pk) throw new Error('Private key required for RSA decryption. Generate keys first.');

  try {
    const decrypted = crypto.privateDecrypt(
      { key: pk, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(ciphertext, 'base64')
    );
    return { ciphertext, plaintext: decrypted.toString('utf8') };
  } catch (e) {
    throw new Error('RSA decryption failed. Ensure the correct private key is used.');
  }
}

module.exports = { rsaEncrypt, rsaDecrypt, rsaGenKeys };
