/** DES (Data Encryption Standard) - Simplified Simulation
 *  Full DES uses 56-bit keys and 16 Feistel rounds.
 *  This implementation simulates DES-like operations using Node's crypto module
 *  with a deterministic key derivation for educational demonstration.
 */

const crypto = require('crypto');

function deriveDesKey(key) {
  // DES needs exactly 8 bytes (64-bit key, 56 effective bits)
  const k = Buffer.alloc(8);
  const keyBuf = Buffer.from(key || 'DESKey01', 'utf8');
  for (let i = 0; i < 8; i++) k[i] = keyBuf[i % keyBuf.length];
  return k;
}

function desEncrypt(plaintext, key) {
  const desKey = deriveDesKey(key);
  // DES requires 8-byte block — CBC mode with zero IV for simplicity
  const iv = Buffer.alloc(8, 0);
  const cipher = crypto.createCipheriv('des-cbc', desKey, iv);
  cipher.setAutoPadding(true);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return {
    plaintext,
    ciphertext: encrypted.toUpperCase(),
    key: desKey.toString('hex').toUpperCase()
  };
}

function desDecrypt(ciphertext, key) {
  const desKey = deriveDesKey(key);
  const iv = Buffer.alloc(8, 0);
  try {
    const decipher = crypto.createDecipheriv('des-cbc', desKey, iv);
    decipher.setAutoPadding(true);
    let decrypted = decipher.update(ciphertext.toLowerCase(), 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return { ciphertext, plaintext: decrypted, key: desKey.toString('hex').toUpperCase() };
  } catch (e) {
    throw new Error('DES decryption failed: ' + e.message);
  }
}

module.exports = { desEncrypt, desDecrypt };
