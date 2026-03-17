/** AES (Advanced Encryption Standard) / Rijndael
 *  AES-256-CBC using Node.js crypto.
 *  Key is derived using SHA-256 to ensure 256-bit length.
 *  IV is deterministically generated from the key for demo purposes.
 */

const crypto = require('crypto');

function deriveAesKey(key) {
  // Always produce a 32-byte (256-bit) key
  return crypto.createHash('sha256').update(key || 'AESDefaultKey!').digest();
}

function aesEncrypt(plaintext, key) {
  const aesKey = deriveAesKey(key);
  // Use first 16 bytes of key hash as IV (deterministic for demo)
  const iv = crypto.createHash('md5').update(key || 'AESDefaultKey!').digest();
  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return {
    plaintext,
    ciphertext: encrypted.toUpperCase(),
    key: aesKey.toString('hex').toUpperCase(),
    iv: iv.toString('hex').toUpperCase()
  };
}

function aesDecrypt(ciphertext, key) {
  const aesKey = deriveAesKey(key);
  const iv = crypto.createHash('md5').update(key || 'AESDefaultKey!').digest();
  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    let decrypted = decipher.update(ciphertext.toLowerCase(), 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return {
      ciphertext,
      plaintext: decrypted,
      key: aesKey.toString('hex').toUpperCase()
    };
  } catch (e) {
    throw new Error('AES decryption failed. Ensure correct key: ' + e.message);
  }
}

module.exports = { aesEncrypt, aesDecrypt };
