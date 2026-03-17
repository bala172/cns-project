/** Blowfish Cipher Simulation
 *  Blowfish uses variable-length keys (32–448 bits) and 16 Feistel rounds.
 *  Node.js crypto supports Blowfish via 'bf-cbc'.
 *  Key is derived to fit Blowfish's requirements.
 */

const crypto = require('crypto');

function deriveBlowfishKey(key) {
  // Blowfish key: 4–56 bytes. We derive a 16-byte key via SHA-256 truncation.
  const k = crypto.createHash('sha256').update(key || 'BlowfishKey').digest();
  return k.slice(0, 16); // 128-bit key
}

function blowfishEncrypt(plaintext, key) {
  const bfKey = deriveBlowfishKey(key);
  const iv = Buffer.alloc(8, 0);
  const cipher = crypto.createCipheriv('bf-cbc', bfKey, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return {
    plaintext,
    ciphertext: encrypted.toUpperCase(),
    key: bfKey.toString('hex').toUpperCase()
  };
}

function blowfishDecrypt(ciphertext, key) {
  const bfKey = deriveBlowfishKey(key);
  const iv = Buffer.alloc(8, 0);
  try {
    const decipher = crypto.createDecipheriv('bf-cbc', bfKey, iv);
    let decrypted = decipher.update(ciphertext.toLowerCase(), 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return { ciphertext, plaintext: decrypted, key: bfKey.toString('hex').toUpperCase() };
  } catch (e) {
    throw new Error('Blowfish decryption failed: ' + e.message);
  }
}

module.exports = { blowfishEncrypt, blowfishDecrypt };
