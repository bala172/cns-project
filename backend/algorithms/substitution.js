/** Substitution Cipher
 *  Uses a 26-character key string as the substitution alphabet.
 *  Each letter maps to the corresponding letter in the key.
 *  If no key provided, uses a default scrambled alphabet.
 */

const DEFAULT_KEY = 'QWERTYUIOPASDFGHJKLZXCVBNM';

function normalizeKey(key) {
  // Ensure key is 26 unique uppercase letters
  let k = (key || DEFAULT_KEY).toUpperCase().replace(/[^A-Z]/g, '');
  if (k.length !== 26) k = DEFAULT_KEY;
  return k;
}

function substEncrypt(plaintext, key) {
  const k = normalizeKey(key);
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const cipher = plaintext.toUpperCase().split('').map(ch => {
    const idx = alpha.indexOf(ch);
    return idx >= 0 ? k[idx] : ch;
  }).join('');
  return { plaintext, ciphertext: cipher, key: k };
}

function substDecrypt(ciphertext, key) {
  const k = normalizeKey(key);
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const plain = ciphertext.toUpperCase().split('').map(ch => {
    const idx = k.indexOf(ch);
    return idx >= 0 ? alpha[idx] : ch;
  }).join('');
  return { ciphertext, plaintext: plain, key: k };
}

module.exports = { substEncrypt, substDecrypt };
