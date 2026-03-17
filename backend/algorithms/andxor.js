/** AND/XOR with 127
 *  Step 1: AND each character's ASCII with 127 (masks top bit → keeps 7-bit ASCII)
 *  Step 2: XOR the result with 127
 *  This is a simple bitwise transformation used in early obfuscation.
 */

function andXorEncrypt(plaintext) {
  const cipher = plaintext.split('').map(ch => {
    const c = ch.charCodeAt(0);
    return String.fromCharCode((c & 127) ^ 127);
  }).join('');
  const hex = Buffer.from(cipher, 'binary').toString('hex').toUpperCase();
  return { plaintext, ciphertext: hex, key: '127 (fixed)' };
}

function andXorDecrypt(ciphertext) {
  try {
    const bytes = Buffer.from(ciphertext, 'hex');
    const plain = bytes.toString('binary').split('').map(ch => {
      const c = ch.charCodeAt(0);
      return String.fromCharCode((c ^ 127) & 127);
    }).join('');
    return { ciphertext, plaintext: plain, key: '127 (fixed)' };
  } catch {
    const plain = ciphertext.split('').map(ch => {
      const c = ch.charCodeAt(0);
      return String.fromCharCode((c ^ 127) & 127);
    }).join('');
    return { ciphertext, plaintext: plain, key: '127 (fixed)' };
  }
}

module.exports = { andXorEncrypt, andXorDecrypt };
