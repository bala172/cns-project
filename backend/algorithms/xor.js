/** XOR Encryption/Decryption
 *  Each character's ASCII value is XOR-ed with the numeric key.
 *  XOR is self-inverse: encrypt(encrypt(x)) = x, so decrypt = encrypt.
 */

function xorEncrypt(plaintext, key = 42) {
  const k = parseInt(key) || 42;
  const cipher = plaintext.split('').map(ch =>
    String.fromCharCode(ch.charCodeAt(0) ^ k)
  ).join('');
  // Represent as hex for readability
  const hex = Buffer.from(cipher, 'binary').toString('hex').toUpperCase();
  return { plaintext, ciphertext: hex, key: k };
}

function xorDecrypt(ciphertext, key = 42) {
  const k = parseInt(key) || 42;
  try {
    const bytes = Buffer.from(ciphertext, 'hex');
    const plain = bytes.toString('binary').split('').map(ch =>
      String.fromCharCode(ch.charCodeAt(0) ^ k)
    ).join('');
    return { ciphertext, plaintext: plain, key: k };
  } catch {
    // Try treating ciphertext as raw string
    const plain = ciphertext.split('').map(ch =>
      String.fromCharCode(ch.charCodeAt(0) ^ k)
    ).join('');
    return { ciphertext, plaintext: plain, key: k };
  }
}

module.exports = { xorEncrypt, xorDecrypt };
