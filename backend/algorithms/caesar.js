/** Caesar Cipher
 *  Shifts each letter by 'shift' positions in the alphabet.
 *  Non-alpha characters are preserved.
 *  Named after Julius Caesar who reportedly used shift=3.
 */

function caesarEncrypt(plaintext, shift = 3) {
  shift = ((parseInt(shift) % 26) + 26) % 26;
  const cipher = plaintext.split('').map(ch => {
    if (ch.match(/[a-z]/)) return String.fromCharCode(((ch.charCodeAt(0) - 97 + shift) % 26) + 97);
    if (ch.match(/[A-Z]/)) return String.fromCharCode(((ch.charCodeAt(0) - 65 + shift) % 26) + 65);
    return ch;
  }).join('');
  return { plaintext, ciphertext: cipher, key: shift };
}

function caesarDecrypt(ciphertext, shift = 3) {
  shift = ((parseInt(shift) % 26) + 26) % 26;
  const plain = ciphertext.split('').map(ch => {
    if (ch.match(/[a-z]/)) return String.fromCharCode(((ch.charCodeAt(0) - 97 - shift + 26) % 26) + 97);
    if (ch.match(/[A-Z]/)) return String.fromCharCode(((ch.charCodeAt(0) - 65 - shift + 26) % 26) + 65);
    return ch;
  }).join('');
  return { ciphertext, plaintext: plain, key: shift };
}

module.exports = { caesarEncrypt, caesarDecrypt };
