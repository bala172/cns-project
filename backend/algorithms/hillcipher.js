/** Hill Cipher
 *  Matrix-based polygraphic substitution cipher.
 *  Uses a 2×2 invertible matrix key (mod 26).
 *  Encrypts pairs of letters as column vectors multiplied by the key matrix.
 */

// Default 2x2 key matrix: [[3,3],[2,5]] — determinant = 9, gcd(9,26)=1
const DEFAULT_MATRIX = [[3, 3], [2, 5]];

function parseMatrix(keyStr) {
  // Accept "3,3,2,5" or "[[3,3],[2,5]]" format
  if (!keyStr) return DEFAULT_MATRIX;
  const nums = keyStr.replace(/[\[\]]/g, '').split(/[,\s]+/).map(Number).filter(n => !isNaN(n));
  if (nums.length === 4) return [[nums[0], nums[1]], [nums[2], nums[3]]];
  return DEFAULT_MATRIX;
}

function modInverse(a, m) {
  // Extended Euclidean Algorithm
  a = ((a % m) + m) % m;
  for (let x = 1; x < m; x++) {
    if ((a * x) % m === 1) return x;
  }
  throw new Error('Matrix is not invertible mod 26. Choose a different key.');
}

function invertMatrix2x2(mat) {
  const [[a, b], [c, d]] = mat;
  const det = ((a * d - b * c) % 26 + 26) % 26;
  const detInv = modInverse(det, 26);
  return [
    [(d * detInv % 26 + 26) % 26,  ((-b * detInv) % 26 + 26) % 26],
    [((-c * detInv) % 26 + 26) % 26, (a * detInv % 26 + 26) % 26]
  ];
}

function hillEncrypt(plaintext, key) {
  const mat = parseMatrix(key);
  // Keep only alpha, pad to even length
  let text = plaintext.toUpperCase().replace(/[^A-Z]/g, '');
  if (text.length % 2 !== 0) text += 'X';

  let cipher = '';
  for (let i = 0; i < text.length; i += 2) {
    const v0 = text.charCodeAt(i) - 65;
    const v1 = text.charCodeAt(i + 1) - 65;
    const c0 = (mat[0][0] * v0 + mat[0][1] * v1) % 26;
    const c1 = (mat[1][0] * v0 + mat[1][1] * v1) % 26;
    cipher += String.fromCharCode(c0 + 65) + String.fromCharCode(c1 + 65);
  }
  const matStr = `[[${mat[0]}],[${mat[1]}]]`;
  return { plaintext, ciphertext: cipher, key: matStr };
}

function hillDecrypt(ciphertext, key) {
  const mat = parseMatrix(key);
  const invMat = invertMatrix2x2(mat);
  let text = ciphertext.toUpperCase().replace(/[^A-Z]/g, '');
  if (text.length % 2 !== 0) text += 'X';

  let plain = '';
  for (let i = 0; i < text.length; i += 2) {
    const v0 = text.charCodeAt(i) - 65;
    const v1 = text.charCodeAt(i + 1) - 65;
    const p0 = (invMat[0][0] * v0 + invMat[0][1] * v1) % 26;
    const p1 = (invMat[1][0] * v0 + invMat[1][1] * v1) % 26;
    plain += String.fromCharCode(p0 + 65) + String.fromCharCode(p1 + 65);
  }
  const matStr = `[[${mat[0]}],[${mat[1]}]]`;
  return { ciphertext, plaintext: plain, key: matStr };
}

module.exports = { hillEncrypt, hillDecrypt };
