/**
 * Cryptography Lab Simulator - Backend Server
 * Node.js + Express.js server with JWT authentication
 */

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'cryptolab_secret_key_2024';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// ─── In-memory user store (replace with MongoDB in production) ─────────────────
const users = [];

// Pre-seed a demo user: admin / password123
(async () => {
  const hash = await bcrypt.hash('password123', 10);
  users.push({ id: 1, username: 'admin', password: hash });
})();

// ─── Middleware: Verify JWT token ──────────────────────────────────────────────
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// ─── Import algorithm modules ──────────────────────────────────────────────────
const { xorEncrypt, xorDecrypt }             = require('./algorithms/xor');
const { andXorEncrypt, andXorDecrypt }       = require('./algorithms/andxor');
const { caesarEncrypt, caesarDecrypt }       = require('./algorithms/caesar');
const { substEncrypt, substDecrypt }         = require('./algorithms/substitution');
const { hillEncrypt, hillDecrypt }           = require('./algorithms/hillcipher');
const { desEncrypt, desDecrypt }             = require('./algorithms/des');
const { blowfishEncrypt, blowfishDecrypt }   = require('./algorithms/blowfish');
const { aesEncrypt, aesDecrypt }             = require('./algorithms/aes');
const { rsaEncrypt, rsaDecrypt, rsaGenKeys } = require('./algorithms/rsa');

// ─── Security strength map ─────────────────────────────────────────────────────
const securityStrength = {
  xor: 10, andxor: 15, caesar: 20, substitution: 30,
  hill: 50, des: 65, blowfish: 80, aes: 95, rsa: 98
};

// ─── Routes ────────────────────────────────────────────────────────────────────

// POST /login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ token, username: user.username });
});

// POST /register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });
  if (users.find(u => u.username === username))
    return res.status(409).json({ error: 'Username already exists' });

  const hash = await bcrypt.hash(password, 10);
  users.push({ id: users.length + 1, username, password: hash });
  res.json({ message: 'User registered successfully' });
});

// GET /algorithms - list all algorithms
app.get('/algorithms', authenticateToken, (req, res) => {
  res.json({
    encryption: [
      { id: 'xor',          name: 'XOR Encryption',      requiresKey: true,  keyType: 'number' },
      { id: 'andxor',       name: 'AND/XOR with 127',    requiresKey: false, keyType: null },
      { id: 'caesar',       name: 'Caesar Cipher',       requiresKey: true,  keyType: 'number' },
      { id: 'substitution', name: 'Substitution Cipher', requiresKey: true,  keyType: 'text' },
      { id: 'hill',         name: 'Hill Cipher',         requiresKey: true,  keyType: 'matrix' },
      { id: 'des',          name: 'DES Algorithm',       requiresKey: true,  keyType: 'text' },
      { id: 'blowfish',     name: 'Blowfish Algorithm',  requiresKey: true,  keyType: 'text' },
      { id: 'aes',          name: 'Rijndael (AES)',       requiresKey: true,  keyType: 'text' },
      { id: 'rsa',          name: 'RSA Encryption',      requiresKey: false, keyType: 'keypair' }
    ]
  });
});

// POST /encrypt
app.post('/encrypt', authenticateToken, (req, res) => {
  const { algorithm, plaintext, key } = req.body;
  if (!algorithm || !plaintext)
    return res.status(400).json({ error: 'Algorithm and plaintext required' });

  try {
    let result = {};
    switch (algorithm) {
      case 'xor':          result = xorEncrypt(plaintext, key); break;
      case 'andxor':       result = andXorEncrypt(plaintext); break;
      case 'caesar':       result = caesarEncrypt(plaintext, parseInt(key) || 3); break;
      case 'substitution': result = substEncrypt(plaintext, key); break;
      case 'hill':         result = hillEncrypt(plaintext, key); break;
      case 'des':          result = desEncrypt(plaintext, key); break;
      case 'blowfish':     result = blowfishEncrypt(plaintext, key); break;
      case 'aes':          result = aesEncrypt(plaintext, key); break;
      case 'rsa':          result = rsaEncrypt(plaintext); break;
      default: return res.status(400).json({ error: 'Unknown algorithm' });
    }
    res.json({ ...result, security: securityStrength[algorithm] || 50, algorithm });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /decrypt
app.post('/decrypt', authenticateToken, (req, res) => {
  const { algorithm, ciphertext, key } = req.body;
  if (!algorithm || !ciphertext)
    return res.status(400).json({ error: 'Algorithm and ciphertext required' });

  try {
    let result = {};
    switch (algorithm) {
      case 'xor':          result = xorDecrypt(ciphertext, key); break;
      case 'andxor':       result = andXorDecrypt(ciphertext); break;
      case 'caesar':       result = caesarDecrypt(ciphertext, parseInt(key) || 3); break;
      case 'substitution': result = substDecrypt(ciphertext, key); break;
      case 'hill':         result = hillDecrypt(ciphertext, key); break;
      case 'des':          result = desDecrypt(ciphertext, key); break;
      case 'blowfish':     result = blowfishDecrypt(ciphertext, key); break;
      case 'aes':          result = aesDecrypt(ciphertext, key); break;
      case 'rsa':          result = rsaDecrypt(ciphertext, key); break;
      default: return res.status(400).json({ error: 'Unknown algorithm' });
    }
    res.json({ ...result, security: securityStrength[algorithm] || 50, algorithm });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /keygen - generate RSA key pair
app.post('/keygen', authenticateToken, (req, res) => {
  try {
    const keys = rsaGenKeys();
    res.json(keys);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve HTML pages
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../frontend/login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, '../frontend/dashboard.html')));
app.get('/encryption', (req, res) => res.sendFile(path.join(__dirname, '../frontend/encryption.html')));
app.get('/decryption', (req, res) => res.sendFile(path.join(__dirname, '../frontend/decryption.html')));

app.listen(PORT, () => console.log(`🔐 Cryptography Lab running at http://localhost:${PORT}`));
