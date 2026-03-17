# 🔐 Cryptography Lab Simulator

A full-stack web application simulating CNS (Cryptography and Network Security) laboratory experiments.

---

## 🚀 Quick Start

### Prerequisites
- Node.js v16+ installed
- (Optional) MongoDB — the app uses in-memory storage by default

### Installation

```bash
# 1. Clone / extract the project
cd cryptolab

# 2. Install backend dependencies
npm install

# 3. Start the server
npm start
```

Open **http://localhost:3000** in your browser.

**Demo credentials:**
- Username: `admin`
- Password: `password123`

---

## 📁 Project Structure

```
cryptolab/
│
├── frontend/
│   ├── login.html        — Login & Registration page
│   ├── dashboard.html    — Main dashboard
│   ├── encryption.html   — Encryption lab
│   ├── decryption.html   — Decryption lab
│   ├── styles.css        — Global dark theme stylesheet
│   └── auth.js           — Shared JWT auth helpers
│
├── backend/
│   ├── server.js         — Express.js API server
│   └── algorithms/
│       ├── xor.js        — XOR encryption
│       ├── andxor.js     — AND/XOR with 127
│       ├── caesar.js     — Caesar cipher
│       ├── substitution.js — Substitution cipher
│       ├── hillcipher.js — Hill cipher (matrix)
│       ├── des.js        — DES (Node crypto)
│       ├── blowfish.js   — Blowfish (Node crypto)
│       ├── aes.js        — AES-256 (Node crypto)
│       └── rsa.js        — RSA-2048 (Node crypto)
│
├── package.json
└── README.md
```

---

## 🔌 API Endpoints

| Method | Route        | Description               | Auth |
|--------|--------------|---------------------------|------|
| POST   | /login       | Authenticate user → JWT   | No   |
| POST   | /register    | Create new account        | No   |
| GET    | /algorithms  | List all algorithms       | Yes  |
| POST   | /encrypt     | Encrypt plaintext         | Yes  |
| POST   | /decrypt     | Decrypt ciphertext        | Yes  |
| POST   | /keygen      | Generate RSA key pair     | Yes  |

### Request examples

**POST /encrypt**
```json
{
  "algorithm": "caesar",
  "plaintext": "Hello World",
  "key": "3"
}
```

**Response**
```json
{
  "plaintext": "Hello World",
  "ciphertext": "Khoor Zruog",
  "key": 3,
  "security": 20,
  "algorithm": "caesar"
}
```

---

## 🔬 Supported Algorithms

| Algorithm         | Type       | Key Input       | Security |
|-------------------|------------|-----------------|----------|
| XOR Encryption    | Symmetric  | Numeric         | 10%      |
| AND/XOR with 127  | Symmetric  | None (fixed)    | 15%      |
| Caesar Cipher     | Symmetric  | Shift (1–25)    | 20%      |
| Substitution      | Symmetric  | 26-letter key   | 30%      |
| Hill Cipher       | Symmetric  | 2×2 matrix      | 50%      |
| DES               | Symmetric  | Text key        | 65%      |
| Blowfish          | Symmetric  | Text key        | 80%      |
| AES-256 (Rijndael)| Symmetric  | Text key        | 95%      |
| RSA-2048          | Asymmetric | Auto-generated  | 98%      |

---

## 🛠 Tech Stack

- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Backend**: Node.js, Express.js
- **Auth**: JWT (jsonwebtoken) + bcryptjs for password hashing
- **Crypto**: Node.js built-in `crypto` module (for DES/Blowfish/AES/RSA)
- **Database**: In-memory (replace `users[]` array in server.js with MongoDB)

### Adding MongoDB (optional)

```bash
npm install mongoose
```

Then replace the in-memory `users` array in `server.js` with a Mongoose model.

---

## 🔒 Security Notes

- Passwords hashed with bcrypt (salt rounds = 10)
- JWT tokens expire after 2 hours
- All `/encrypt`, `/decrypt`, `/keygen`, `/algorithms` routes require a valid JWT
- RSA uses OAEP padding (secure)
- AES uses 256-bit derived keys with CBC mode
- DES and Blowfish included for educational purposes only (considered insecure today)
