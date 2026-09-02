const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8080;

// Enforce modern security headers via Helmet
app.use(helmet());

// Enforce strict CORS policy
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGIN || 'https://app.example.com',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'CSRF-Token'],
  })
);

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// Initialize CSRF protection middleware (resolves express-check-csurf-middleware-usage rule)
const csrfProtection = csrf({ cookie: { httpOnly: true, secure: true, sameSite: 'strict' } });
app.use(csrfProtection);

// Simulated in-memory database using parameterized query lookup pattern
const usersDb = new Map();

// Helper for constant time hash comparison to prevent timing attacks
function safeCompareHashes(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// Health Check Endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', service: 'nodejs-clean-baseline' });
});

// Endpoint to retrieve CSRF token for clients
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// User Retrieval with input type enforcement
app.get('/api/users/:id', (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (isNaN(userId) || userId <= 0) {
    return res.status(400).json({ error: 'Invalid user identifier format.' });
  }

  const user = usersDb.get(userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  return res.status(200).json({
    id: user.id,
    username: user.username,
    email: user.email,
  });
});

// User Registration Endpoint with safe password hashing and CSRF protection
app.post('/api/users', (req, res) => {
  const { username, email, password } = req.body;

  if (
    !username ||
    typeof username !== 'string' ||
    !/^[a-zA-Z0-9_-]{3,50}$/.test(username)
  ) {
    return res.status(400).json({ error: 'Invalid username format.' });
  }

  if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }

  if (!password || typeof password !== 'string' || password.length < 12) {
    return res.status(400).json({ error: 'Password must be at least 12 characters.' });
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');

  const newId = usersDb.size + 1;
  const userRecord = {
    id: newId,
    username,
    email,
    salt,
    hash,
  };

  usersDb.set(newId, userRecord);

  return res.status(201).json({
    id: newId,
    username,
    email,
  });
});

if (require.main === module) {
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`Server executing securely on port ${PORT}`);
  });
}

module.exports = app;
