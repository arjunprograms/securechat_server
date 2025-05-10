require('dotenv').config();

let admin, bucket;
try {
  admin = require('firebase-admin');
  let serviceAccount;
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    console.log('Firebase credentials loaded from environment variable');
  } else {
    serviceAccount = require('./firebase-service-account.json');
    console.log('Firebase credentials loaded from local file');
  }
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || 'subedi-chat-files.appspot.com'
  });
  bucket = admin.storage().bucket();
  console.log('Firebase initialized successfully with bucket:', bucket.name);
} catch (err) {
  console.error('Firebase initialization error:', err);
  bucket = null;
}

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const formidable = require('formidable');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const { v4: uuidv4 } = require('uuid');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", "wss://securechat-server-1s4i.onrender.com"],
      imgSrc: ["'self'", "data:", "https://storage.googleapis.com"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
  crossOriginResourcePolicy: { policy: "cross-origin" },
}));

const csrfTokens = new Map();

app.get('/csrf-token', (req, res) => {
  const token = uuidv4();
  const clientIp = req.ip || req.connection.remoteAddress;
  csrfTokens.set(token, {
    ip: clientIp,
    expires: Date.now() + (15 * 60 * 1000)
  });
  if (Math.random() < 0.01) {
    cleanExpiredCsrfTokens();
  }
  res.json({ csrfToken: token });
});

function cleanExpiredCsrfTokens() {
  const now = Date.now();
  for (const [token, data] of csrfTokens.entries()) {
    if (data.expires < now) {
      csrfTokens.delete(token);
    }
  }
}

function verifyCsrfToken(req, res, next) {
  if (req.method === 'GET' || req.path === '/health') {
    return next();
  }
  const token = req.headers['x-csrf-token'];
  if (!token) {
    return res.status(403).json({ error: 'CSRF token missing' });
  }
  const tokenData = csrfTokens.get(token);
  if (!tokenData) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  if (tokenData.expires < Date.now()) {
    csrfTokens.delete(token);
    return res.status(403).json({ error: 'CSRF token expired' });
  }
  next();
}

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
  skip: (req) => req.path === '/health' || req.path === '/ws'
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts, please try again later.' }
});

const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 50,
  delayMs: (hits) => hits * 100,
});

app.use(apiLimiter);
app.use(speedLimiter);
app.use('/login', authLimiter);
app.use('/register', authLimiter);

const sanitizeInput = (req, res, next) => {
  if (req.body) {
    for (const key in req.body) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = req.body[key]
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;')
          .replace(/\//g, '&#x2F;');
      }
    }
  }
  next();
};

app.use(sanitizeInput);

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
  });
  next();
});

const suspiciousIPs = new Map();

app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const suspiciousData = suspiciousIPs.get(ip) || { count: 0, lastSeen: Date.now() };
  if (Date.now() - suspiciousData.lastSeen > 24 * 60 * 60 * 1000) {
    suspiciousData.count = 0;
  }
  suspiciousData.lastSeen = Date.now();
  if (req.path !== '/health' && req.path !== '/') {
    suspiciousData.count++;
    if (suspiciousData.count > 100) {
      console.log(`Suspicious activity detected from IP: ${ip}`);
      setTimeout(() => next(), 5000);
      return;
    }
  }
  suspiciousIPs.set(ip, suspiciousData);
  next();
});

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept', 'X-CSRF-Token']
}));

app.use(express.json());

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);

app.use('/uploads', express.static(uploadDir));

const connections = new Map();
const typingUsers = new Set();
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000;

function createLogger(username) {
  const timestamp = new Date().toISOString().replace(/:/g, '-');
  const filePath = path.join(logsDir, `${username}_${timestamp}.log`);
  return {
    log: (msg) => {
      try {
        fs.appendFileSync(filePath, `[${new Date().toISOString()}] ${msg}\n`);
      } catch (err) {
        console.error(`Error writing to log file for ${username}:`, err);
      }
    }
  };
}

function generateUniqueId() {
  return `${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
}

function broadcast(message, exclude = null) {
  if (message.recipient && message.recipient !== 'all') return;
  wss.clients.forEach(client => {
    if (client !== exclude && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

async function query(text, params) {
  try {
    const res = await pool.query(text, params);
    return res.rows;
  } catch (err) {
    console.error('Database query error:', err);
    throw err;
  }
}

async function getUserByUsername(username) {
  const rows = await query('SELECT * FROM users WHERE username = $1', [username]);
  return rows[0] || null;
}

app.options('*', cors());

app.post('/upload', verifyCsrfToken, async (req, res) => {
  try {
    res.header('Content-Type', 'application/json');
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Accept, X-CSRF-Token');

    if (!bucket) {
      console.error('Firebase storage not initialized');
      return res.status(503).json({ error: 'File storage service is not available' });
    }

    const form = new formidable.IncomingForm({
      maxFileSize: 5 * 1024 * 1024,
      keepExtensions: true,
      multiples: false,
      uploadDir: uploadDir
    });

    form.parse(req, async (err, fields, files) => {
      try {
        if (err) {
          console.error('Form parsing error:', err);
          return res.status(400).json({ error: 'Failed to parse file: ' + err.message });
        }

        const fileKey = Object.keys(files)[0];
        const file = files[fileKey];
        if (!file) {
          return res.status(400).json({ error: 'No file uploaded' });
        }

        const isEncrypted = fields.encrypted === 'true';
        const encryptedKey = fields.encryptedKey || null;
        const iv = fields.iv || null;
        const originalFilename = file.originalFilename || path.basename(file.filepath);
        const safeFilename = originalFilename.replace(/[^a-zA-Z0-9.-]/g, '_');
        const destFilename = `uploads/${Date.now()}_${safeFilename}`;

        const blob = bucket.file(destFilename);
        const blobStream = blob.createWriteStream({
          metadata: {
            contentType: file.mimetype,
            metadata: {
              originalName: originalFilename,
              encrypted: isEncrypted ? 'true' : 'false',
              encryptedKey,
              iv
            }
          },
          resumable: false
        });

        blobStream.on('error', err => {
          console.error('Upload to Firebase failed:', err);
          res.status(500).json({ error: 'Firebase upload failed: ' + err.message });
        });

        blobStream.on('finish', async () => {
          try {
            await blob.makePublic();
            const publicUrl = `https://storage.googleapis.com/${bucket.name}/${destFilename}`;
            console.log('File uploaded successfully to Firebase:', publicUrl);
            res.json({
              url: publicUrl,
              filename: originalFilename,
              type: file.mimetype,
              encrypted: isEncrypted,
              encryptedKey,
              iv
            });
          } catch (err) {
            console.error('Error making blob public:', err);
            res.status(500).json({ error: 'Failed to make file public: ' + err.message });
          }
        });

        fs.createReadStream(file.filepath).pipe(blobStream);
      } catch (err) {
        console.error('Upload processing error:', err);
        res.status(500).json({ error: 'Server error during upload: ' + err.message });
      }
    });
  } catch (err) {
    console.error('Unexpected error in /upload:', err);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

app.post('/register', verifyCsrfToken, async (req, res) => {
  try {
    const { username, password, displayName } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    const existingUser = await getUserByUsername(username);
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await query('INSERT INTO users (username, password, display_name) VALUES ($1, $2, $3)', [username, hashedPassword, displayName || username]);
    res.json({ message: 'Registration successful' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

app.post('/login', verifyCsrfToken, async (req, res) => {
  try {
    const { username, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const attempts = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };

    if (attempts.count >= MAX_LOGIN_ATTEMPTS && Date.now() - attempts.lastAttempt < LOCKOUT_TIME) {
      return res.status(429).json({ error: 'Too many login attempts, please try again later' });
    }

    const user = await getUserByUsername(username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      attempts.count++;
      attempts.lastAttempt = Date.now();
      loginAttempts.set(ip, attempts);
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    loginAttempts.delete(ip);
    res.json({ message: 'Login successful' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

app.post('/profile', verifyCsrfToken, async (req, res) => {
  try {
    const { username, displayName, status } = req.body;
    await query('UPDATE users SET display_name = $1, status = $2 WHERE username = $3', [displayName, status, username]);
    res.json({ message: 'Profile updated' });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ error: 'Server error during profile update' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  res.status(500).json({ error: 'Internal server error: ' + err.message });
});

wss.on('connection', (ws, req) => {
  const clientId = generateUniqueId();
  connections.set(clientId, { ws, username: null });

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      const conn = connections.get(clientId);

      if (data.type === 'auth') {
        const user = await getUserByUsername(data.username);
        if (user && await bcrypt.compare(data.password, user.password)) {
          conn.username = data.username;
          ws.send(JSON.stringify({ type: 'auth', success: true }));
          broadcast({ type: 'profile', username: data.username, displayName: user.display_name, status: user.status });
          const users = await query('SELECT username, display_name, status FROM users');
          ws.send(JSON.stringify({ type: 'userList', users }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Authentication failed' }));
          ws.close();
        }
      } else if (conn.username) {
        if (data.type === 'message' || data.type === 'file') {
          if (data.recipient === 'all') {
            broadcast(data, ws);
          } else {
            connections.forEach((client, id) => {
              if (client.username === data.recipient && client.ws.readyState === WebSocket.OPEN) {
                client.ws.send(JSON.stringify(data));
              }
            });
            if (data.username === conn.username) {
              ws.send(JSON.stringify(data));
            }
          }
        } else if (data.type === 'typing') {
          connections.forEach((client, id) => {
            if (client.username === data.recipient && client.ws.readyState === WebSocket.OPEN) {
              client.ws.send(JSON.stringify(data));
            }
          });
        } else if (data.type === 'read') {
          connections.forEach((client, id) => {
            if (client.username === data.recipient && client.ws.readyState === WebSocket.OPEN) {
              client.ws.send(JSON.stringify(data));
            }
          });
        } else if (data.type === 'profile') {
          await query('UPDATE users SET display_name = $1, status = $2 WHERE username = $3', [data.displayName, data.status, data.username]);
          broadcast(data);
        } else if (data.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong' }));
        }
      }
    } catch (err) {
      console.error('WebSocket message error:', err);
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
    }
  });

  ws.on('close', () => {
    const conn = connections.get(clientId);
    if (conn.username) {
      broadcast({ type: 'profile', username: conn.username, status: 'offline' });
    }
    connections.delete(clientId);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});