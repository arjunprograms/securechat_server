// Load environment variables
require('dotenv').config();

// Firebase setup with error handling
let admin, bucket;
try {
  admin = require('firebase-admin');
  let serviceAccount;
  
  // Try to get Firebase credentials from environment or file
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    // If provided as environment variable, parse the JSON
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    console.log('Firebase credentials loaded from environment variable');
  } else {
    // Otherwise load from local file
    serviceAccount = require('./firebase-service-account.json');
    console.log('Firebase credentials loaded from local file');
  }
  
  // Initialize Firebase with the correct method name
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || 'subedi-chat-files.appspot.com'
  });
  
  bucket = admin.storage().bucket();
  console.log('Firebase initialized successfully with bucket:', bucket.name);
} catch (err) {
  console.error('Firebase initialization error:', err);
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

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Express + HTTP server
const app = express();
const server = http.createServer(app);

// WebSocket server attached to HTTP server
const wss = new WebSocket.Server({ server });

// ----- Enhanced Security Middleware -----

// Apply Helmet for security headers
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

// Set up CSRF protection with random tokens
const csrfTokens = new Map();

// Generate CSRF token endpoint
app.get('/csrf-token', (req, res) => {
  const token = uuidv4();
  const clientIp = req.ip || req.connection.remoteAddress;
  
  // Store the token with expiration (15 minutes)
  csrfTokens.set(token, {
    ip: clientIp,
    expires: Date.now() + (15 * 60 * 1000)
  });
  
  // Clean expired tokens (run every 100 requests)
  if (Math.random() < 0.01) {
    cleanExpiredCsrfTokens();
  }
  
  res.json({ csrfToken: token });
});

// Clean expired CSRF tokens
function cleanExpiredCsrfTokens() {
  const now = Date.now();
  for (const [token, data] of csrfTokens.entries()) {
    if (data.expires < now) {
      csrfTokens.delete(token);
    }
  }
}

// CSRF verification middleware for sensitive routes
function verifyCsrfToken(req, res, next) {
  // Skip for GET requests and health check
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
  
  // Check if token is expired
  if (tokenData.expires < Date.now()) {
    csrfTokens.delete(token);
    return res.status(403).json({ error: 'CSRF token expired' });
  }
  
  // Token is valid
  next();
}

// Rate limiters

// General API limiter - 100 requests per 15 minutes
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: { error: 'Too many requests, please try again later.' },
  skip: (req) => {
    // Don't rate limit health checks and WebSocket connections
    return req.path === '/health' || req.path === '/ws';
  }
});

// More restrictive limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 requests per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts, please try again later.' }
});

// Speed limiter - slows down responses after too many requests
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 50, // allow 50 requests per 15 minutes, then...
  delayMs: (hits) => hits * 100, // add 100ms delay per hit
});

// Apply rate limiters
app.use(apiLimiter);
app.use(speedLimiter);

// Apply auth limiter to auth routes
app.use('/login', authLimiter);
app.use('/register', authLimiter);

// Input sanitization middleware
const sanitizeInput = (req, res, next) => {
  if (req.body) {
    // Simple XSS protection for string inputs
    for (const key in req.body) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = req.body[key]
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#x27;')
          .replace(/\//g, '&#x2F;');
      }
    }
  }
  next();
};

// Apply input sanitization
app.use(sanitizeInput);

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
  });
  next();
});

// Suspicious IP tracking
const suspiciousIPs = new Map();

// IP-based protection middleware
app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  
  // Check if this IP is suspicious
  const suspiciousData = suspiciousIPs.get(ip) || { count: 0, lastSeen: Date.now() };
  
  // Reset if it's been more than a day
  if (Date.now() - suspiciousData.lastSeen > 24 * 60 * 60 * 1000) {
    suspiciousData.count = 0;
  }
  
  // Update last seen
  suspiciousData.lastSeen = Date.now();
  
  // Check for suspicious patterns (hitting many endpoints rapidly)
  if (req.path !== '/health' && req.path !== '/') {
    suspiciousData.count++;
    
    // If too many requests in a short time
    if (suspiciousData.count > 100) {
      console.log(`Suspicious activity detected from IP: ${ip}`);
      
      // Slow them down dramatically
      setTimeout(() => {
        next();
      }, 5000); // 5 second delay
      
      return;
    }
  }
  
  // Store updated data
  suspiciousIPs.set(ip, suspiciousData);
  
  next();
});

// Standard CORS middleware
app.use(cors({
  origin: '*', // Allow all origins for development - restrict in production
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept', 'X-CSRF-Token']
}));

// Parse JSON bodies
app.use(express.json());

// Ensure directories exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);

// Serve uploaded files (fallback for local development)
app.use('/uploads', express.static(uploadDir));

// Track active connections and typing users
const connections = new Map();
const typingUsers = new Set();

// Throttle login
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

// Utility: create per-user logger
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

// Utility: generate unique ID
function generateUniqueId() {
  return `${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
}

// Broadcast to all clients (except optional exclude) for public messages
function broadcast(message, exclude = null) {
  if (message.recipient && message.recipient !== 'all') return;
  wss.clients.forEach(client => {
    if (client !== exclude && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

// Database helpers
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

// -------- HTTP Endpoints -------- //

// OPTIONS handler for CORS preflight
app.options('*', cors());

// File upload endpoint - Firebase Storage
app.post('/upload', verifyCsrfToken, (req, res) => {
  console.log('Upload request received');
  
  // DEBUG LOGGING
  console.log('Firebase bucket status:', !!bucket ? 'Available' : 'Not available');
  console.log('Bucket name');

  // Load environment variables
require('dotenv').config();

// Firebase setup with error handling
let admin, bucket;
try {
  admin = require('firebase-admin');
  let serviceAccount;
  
  // Try to get Firebase credentials from environment or file
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    // If provided as environment variable, parse the JSON
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    console.log('Firebase credentials loaded from environment variable');
  } else {
    // Otherwise load from local file
    serviceAccount = require('./firebase-service-account.json');
    console.log('Firebase credentials loaded from local file');
  }
  
  // Initialize Firebase with the correct method name
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || 'subedi-chat-files.appspot.com'
  });
  
  bucket = admin.storage().bucket();
  console.log('Firebase initialized successfully with bucket:', bucket.name);
} catch (err) {
  console.error('Firebase initialization error:', err);
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

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Express + HTTP server
const app = express();
const server = http.createServer(app);

// WebSocket server attached to HTTP server
const wss = new WebSocket.Server({ server });

// ----- Enhanced Security Middleware -----

// Apply Helmet for security headers
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

// Set up CSRF protection with random tokens
const csrfTokens = new Map();

// Generate CSRF token endpoint
app.get('/csrf-token', (req, res) => {
  const token = uuidv4();
  const clientIp = req.ip || req.connection.remoteAddress;
  
  // Store the token with expiration (15 minutes)
  csrfTokens.set(token, {
    ip: clientIp,
    expires: Date.now() + (15 * 60 * 1000)
  });
  
  // Clean expired tokens (run every 100 requests)
  if (Math.random() < 0.01) {
    cleanExpiredCsrfTokens();
  }
  
  res.json({ csrfToken: token });
});

// Clean expired CSRF tokens
function cleanExpiredCsrfTokens() {
  const now = Date.now();
  for (const [token, data] of csrfTokens.entries()) {
    if (data.expires < now) {
      csrfTokens.delete(token);
    }
  }
}

// CSRF verification middleware for sensitive routes
function verifyCsrfToken(req, res, next) {
  // Skip for GET requests and health check
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
  
  // Check if token is expired
  if (tokenData.expires < Date.now()) {
    csrfTokens.delete(token);
    return res.status(403).json({ error: 'CSRF token expired' });
  }
  
  // Token is valid
  next();
}

// Rate limiters

// General API limiter - 100 requests per 15 minutes
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: { error: 'Too many requests, please try again later.' },
  skip: (req) => {
    // Don't rate limit health checks and WebSocket connections
    return req.path === '/health' || req.path === '/ws';
  }
});

// More restrictive limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 requests per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts, please try again later.' }
});

// Speed limiter - slows down responses after too many requests
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 50, // allow 50 requests per 15 minutes, then...
  delayMs: (hits) => hits * 100, // add 100ms delay per hit
});

// Apply rate limiters
app.use(apiLimiter);
app.use(speedLimiter);

// Apply auth limiter to auth routes
app.use('/login', authLimiter);
app.use('/register', authLimiter);

// Input sanitization middleware
const sanitizeInput = (req, res, next) => {
  if (req.body) {
    // Simple XSS protection for string inputs
    for (const key in req.body) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = req.body[key]
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#x27;')
          .replace(/\//g, '&#x2F;');
      }
    }
  }
  next();
};

// Apply input sanitization
app.use(sanitizeInput);

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
  });
  next();
});

// Suspicious IP tracking
const suspiciousIPs = new Map();

// IP-based protection middleware
app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  
  // Check if this IP is suspicious
  const suspiciousData = suspiciousIPs.get(ip) || { count: 0, lastSeen: Date.now() };
  
  // Reset if it's been more than a day
  if (Date.now() - suspiciousData.lastSeen > 24 * 60 * 60 * 1000) {
    suspiciousData.count = 0;
  }
  
  // Update last seen
  suspiciousData.lastSeen = Date.now();
  
  // Check for suspicious patterns (hitting many endpoints rapidly)
  if (req.path !== '/health' && req.path !== '/') {
    suspiciousData.count++;
    
    // If too many requests in a short time
    if (suspiciousData.count > 100) {
      console.log(`Suspicious activity detected from IP: ${ip}`);
      
      // Slow them down dramatically
      setTimeout(() => {
        next();
      }, 5000); // 5 second delay
      
      return;
    }
  }
  
  // Store updated data
  suspiciousIPs.set(ip, suspiciousData);
  
  next();
});

// Standard CORS middleware
app.use(cors({
  origin: '*', // Allow all origins for development - restrict in production
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept', 'X-CSRF-Token']
}));

// Parse JSON bodies
app.use(express.json());

// Ensure directories exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);

// Serve uploaded files (fallback for local development)
app.use('/uploads', express.static(uploadDir));

// Track active connections and typing users
const connections = new Map();
const typingUsers = new Set();

// Throttle login
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

// Utility: create per-user logger
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

// Utility: generate unique ID
function generateUniqueId() {
  return `${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
}

// Broadcast to all clients (except optional exclude) for public messages
function broadcast(message, exclude = null) {
  if (message.recipient && message.recipient !== 'all') return;
  wss.clients.forEach(client => {
    if (client !== exclude && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

// Database helpers
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

// -------- HTTP Endpoints -------- //

// OPTIONS handler for CORS preflight
app.options('*', cors());

// File upload endpoint - Firebase Storage
app.post('/upload', verifyCsrfToken, (req, res) => {
  console.log('Upload request received');
  
  // DEBUG LOGGING
  console.log('Firebase bucket status:', !!bucket ? 'Available' : 'Not available');
  console.log('Bucket name:', bucket ? bucket.name : 'None');
  
  // ALWAYS SET CONTENT TYPE HEADER
  res.header('Content-Type', 'application/json');
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Accept, X-CSRF-Token');
  
  // Check if Firebase is properly initialized
  if (!bucket) {
    console.error('Firebase storage not initialized');
    return res.json({ error: 'File storage service is not available' });
  }
  
  // parse a single file upload
  const form = new formidable.IncomingForm({
    maxFileSize: 5 * 1024 * 1024, // 5MB limit
    keepExtensions: true,
    multiples: false,
    uploadDir: uploadDir // Set upload directory for potential fallback
  });

  form.parse(req, async (err, fields, files) => {
    if (err) {
      console.error('Form parsing error:', err);
      return res.json({ error: err.message });
    }

    // grab the one file that was uploaded
    const fileKey = Object.keys(files)[0];
    const file = files[fileKey];
    
    if (!file) {
      return res.json({ error: 'No file uploaded' });
    }

    try {
      // Check for encrypted file info
      const isEncrypted = fields.encrypted === 'true';
      const encryptedKey = fields.encryptedKey || null;
      const iv = fields.iv || null;
      
      // FIREBASE UPLOAD CODE
      // generate a unique filename and upload it to Firebase
      const originalFilename = file.originalFilename || path.basename(file.filepath);
      const safeFilename = originalFilename.replace(/[^a-zA-Z0-9.-]/g, '_'); // Sanitize filename
      const destFilename = `uploads/${Date.now()}_${safeFilename}`;
      
      try {
        const blob = bucket.file(destFilename);
        
        // Create a write stream with explicit configuration
        const blobStream = blob.createWriteStream({
          metadata: { 
            contentType: file.mimetype,
            metadata: {
              originalName: originalFilename,
              encrypted: isEncrypted ? 'true' : 'false',
              // Don't store these in cleartext in production!
              // This is just for demo purposes
              encryptedKey: encryptedKey,
              iv: iv
            }
          },
          resumable: false // Set to false for small files for faster uploads
        });

        // Handle errors in the upload stream with better logging
        blobStream.on('error', err => {
          console.error('Upload to Firebase failed:', err);
          console.error('Error details:', JSON.stringify(err, null, 2));
          return res.json({ error: 'Firebase upload failed: ' + err.message });
        });

        // When upload completes
        blobStream.on('finish', async () => {
          try {
            // make the file publicly readable
            await blob.makePublic();

            // construct the public URL
            const publicUrl = `https://storage.googleapis.com/${bucket.name}/${destFilename}`;
            console.log('File uploaded successfully to Firebase:', publicUrl);

            // Return JSON response with file info
            return res.json({
              url: publicUrl,
              filename: originalFilename,
              type: file.mimetype,
              encrypted: isEncrypted,
              encryptedKey: encryptedKey,
              iv: iv
            });
          } catch (err) {
            console.error('Error making blob public:', err);
            return res.json({ error: 'Failed to make file public: ' + err.message });
          }
        });

        // Create a read stream with explicit encoding and pipe it to the GCS upload stream
        fs.createReadStream(file.filepath).pipe(blobStream);
        
      } catch (firebaseErr) {
        console.error('Firebase operation error:', firebaseErr);
        
        // LOCAL FALLBACK - If Firebase fails, store locally
        const filename = path.basename(file.filepath);
        const destPath = path.join(uploadDir, filename);
        
        if (path.dirname(file.filepath) !== uploadDir) {
          fs.renameSync(file.filepath, destPath);
        }
        
        const fileUrl = `/uploads/${filename}`;
        console.log('Firebase failed, file saved locally instead:', fileUrl);
        
        return res.json({
          url: fileUrl,
          filename: file.originalFilename || filename,
          type: file.mimetype,
          encrypted: isEncrypted,
          encryptedKey: encryptedKey,
          iv: iv
        });
      }
      
    } catch (err) {
      console.error('Error in upload handler:', err);
      return res.json({ error: 'Upload processing failed: ' + err.message });
    }
  });
});})