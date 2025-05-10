// ============================================================================
// SECURE CHAT APPLICATION - CONSOLIDATED SERVER
// ============================================================================
// This is a fully consolidated version of the server that includes:
// 1. Security middleware & rate limiting
// 2. Uptime monitoring
// 3. WebSocket auto-reconnect handling
// 4. End-to-end encryption support
// 5. 24/7 uptime strategies
// ============================================================================

// Load environment variables
require('dotenv').config();
const admin = require('firebase-admin');
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
const { v4: uuidv4 } = require('uuid');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const os = require('os');
const https = require('https');

// ============================================================================
// FIREBASE INITIALIZATION
// ============================================================================

// Check for service account file
let serviceAccount;
try {
  serviceAccount = require('./firebase-service-account.json');
} catch (error) {
  console.error('Error loading Firebase service account:', error);
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      // Try using environment variable if file doesn't exist
      serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
      console.log('Using Firebase service account from environment variable');
    } catch (err) {
      console.error('Failed to parse Firebase service account from environment:', err);
      process.exit(1);
    }
  } else {
    console.error('No Firebase service account found in file or environment');
    process.exit(1);
  }
}

// Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET || 'subedi-chat-files.appspot.com'
});

const bucket = admin.storage().bucket();

// ============================================================================
// DATABASE CONNECTION
// ============================================================================

// PostgreSQL connection pool with connection retry
const createPool = () => {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 10, // Maximum number of clients in the pool
    idleTimeoutMillis: 30000, // How long a client is allowed to remain idle before being closed
    connectionTimeoutMillis: 5000, // How long to wait for a connection to become available
  });
  
  // Test the connection
  pool.query('SELECT NOW()', (err) => {
    if (err) {
      console.error('Error connecting to database:', err);
      console.log('Retrying in 5 seconds...');
      setTimeout(createPool, 5000);
    } else {
      console.log('Successfully connected to database');
    }
  });
  
  // Handle pool errors
  pool.on('error', (err) => {
    console.error('Unexpected error on idle client', err);
  });
  
  return pool;
};

const pool = createPool();

// ============================================================================
// SECURITY MIDDLEWARE
// ============================================================================

// Function to configure security middleware
function configureSecurityMiddleware(app) {
  // CORS configuration - more restrictive for production
  const corsOptions = {
    origin: process.env.NODE_ENV === 'production' 
      ? [
          process.env.FRONTEND_URL || 'https://your-frontend-domain.com', 
          'https://localhost:3000'
        ] 
      : '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Accept'],
    credentials: true,
    maxAge: 86400 // 24 hours
  };
  
  // Apply Helmet for security headers
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        connectSrc: ["'self'", 
          process.env.NODE_ENV === 'production' 
            ? process.env.FRONTEND_URL || 'https://your-frontend-domain.com' 
            : '*'
        ],
        imgSrc: ["'self'", 'data:', 'https://storage.googleapis.com'],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // Needed for some UI frameworks
        upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
      }
    },
    crossOriginEmbedderPolicy: false, // May need to disable for some integrations
  }));
  
  // Rate limiting configurations
  const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 300, // Limit each IP to 100 requests per windowMs
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    message: { error: 'Too many requests, please try again later' },
    skip: (req) => req.method === 'OPTIONS' // Skip OPTIONS requests (for CORS)
  });
  
  // More restrictive limit for auth endpoints
  const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 20, // Limit each IP to 20 login/register attempts per hour
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many authentication attempts, please try again later' }
  });

  // Speed limiter for brute force prevention
  const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 30, // Allow 30 requests per 15 minutes without delay
    delayMs: (hits) => hits * 100, // Add 100ms of delay per hit above threshold
    maxDelayMs: 10000 // Max delay of 10 seconds
  });

  // Apply rate limiting middleware to all requests
  app.use(apiLimiter);
  
  // Apply stricter limits to auth routes
  app.use(['/login', '/register', '/update-profile'], authLimiter);
  app.use(['/login', '/register', '/update-profile'], speedLimiter);
  
  // File upload size limiting middleware
  const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
  app.use('/upload', (req, res, next) => {
    const contentLength = parseInt(req.headers['content-length'], 10) || 0;
    if (contentLength > MAX_FILE_SIZE) {
      return res.status(413).json({ error: 'File too large. Maximum size is 5MB.' });
    }
    next();
  });

  // WebSocket rate limiting
  // This will need to be applied separately to WebSocket connections
  const wsConnections = new Map(); // IP -> {count, timestamp}
  const WS_MAX_CONNECTIONS_PER_IP = 5;
  const WS_WINDOW_MS = 60 * 1000; // 1 minute window
  
  return {
    corsOptions,
    wsRateLimiter: (ip) => {
      const now = Date.now();
      
      // Clean up old entries
      for (const [recordedIp, data] of wsConnections.entries()) {
        if (now - data.timestamp > WS_WINDOW_MS) {
          wsConnections.delete(recordedIp);
        }
      }
      
      // Check current IP
      const record = wsConnections.get(ip) || { count: 0, timestamp: now };
      
      // Update record
      if (now - record.timestamp > WS_WINDOW_MS) {
        record.count = 1;
        record.timestamp = now;
      } else {
        record.count += 1;
      }
      wsConnections.set(ip, record);
      
      // Return true if limit exceeded
      return record.count > WS_MAX_CONNECTIONS_PER_IP;
    }
  };
}

// ============================================================================
// UPTIME MONITORING
// ============================================================================

// Uptime Monitor class
class UptimeMonitor {
  constructor(app, options = {}) {
    this.app = app;
    this.options = {
      pingInterval: options.pingInterval || 5 * 60 * 1000, // 5 minutes
      pingEndpoint: options.pingEndpoint || '/health',
      verbose: options.verbose || false,
      alertThreshold: options.alertThreshold || 3, // Failed pings before alerting
      selfPing: options.selfPing !== undefined ? options.selfPing : true
    };
    
    this.serverUrl = options.serverUrl || null;
    this.lastPingTime = Date.now();
    this.failedPings = 0;
    this.isShuttingDown = false;
    this.metrics = {
      uptime: 0,
      requestCount: 0,
      errors: 0,
      memoryUsage: 0,
      lastResponseTime: 0
    };
    
    // Register restart handlers
    process.on('SIGTERM', () => this.handleShutdown('SIGTERM'));
    process.on('SIGINT', () => this.handleShutdown('SIGINT'));
    
    // Start tracking uptime
    this.startTime = Date.now();
    
    // Track memory usage
    this.memoryInterval = setInterval(() => {
      this.metrics.memoryUsage = process.memoryUsage().heapUsed;
    }, 60000); // Every minute
    
    this.setupHealthEndpoint();
    
    if (this.options.selfPing && this.serverUrl) {
      this.setupSelfPing();
    }
  }
  
  setupHealthEndpoint() {
    // Health check endpoint
    this.app.get(this.options.pingEndpoint, (req, res) => {
      this.metrics.requestCount++;
      
      // Calculate uptime in seconds
      this.metrics.uptime = Math.floor((Date.now() - this.startTime) / 1000);
      
      // Get system info
      const systemInfo = {
        platform: os.platform(),
        arch: os.arch(),
        cpus: os.cpus().length,
        loadAvg: os.loadavg(),
        freemem: os.freemem(),
        totalmem: os.totalmem(),
        node: process.version
      };
      
      // Send response
      res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: this.metrics.uptime,
        metrics: {
          requests: this.metrics.requestCount,
          errors: this.metrics.errors,
          memoryUsage: `${Math.round(this.metrics.memoryUsage / 1024 / 1024 * 100) / 100} MB`,
          lastResponseTime: `${this.metrics.lastResponseTime}ms`
        },
        system: systemInfo
      });
    });
    
    // Simple alive endpoint (minimal CPU usage, for frequent pings)
    this.app.get('/ping', (req, res) => {
      res.status(200).send('pong');
    });
  }
  
  setupSelfPing() {
    // Self-ping interval to prevent cold starts and keep the server alive
    this.pingInterval = setInterval(() => {
      const start = Date.now();
      const pingUrl = new URL(this.options.pingEndpoint, this.serverUrl);
      
      const httpModule = pingUrl.protocol === 'https:' ? https : http;
      
      const req = httpModule.get(pingUrl.toString(), (res) => {
        this.metrics.lastResponseTime = Date.now() - start;
        this.lastPingTime = Date.now();
        this.failedPings = 0;
        
        if (this.options.verbose) {
          console.log(`Self-ping successful: ${res.statusCode} - ${this.metrics.lastResponseTime}ms`);
        }
        
        // Consume the response
        res.resume();
      });
      
      req.on('error', (err) => {
        this.failedPings++;
        this.metrics.errors++;
        console.error(`Self-ping failed: ${err.message}`);
        
        if (this.failedPings >= this.options.alertThreshold) {
          this.handleFailedPings();
        }
      });
      
      req.on('timeout', () => {
        this.failedPings++;
        this.metrics.errors++;
        console.error('Self-ping timeout');
        req.abort();
        
        if (this.failedPings >= this.options.alertThreshold) {
          this.handleFailedPings();
        }
      });
      
      req.setTimeout(30000); // 30 second timeout
      
    }, this.options.pingInterval);
  }
  
  handleFailedPings() {
    console.error(`Alert: Server has failed ${this.failedPings} consecutive pings`);
    
    // Here you could add logic to:
    // 1. Send alerts (email, SMS, etc.)
    // 2. Log to monitoring service
    // 3. Attempt recovery actions
    
    // Example: You could integrate with a notification service
    this.sendNotification({
      level: 'critical',
      message: `Server has failed ${this.failedPings} consecutive pings`,
      timestamp: new Date().toISOString(),
      metrics: this.metrics
    });
  }
  
  sendNotification(data) {
    // This is a placeholder for your notification service
    // You could integrate with services like:
    // - SendGrid, Twilio for emails/SMS
    // - Slack, Discord for team notifications
    // - PagerDuty for on-call alerts
    
    console.error('ALERT NOTIFICATION:', data.message);
    
    // Example implementation for Slack webhook:
    const webhookUrl = process.env.SLACK_WEBHOOK_URL;
    
    if (!webhookUrl) return;
    
    const postData = JSON.stringify({
      text: `🚨 *ALERT*: ${data.message}`,
      attachments: [
        {
          color: data.level === 'critical' ? '#FF0000' : '#FFA500',
          fields: [
            { title: 'Timestamp', value: data.timestamp, short: true },
            { title: 'Uptime', value: `${Math.floor(data.metrics.uptime / 60)} minutes`, short: true },
            { title: 'Memory', value: `${Math.round(data.metrics.memoryUsage / 1024 / 1024 * 100) / 100} MB`, short: true },
            { title: 'Failed Pings', value: this.failedPings.toString(), short: true }
          ]
        }
      ]
    });
    
    try {
      const urlObj = new URL(webhookUrl);
      
      const options = {
        hostname: urlObj.hostname,
        path: urlObj.pathname + urlObj.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        }
      };
      
      const req = https.request(options, (res) => {
        res.on('data', () => {});
        res.on('end', () => {
          if (this.options.verbose) {
            console.log('Alert notification sent');
          }
        });
      });
      
      req.on('error', (error) => console.error('Error sending alert:', error));
      req.write(postData);
      req.end();
    } catch (err) {
      console.error('Failed to send notification:', err);
    }
  }
  
  handleShutdown(signal) {
    if (this.isShuttingDown) return;
    this.isShuttingDown = true;
    
    console.log(`Received ${signal}. Graceful shutdown initiated.`);
    
    // Clear intervals
    clearInterval(this.pingInterval);
    clearInterval(this.memoryInterval);
    
    // You might add additional cleanup here
    // For example, closing database connections
    
    // Exit with success code
    process.exit(0);
  }
  
  getMetrics() {
    return { ...this.metrics };
  }
}

// ============================================================================
// EXPRESS APP SETUP
// ============================================================================

// Express + HTTP server
const app = express();
const server = http.createServer(app);

// WebSocket server attached to HTTP server
const wss = new WebSocket.Server({ 
  server,
  // Add ping/pong for connection health checks
  pingInterval: 30000, // Send a ping every 30 seconds
  pingTimeout: 10000, // Wait 10 seconds for the pong response
});

// Apply security middleware
const { corsOptions, wsRateLimiter } = configureSecurityMiddleware(app);

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '1mb' })); // Limit JSON size

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

// Message queue for offline users
const messageQueues = new Map(); // username -> [{message, timestamp}]
const MAX_QUEUE_SIZE = 100; // Maximum messages to queue per user
const MAX_QUEUE_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// Utility: create per-user logger
function createLogger(username) {
  const timestamp = new Date().toISOString().replace(/:/g, '-');
  const filePath = path.join(logsDir, `${username}_${timestamp}.log`);
  return {
    log: (msg) => fs.appendFileSync(filePath, `[${new Date().toISOString()}] ${msg}\n`)
  };
}

// Utility: generate unique ID
function generateUniqueId() {
  return uuidv4();
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

// Queue a message for an offline user
function queueMessageForUser(username, message) {
  if (!messageQueues.has(username)) {
    messageQueues.set(username, []);
  }
  
  const queue = messageQueues.get(username);
  
  // Add timestamp for expiration
  message.queuedAt = Date.now();
  
  // Add to queue
  queue.push(message);
  
  // Trim queue if it gets too large (FIFO)
  if (queue.length > MAX_QUEUE_SIZE) {
    queue.shift(); // Remove oldest message
  }
  
  console.log(`Queued message for offline user ${username}, queue size: ${queue.length}`);
}

// Clean up expired messages in queues
function cleanupMessageQueues() {
  const now = Date.now();
  
  for (const [username, queue] of messageQueues.entries()) {
    const initialSize = queue.length;
    
    // Filter out expired messages
    const updatedQueue = queue.filter(msg => (now - msg.queuedAt) < MAX_QUEUE_AGE);
    
    // Update the queue
    if (updatedQueue.length < initialSize) {
      console.log(`Cleaned up ${initialSize - updatedQueue.length} expired messages for ${username}`);
      messageQueues.set(username, updatedQueue);
    }
  }
}

// Set up a periodic cleanup
setInterval(cleanupMessageQueues, 6 * 60 * 60 * 1000); // Every 6 hours

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

// Make sure the schema is set up
async function ensureSchema() {
  try {
    // Create users table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        username VARCHAR(50) PRIMARY KEY,
        password_hash TEXT NOT NULL,
        public_key TEXT,
        display_name VARCHAR(100),
        status VARCHAR(20) DEFAULT 'offline',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
      )
    `);
    
    // Create messages table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id VARCHAR(50) PRIMARY KEY,
        sender VARCHAR(50) NOT NULL REFERENCES users(username),
        recipient VARCHAR(50) NOT NULL,
        content TEXT,
        is_encrypted BOOLEAN DEFAULT false,
        read_status VARCHAR(20) DEFAULT 'sent',
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create files table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS files (
        id VARCHAR(50) PRIMARY KEY,
        sender VARCHAR(50) NOT NULL REFERENCES users(username),
        recipient VARCHAR(50) NOT NULL,
        filename VARCHAR(255),
        file_url TEXT,
        file_type VARCHAR(100),
        is_encrypted BOOLEAN DEFAULT false,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    console.log('Database schema initialized');
  } catch (err) {
    console.error('Error ensuring database schema:', err);
  }
}

// ============================================================================
// HTTP ENDPOINTS
// ============================================================================

// OPTIONS handler for CORS preflight
app.options('*', cors(corsOptions));

// Update public key endpoint
app.post('/update-key', async (req, res) => {
  const { username, publicKey } = req.body;
  
  if (!username || !publicKey) {
    return res.status(400).json({ error: 'Username and public key required' });
  }
  
  try {
    const user = await getUserByUsername(username);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    await pool.query('UPDATE users SET public_key = $1 WHERE username = $2', [publicKey, username]);
    
    // Broadcast to all connected clients that public key has been updated
    broadcast({
      type: 'public_key_updated',
      username,
      timestamp: new Date().toISOString()
    });
    
    res.json({ message: 'Public key updated successfully' });
  } catch (err) {
    console.error('Error updating public key:', err);
    res.status(500).json({ error: err.message });
  }
});

// Update user profile
app.post('/update-profile', async (req, res) => {
  const { username, profile } = req.body;
  try {
    await pool.query(
      'UPDATE users SET display_name = $1, status = $2 WHERE username = $3',
      [profile.displayName, profile.status, username]
    );
    broadcast({ type: 'profile_update', username, profile });
    createLogger(username).log('Profile updated');
    res.json({ message: 'Profile updated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Retrieve chat history
app.get('/message-history', async (req, res) => {
  const { username } = req.query;
  
  if (!username) {
    return res.status(400).json({ error: 'Username parameter is required' });
  }
  
  try {
    // Get messages where the user is either the sender or recipient
    const rows = await query(
      `SELECT id, sender as username, recipient, content, is_encrypted as encrypted, timestamp as time 
       FROM messages 
       WHERE sender = $1 OR recipient = $1 OR recipient = 'all'
       ORDER BY timestamp DESC LIMIT 200`,
      [username]
    );
    
    // Also get file messages
    const fileRows = await query(
      `SELECT id, sender as username, recipient, file_url as fileUrl, filename, file_type as fileType, 
              is_encrypted as encrypted, timestamp as time, 'file' as type
       FROM files
       WHERE sender = $1 OR recipient = $1 OR recipient = 'all'
       ORDER BY timestamp DESC LIMIT 50`,
      [username]
    );
    
    // Combine and sort
    const combined = [...rows, ...fileRows]
      .sort((a, b) => new Date(a.time) - new Date(b.time));
    
    res.json(combined);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Get pending messages for user
app.get('/pending-messages', async (req, res) => {
  const { username } = req.query;
  
  if (!username) {
    return res.status(400).json({ error: 'Username required' });
  }
  
  try {
    const user = await getUserByUsername(username);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const queue = messageQueues.get(username) || [];
    
    // Return the messages but don't clear them yet (they'll be cleared when acknowledged via WebSocket)
    res.json({
      count: queue.length,
      messages: queue
    });
  } catch (err) {
    console.error('Error retrieving pending messages:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// WEBSOCKET HANDLING
// ============================================================================

// Set up WebSocket heartbeats to detect dead connections
function heartbeat() {
  this.isAlive = true;
}

// Check client connections and terminate dead ones
const pingInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) {
      console.log('Terminating dead connection');
      return ws.terminate();
    }
    
    ws.isAlive = false;
    ws.ping();
  });
}, 30000); // Check every 30 seconds

wss.on('connection', (ws, req) => {
  let currentUser = null;
  let logger = null;
  
  // Get client IP for rate limiting
  const ip = req.headers['x-forwarded-for'] || 
             req.connection.remoteAddress || 
             req.socket.remoteAddress;
             
  // Check if this IP has too many connections
  if (wsRateLimiter(ip)) {
    console.warn(`Connection limit exceeded for IP: ${ip}`);
    ws.close(1008, 'Too many connections from this IP');
    return;
  }
  
  // Setup heartbeat
  ws.isAlive = true;
  ws.on('pong', heartbeat);
  
  console.log('New WebSocket connection established from', ip);

  ws.on('message', async raw => {
    try {
      // Add rate limiting for messages
      const MAX_MESSAGES_PER_MINUTE = 60;
      
      if (!ws.messageCount) {
        ws.messageCount = 0;
        ws.messageReset = Date.now() + 60000; // Reset after 1 minute
      }
      
      // Check if we should reset the counter
      if (Date.now() > ws.messageReset) {
        ws.messageCount = 0;
        ws.messageReset = Date.now() + 60000;
      }
      
      // Increment message count
      ws.messageCount++;
      
      // Check if limit exceeded
      if (ws.messageCount > MAX_MESSAGES_PER_MINUTE) {
        ws.send(JSON.stringify({
          type: 'system',
          message: 'Message rate limit exceeded. Please slow down.'
        }));
        return;
      }
      
      const data = JSON.parse(raw);

      if (data.type === 'auth') {
        const user = await getUserByUsername(data.username);
        if (user && await bcrypt.compare(data.password, user.password_hash)) {
          currentUser = data.username;
          logger = createLogger(currentUser);
          
          // Close any existing connection for this user
          const existingConnection = connections.get(currentUser);
          if (existingConnection && existingConnection !== ws) {
            console.log(`Closing existing connection for ${currentUser}`);
            existingConnection.close();
          }
          
          connections.set(currentUser, ws);
          if (data.publicKey) await pool.query('UPDATE users SET public_key = $1 WHERE username = $2', [data.publicKey, currentUser]);
          await pool.query('UPDATE users SET status = $1 WHERE username = $2', ['online', currentUser]);

          ws.send(JSON.stringify({ type: 'system', message: `Welcome ${currentUser}!` }));
          const online = Array.from(connections.keys());
          ws.send(JSON.stringify({ type: 'online_users', users: online }));
          broadcast({ type: 'system', message: `${currentUser} joined` }, ws);
          broadcast({ type: 'online_users', users: online });
          
          // Check for queued messages
          const pendingMessages = messageQueues.get(currentUser) || [];
          if (pendingMessages.length > 0) {
            ws.send(JSON.stringify({ 
              type: 'system', 
              message: `You have ${pendingMessages.length} message(s) that arrived while you were offline.` 
            }));
            
            // Send queued messages
            pendingMessages.forEach(msg => {
              ws.send(JSON.stringify(msg));
            });
            
            // Clear the queue
            messageQueues.delete(currentUser);
            console.log(`Delivered ${pendingMessages.length} queued messages to ${currentUser}`);
          }
          
          logger.log('WebSocket authenticated');
        } else {
          ws.send(JSON.stringify({ type: 'system', message: 'Authentication failed' }));
        }
        return;
      }

      if (!currentUser) {
        ws.send(JSON.stringify({ type: 'system', message: 'Not authenticated' }));
        return;
      }

      switch (data.type) {
        case 'message': {
          const msg = {
            type: 'message',
            id: data.messageId || generateUniqueId(),
            username: currentUser,
            content: data.content,
            encrypted: !!data.encrypted,
            formatted: !!data.formatted,
            recipient: data.recipient || 'all',
            time: new Date().toISOString()
          };
          await pool.query(
            'INSERT INTO messages(id,sender,recipient,content,is_encrypted,timestamp) VALUES($1,$2,$3,$4,$5,$6)',
            [msg.id, msg.username, msg.recipient, msg.content, msg.encrypted, msg.time]
          );
          logger.log(`Message to ${msg.recipient}: ${msg.encrypted ? '[ENCRYPTED]' : msg.content}`);

          if (msg.recipient !== 'all') {
            const dest = connections.get(msg.recipient);
            if (dest && dest.readyState === WebSocket.OPEN) {
              dest.send(JSON.stringify(msg));
            } else {
              // Recipient is offline, queue the message
              queueMessageForUser(msg.recipient, msg);
              logger.log(`Message queued for offline user ${msg.recipient}`);
            }
            ws.send(JSON.stringify(msg));
          } else {
            broadcast(msg);
          }

          ws.send(JSON.stringify({ type: 'read_receipt', messageId: msg.id, status: 'delivered' }));
          break;
        }

        case 'typing':
          if (data.recipient === 'all') {
            broadcast({ type: 'typing_indicator', username: currentUser, isTyping: data.isTyping }, ws);
          } else {
            const dest = connections.get(data.recipient);
            if (dest && dest.readyState === WebSocket.OPEN) {
              dest.send(JSON.stringify({
                type: 'typing_indicator',
                username: currentUser,
                isTyping: data.isTyping
              }));
            }
          }
          break;

        case 'ping':
          ws.send(JSON.stringify({ type: 'pong', time: new Date().toISOString() }));
          break;

        case 'file': {
          const f = {
            type: 'file',
            id: data.messageId || generateUniqueId(),
            username: currentUser,
            fileUrl: data.fileUrl,
            filename: data.filename,
            fileType: data.fileType,
            encrypted: !!data.encrypted,
            recipient: data.recipient || 'all',
            time: new Date().toISOString()
          };
          
          try {
            await pool.query(
              'INSERT INTO files(id,sender,recipient,filename,file_url,file_type,is_encrypted,timestamp) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
              [f.id, f.username, f.recipient, f.filename, f.fileUrl, f.fileType, f.encrypted, f.time]
            );
            
            logger.log(`File to ${f.recipient}: ${f.filename} (${f.fileUrl})`);
  
            if (f.recipient !== 'all') {
              const destWs = connections.get(f.recipient);
              if (destWs && destWs.readyState === WebSocket.OPEN) {
                destWs.send(JSON.stringify(f));
              } else {
                // Queue file notification for offline user
                queueMessageForUser(f.recipient, f);
                logger.log(`File notification queued for offline user ${f.recipient}`);
              }
              ws.send(JSON.stringify(f)); // Send back to sender
            } else {
              broadcast(f);
            }
            
            // Send delivery receipt
            ws.send(JSON.stringify({ 
              type: 'read_receipt', 
              messageId: f.id, 
              status: 'delivered',
              time: new Date().toISOString()
            }));
            
          } catch (err) {
            console.error('Error saving file message:', err);
            ws.send(JSON.stringify({ 
              type: 'system', 
              message: `Error saving file: ${err.message}`
            }));
          }
          break;
        }

        case 'read_receipt': {
          const dest = connections.get(data.sender);
          if (dest && dest.readyState === WebSocket.OPEN) {
            dest.send(JSON.stringify({ 
              type: 'read_receipt', 
              messageId: data.messageId, 
              reader: currentUser, 
              status: 'read', 
              time: new Date().toISOString() 
            }));
          }
          break;
        }
        
        case 'acknowledge_messages': {
          // Client acknowledges receipt of queued messages, so we can clear them
          if (data.clear && messageQueues.has(currentUser)) {
            messageQueues.delete(currentUser);
            ws.send(JSON.stringify({ 
              type: 'system', 
              message: 'Message queue cleared' 
            }));
            logger.log('Message queue cleared by client acknowledgment');
          }
          break;
        }
      }
    } catch (err) {
      console.error('WS message error:', err);
      if (logger) {
        logger.log(`WebSocket error: ${err.message}`);
      }
      
      // Try to inform the client about the error
      try {
        ws.send(JSON.stringify({ 
          type: 'system', 
          message: 'An error occurred processing your request' 
        }));
      } catch (sendErr) {
        console.error('Error sending error message to client:', sendErr);
      }
    }
  });

  ws.on('close', async () => {
    if (!currentUser) return;
    
    console.log(`WebSocket disconnected for user: ${currentUser}`);
    connections.delete(currentUser);
    
    try {
      // Only update to offline if the user doesn't have another active connection
      if (!connections.has(currentUser)) {
        await pool.query('UPDATE users SET status = $1 WHERE username = $2', ['offline', currentUser]);
        logger.log('WebSocket disconnected, user status set to offline');
        broadcast({ type: 'system', message: `${currentUser} left` });
        broadcast({ type: 'online_users', users: Array.from(connections.keys()) });
      } else {
        logger.log('WebSocket disconnected, but user has another active connection');
      }
    } catch (err) {
      console.error('Error updating user status on disconnect:', err);
    }
  });

  // Keep track of client activity
  ws.lastActivity = Date.now();
  
  // Send a ping every 30 seconds to keep the connection alive
  const clientPingInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      // Only send ping if there's been no activity for a while
      if (Date.now() - ws.lastActivity > 25000) { // 25 seconds
        ws.send(JSON.stringify({ type: 'ping', time: Date.now() }));
      }
    } else {
      clearInterval(clientPingInterval);
    }
  }, 30000);
  
  ws.on('close', () => {
    clearInterval(clientPingInterval);
  });
});

// Clean up interval when server is shutting down
wss.on('close', () => {
  clearInterval(pingInterval);
});

// ============================================================================
// SERVER STARTUP
// ============================================================================

// Initialize the database schema
ensureSchema().catch(err => {
  console.error('Failed to initialize database schema:', err);
  process.exit(1);
});

// Start server
const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  
  // Set up the uptime monitor
  const monitor = new UptimeMonitor(app, {
    serverUrl: process.env.SERVER_URL || `http://localhost:${PORT}`,
    pingInterval: process.env.PING_INTERVAL ? parseInt(process.env.PING_INTERVAL) : 5 * 60 * 1000,
    verbose: process.env.NODE_ENV !== 'production'
  });
});

// Handle graceful shutdown
process.on('SIGTERM', shutDown);
process.on('SIGINT', shutDown);

function shutDown() {
  console.log('Received shutdown signal');
  
  // Close the WebSocket server
  wss.close(() => {
    console.log('WebSocket server closed');
  });
  
  // Close the HTTP server
  server.close(() => {
    console.log('HTTP server closed');
    
    // Close the database pool
    pool.end().then(() => {
      console.log('Database connections closed');
      process.exit(0);
    }).catch(err => {
      console.error('Error closing database connections:', err);
      process.exit(1);
    });
  });
  
  // Force exit after 10 seconds if graceful shutdown fails
  setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
}

// File upload endpoint - Firebase Storage
app.post('/upload', (req, res) => {
  console.log('Upload request received');
  
  // Set appropriate headers for CORS
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Accept');
  
  // parse a single file upload
  const form = new formidable.IncomingForm({
    maxFileSize: 5 * 1024 * 1024, // 5MB limit
    keepExtensions: true,
    multiples: false
  });

  form.parse(req, async (err, fields, files) => {
    if (err) {
      console.error('Form parsing error:', err);
      return res.status(500).json({ error: err.message });
    }

    // grab the one file that was uploaded
    const fileKey = Object.keys(files)[0];
    const file = files[fileKey];
    
    if (!file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    try {
      // generate a unique filename and upload it into your GCS bucket
      const originalFilename = file.originalFilename || path.basename(file.filepath);
      const fileExt = path.extname(originalFilename);
      const basename = path.basename(originalFilename, fileExt);
      const destFilename = `${basename}_${generateUniqueId()}${fileExt}`;
      
      const blob = bucket.file(destFilename);
      const blobStream = blob.createWriteStream({
        metadata: { 
          contentType: file.mimetype,
          metadata: {
            // Add custom metadata for security
            uploadTime: new Date().toISOString(),
            originalFilename: originalFilename
          }
        },
        resumable: false // For smaller files, disable resumable uploads for speed
      });

      // Handle errors in the upload stream
      blobStream.on('error', err => {
        console.error('Upload to Firebase failed:', err);
        return res.status(500).json({ error: 'Firebase upload failed: ' + err.message });
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
          res.json({
            url: publicUrl,
            filename: originalFilename,
            type: file.mimetype
          });
        } catch (err) {
          console.error('Error making blob public:', err);
          res.status(500).json({ error: 'Failed to make file public: ' + err.message });
        }
      });

      // Create a read stream from the temp file and pipe it to the GCS upload stream
      fs.createReadStream(file.filepath).pipe(blobStream);
      
    } catch (err) {
      console.error('Error in upload handler:', err);
      res.status(500).json({ error: 'Upload processing failed: ' + err.message });
    }
  });
});

// User registration
app.post('/register', async (req, res) => {
  const { username, password, publicKey, profile } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  try {
    if (await getUserByUsername(username)) {
      return res.status(400).json({ error: 'Username already taken' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users(username, password_hash, public_key, display_name, status) VALUES ($1,$2,$3,$4,$5)',
      [username, passwordHash, publicKey, profile?.displayName || username, 'offline']
    );
    createLogger('system').log(`User registered: ${username}`);
    res.json({ message: 'Registered successfully' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: err.message });
  }
});

// User login
app.post('/login', async (req, res) => {
  const { username, password, publicKey } = req.body;
  const attempts = loginAttempts.get(username) || { count: 0, last: 0 };

  // IP-based rate limiting is handled by middleware, but we also want username-specific limiting
  if (attempts.count >= MAX_LOGIN_ATTEMPTS && Date.now() - attempts.last < LOCKOUT_TIME) {
    const wait = Math.ceil((LOCKOUT_TIME - (Date.now() - attempts.last)) / 60000);
    return res.status(429).json({ error: `Account locked. Try again in ${wait} minutes.` });
  }

  try {
    const user = await getUserByUsername(username);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      loginAttempts.set(username, { count: attempts.count + 1, last: Date.now() });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Reset login attempts on successful login
    loginAttempts.delete(username);
    
    // Update public key if provided
    if (publicKey) {
      await pool.query('UPDATE users SET public_key = $1 WHERE username = $2', [publicKey, username]);
    }
    
    // Update user status and last login time
    await pool.query(
      'UPDATE users SET status = $1, last_login = NOW() WHERE username = $2', 
      ['online', username]
    );
    
    createLogger(username).log('User logged in');
    
    // Get current public key
    const currentKey = publicKey || user.public_key;
    
    res.json({ 
      message: 'Logged in', 
      publicKey: currentKey,
      user: {
        username: user.username,
        displayName: user.display_name,
        status: 'online'
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Fetch public keys
app.get('/public-keys', async (req, res) => {
  try {
    const rows = await query('SELECT username, public_key FROM users', []);
    const keys = {};
    rows.forEach(r => { if (r.public_key) keys[r.username] = r.public_key; });
    res.json(keys);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Fetch user profiles
app.get('/user-profiles', async (req, res) => {
  try {
    const rows = await query('SELECT username, display_name, status FROM users', []);
    const profiles = {};
    rows.forEach(r => profiles[r.username] = { displayName: r.display_name, status: r.status });
    res.json(profiles);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });