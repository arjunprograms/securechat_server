// Load environment variables
require('dotenv').config();
const admin = require('firebase-admin');
const serviceAccount = require('./firebase-service-account.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  // replace with your bucket name from the Firebase console:
  storageBucket: 'subedi-chat-files.appspot.com'
});

const bucket = admin.storage().bucket();

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

// Middleware
app.use(cors({
  origin: '*', // Allow all origins for development
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept']
}));
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
    log: (msg) => fs.appendFileSync(filePath, `[${new Date().toISOString()}] ${msg}\n`)
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
      const destFilename = `${Date.now()}_${originalFilename}`;
      const blob = bucket.file(destFilename);
      const blobStream = blob.createWriteStream({
        metadata: { contentType: file.mimetype }
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
  const { username, password } = req.body;
  const attempts = loginAttempts.get(username) || { count: 0, last: 0 };

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
    loginAttempts.delete(username);
    await pool.query('UPDATE users SET status = $1 WHERE username = $2', ['online', username]);
    createLogger(username).log('User logged in');
    res.json({ message: 'Logged in', publicKey: user.public_key });
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
  try {
    const rows = await query(
      'SELECT id, sender as username, recipient, content, is_encrypted as encrypted, timestamp as time FROM messages ORDER BY timestamp',
      []
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// -------- WebSocket Handling -------- //

wss.on('connection', ws => {
  let currentUser = null;
  let logger = null;

  console.log('New WebSocket connection established');

  ws.on('message', async raw => {
    try {
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
            recipient: data.
            recipient || 'all',
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
      await pool.query('UPDATE users SET status = $1 WHERE username = $2', ['offline', currentUser]);
      logger.log('WebSocket disconnected');
      broadcast({ type: 'system', message: `${currentUser} left` });
      broadcast({ type: 'online_users', users: Array.from(connections.keys()) });
    } catch (err) {
      console.error('Error updating user status on disconnect:', err);
    }
  });
  
  // Send a ping every 30 seconds to keep the connection alive
  const pingInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'ping', time: Date.now() }));
    } else {
      clearInterval(pingInterval);
    }
  }, 30000);
  
  ws.on('close', () => {
    clearInterval(pingInterval);
  });
});

// Start server
const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));