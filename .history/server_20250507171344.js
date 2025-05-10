// Load environment variables from .env (if present)
require('dotenv').config();

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const formidable = require('formidable');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');

// MySQL connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'sql102.infinityfree.com',
  user: process.env.DB_USER || 'if0_38921113',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'if0_38921113_securechat_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Express + HTTP server
const app = express();
const server = http.createServer(app);

// WebSocket server attached to HTTP server
const wss = new WebSocket.Server({ server });

// Middleware
app.use(cors());
app.use(express.json());

// Ensure directories exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);

// Serve uploaded files
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
async function getUserByUsername(username) {
  const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
  return rows[0] || null;
}

// -------- HTTP Endpoints -------- //

// File upload endpoint
app.post('/upload', (req, res) => {
  const form = formidable({ uploadDir, keepExtensions: true, maxFileSize: 10 * 1024 * 1024 });
  form.parse(req, (err, fields, files) => {
    if (err) return res.status(500).json({ error: err.message });
    const fileKey = Object.keys(files)[0];
    const file = files[fileKey];
    if (!file) return res.status(400).json({ error: 'No file uploaded' });

    const filename = file.originalFilename || path.basename(file.filepath);
    const destPath = path.join(uploadDir, filename);
    fs.renameSync(file.filepath, destPath);
    res.json({ url: `/uploads/${filename}`, filename, type: file.mimetype });
  });
});

// User registration
app.post('/register', async (req, res) => {
  const { username, password, publicKey, profile } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  try {
    if (await getUserByUsername(username)) {
      return res.status(400).json({ error: 'Username already taken' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users(username, password_hash, public_key, display_name, status) VALUES (?,?,?,?,?)',
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
    await pool.query('UPDATE users SET status = ? WHERE username = ?', ['online', username]);
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
    const [rows] = await pool.query('SELECT username, public_key FROM users');
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
    const [rows] = await pool.query('SELECT username, display_name, status FROM users');
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
      'UPDATE users SET display_name = ?, status = ? WHERE username = ?',
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
    const [rows] = await pool.query(
      'SELECT id, sender as username, recipient, content, is_encrypted as encrypted, timestamp as time FROM messages ORDER BY timestamp'
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// -------- WebSocket Handling -------- //

wss.on('connection', ws => {
  let currentUser = null;
  let logger = null;

  ws.on('message', async raw => {
    try {
      const data = JSON.parse(raw);

      if (data.type === 'auth') {
        const user = await getUserByUsername(data.username);
        if (user && await bcrypt.compare(data.password, user.password_hash)) {
          currentUser = data.username;
          logger = createLogger(currentUser);
          connections.set(currentUser, ws);
          if (data.publicKey) await pool.query('UPDATE users SET public_key = ? WHERE username = ?', [data.publicKey, currentUser]);
          await pool.query('UPDATE users SET status = ? WHERE username = ?', ['online', currentUser]);

          ws.send(JSON.stringify({ type: 'system', message: `Welcome ${currentUser}!` }));
          const online = Array.from(connections.keys());
          ws.send(JSON.stringify({ type: 'online_users', users: online }));
          broadcast({ type: 'system', message: `${currentUser} joined` }, ws);
          broadcast({ type: 'online_users', users: online });
          logger.log('WebSocket authenticated');
        }
        return;
      }

      if (!currentUser) return;

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
            'INSERT INTO messages(id,sender,recipient,content,is_encrypted,timestamp) VALUES(?,?,?,?,?,?)',
            [msg.id, msg.username, msg.recipient, msg.content, msg.encrypted ? 1 : 0, msg.time]
          );
          logger.log(`Message to ${msg.recipient}: ${msg.encrypted ? '[ENCRYPTED]' : msg.content}`);

          if (msg.recipient !== 'all') {
            const dest = connections.get(msg.recipient);
            if (dest && dest.readyState === WebSocket.OPEN) dest.send(JSON.stringify(msg));
            ws.send(JSON.stringify(msg));
          } else broadcast(msg);

          ws.send(JSON.stringify({ type: 'read_receipt', messageId: msg.id, status: 'delivered' }));
          break;
        }

        case 'typing':
          broadcast({ type: 'typing_indicator', username: currentUser, isTyping: data.isTyping, recipient: data.recipient || 'all' }, ws);
          break;

        case 'ping':
          ws.send(JSON.stringify({ type: 'pong', time: new Date().toISOString() }));
          break;

        case 'file': {
          const f = {
            type: 'file',
            id: generateUniqueId(),
            username: currentUser,
            fileUrl: data.fileUrl,
            filename: data.filename,
            fileType: data.fileType,
            encrypted: !!data.encrypted,
            recipient: data.recipient || 'all',
            time: new Date().toISOString()
          };
          await pool.query(
            'INSERT INTO files(id,sender,recipient,filename,file_url,file_type,is_encrypted,timestamp) VALUES(?,?,?,?,?,?,?,?)',
            [f.id, f.username, f.recipient, f.filename, f.fileUrl, f.fileType, f.encrypted ? 1 : 0, f.time]
          );
          logger.log(`File to ${f.recipient}: ${f.filename}`);

          if (f.recipient !== 'all') {
            const destWs = connections.get(f.recipient);
            if (destWs && destWs.readyState === WebSocket.OPEN) destWs.send(JSON.stringify(f));
            ws.send(JSON.stringify(f));
          } else broadcast(f);
          break;
        }

        case 'read_receipt_ack': {
          const dest = connections.get(data.sender);
          if (dest && dest.readyState === WebSocket.OPEN) {
            dest.send(JSON.stringify({ type: 'read_receipt', messageId: data.messageId, reader: currentUser, status: 'read', time: new Date().toISOString() }));
          }
          break;
        }
      }
    } catch (err) {
      console.error('WS message error:', err);
    }
  });

  ws.on('close', async () => {
    if (!currentUser) return;
    connections.delete(currentUser);
    await pool.query('UPDATE users SET status = ? WHERE username = ?', ['offline', currentUser]);
    logger.log('WebSocket disconnected');
    broadcast({ type: 'system', message: `${currentUser} left` });
    broadcast({ type: 'online_users', users: Array.from(connections.keys()) });
  });
});

// Start server
const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
