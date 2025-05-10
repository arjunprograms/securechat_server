// Load environment variables
require('dotenv').config();
const admin = require('firebase-admin');

// --- Firebase Admin SDK Initialization ---
let serviceAccount;
try {
    // In production (like Render), use environment variables for service account JSON
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
        serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
    } else {
        // Fallback for local development (ensure firebase-service-account.json is gitignored)
        serviceAccount = require('./firebase-service-account.json');
    }
} catch (error) {
    console.error("CRITICAL ERROR: Firebase service account JSON not found, invalid, or inaccessible.", error);
    console.error("For local dev, ensure 'firebase-service-account.json' is in the root.");
    console.error("For production, ensure FIREBASE_SERVICE_ACCOUNT_JSON environment variable is set correctly.");
    process.exit(1);
}

try {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      storageBucket: process.env.FIREBASE_STORAGE_BUCKET // e.g., 'your-project-id.appspot.com'
    });
} catch(initError) {
    console.error("CRITICAL ERROR: Firebase Admin SDK initialization failed.", initError);
    console.error("Verify your service account credentials and storage bucket name.");
    process.exit(1);
}
const bucket = admin.storage().bucket();
console.log(`Firebase Admin SDK initialized. Storage bucket: ${bucket.name}`);


// --- Module Imports ---
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
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

// --- PostgreSQL Connection Pool ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});
pool.on('connect', () => console.log('PostgreSQL connected'));
pool.on('error', (err) => console.error('PostgreSQL pool error:', err));


// --- Express App Setup ---
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// --- Middleware ---
app.use(helmet()); // Basic security headers
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*', // Be specific in production
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept', 'Authorization']
}));
app.use(express.json({ limit: '5mb' })); // Limit JSON payload, adjust if needed for other things than chat

// --- Rate Limiting ---
const generalApiLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: process.env.NODE_ENV === 'production' ? 100 : 500, // Requests per IP
	standardHeaders: true, legacyHeaders: false, 
    message: { error: 'Too many API requests, please try again after 15 minutes.'}
});
const authLimiter = rateLimit({ 
	windowMs: 15 * 60 * 1000, max: process.env.NODE_ENV === 'production' ? 10 : 50, 
	standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many authentication attempts, please try again after 15 minutes.'}
});
const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: process.env.NODE_ENV === 'production' ? 30 : 100, // uploads per IP per hour
    standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many upload attempts, please try again later.'}
});

// Apply limiters (consider prefixing API routes e.g. /api/v1/)
app.use(['/public-keys', '/user-profiles', '/message-history', '/update-key', '/update-profile'], generalApiLimiter);
app.use(['/register', '/login'], authLimiter);
app.use('/upload', uploadLimiter);


// --- Globals & Utilities ---
const connections = new Map(); // username -> WebSocket instance
const loginAttempts = new Map(); // ip -> { count, lastAttemptTime }
const MAX_LOGIN_ATTEMPTS_PER_IP = 10; // More forgiving than per username for general IP blocking
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; 

function getLogger(context = 'system') {
    return {
        log: (message) => console.log(`[${new Date().toISOString()}] [${context}] INFO: ${message}`),
        warn: (message) => console.warn(`[${new Date().toISOString()}] [${context}] WARN: ${message}`),
        error: (message, errorObj) => console.error(`[${new Date().toISOString()}] [${context}] ERROR: ${message}`, errorObj || '')
    };
}
const systemLogger = getLogger();

function generateUniqueId() {
  return `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
}

async function dbQuery(text, params) {
  const client = await pool.connect();
  try {
    const res = await client.query(text, params);
    return res; // Return full result (rows, rowCount etc)
  } catch (err) {
    systemLogger.error(`Database query failed: ${text.substring(0,100)}`, err);
    throw err; 
  } finally {
    client.release();
  }
}

async function getUserByUsername(username) {
  const result = await dbQuery('SELECT id, username, password_hash, public_key, display_name, status FROM users WHERE username = $1', [username]);
  return result.rows[0] || null;
}

// --- HTTP Endpoints ---
app.options('*', cors()); // Handle preflight requests for all routes

app.post('/upload', (req, res) => {
  const remoteIp = req.ip;
  const uploaderLogger = getLogger(`upload-${remoteIp}`);
  uploaderLogger.log('Upload request initiated.');
  
  const form = new formidable.IncomingForm({
    maxFileSize: 15 * 1024 * 1024, 
    keepExtensions: true,
    multiples: false,
    // formidable creates temp files by default, which will be cleaned up.
  });

  form.parse(req, async (err, fields, files) => {
    if (err) {
      uploaderLogger.error('Formidable parsing error:', err);
      return res.status(400).json({ error: `File parsing error: ${err.message || 'Unknown error'}` });
    }

    const fileArray = files.file; 
    const uploadedFile = fileArray && fileArray.length > 0 ? fileArray[0] : null;
    
    if (!uploadedFile) {
      uploaderLogger.warn('No file found in `files.file` array.');
      return res.status(400).json({ error: 'No file was uploaded or file field name is incorrect.' });
    }

    try {
      // Use original filename from client, sanitize it for storage path
      const clientOriginalFilename = uploadedFile.originalFilename || `file-${Date.now()}`;
      const sanitizedOriginalName = clientOriginalFilename.replace(/[^a-zA-Z0-9._-]/g, '_');
      const storageFilename = `${Date.now()}_${crypto.randomBytes(4).toString('hex')}_${sanitizedOriginalName}`;
      
      const blob = bucket.file(storageFilename);
      const blobStream = blob.createWriteStream({
        metadata: { contentType: uploadedFile.mimetype || 'application/octet-stream' },
        public: true, // Make uploaded files public by default
        resumable: false 
      });

      blobStream.on('error', uploadErr => {
        uploaderLogger.error('Firebase Storage stream error:', uploadErr);
        return res.status(500).json({ error: 'File storage failed. Please try again.' });
      });

      blobStream.on('finish', async () => {
        try {
          // Public URL (ensure bucket/file permissions allow public reads)
          const publicUrl = `https://storage.googleapis.com/${bucket.name}/${blob.name}`;
          uploaderLogger.log(`File uploaded: ${publicUrl} (Original: ${clientOriginalFilename})`);
          res.status(200).json({
            url: publicUrl,
            filename: clientOriginalFilename, 
            type: uploadedFile.mimetype 
          });
        } catch (finishErr) {
          uploaderLogger.error('Error constructing public URL or post-upload:', finishErr);
          res.status(500).json({ error: 'Failed to finalize file upload details.' });
        }
      });

      fs.createReadStream(uploadedFile.filepath).pipe(blobStream);
      
    } catch (handlerLogicErr) {
      uploaderLogger.error('Server-side /upload handler logic error:', handlerLogicErr);
      res.status(500).json({ error: 'Internal server error during file upload.' });
    } finally {
        // Clean up the temporary file formidable created
        if (uploadedFile && uploadedFile.filepath && fs.existsSync(uploadedFile.filepath)) {
            fs.unlink(uploadedFile.filepath, unlinkErr => {
                if (unlinkErr) uploaderLogger.warn('Error deleting temp uploaded file:', unlinkErr);
            });
        }
    }
  });
});

app.post('/register', async (req, res) => {
  const { username, password, publicKey, profile } = req.body;
  const reqLogger = getLogger(`register-${req.ip}`);

  if (!username || !password) {
    reqLogger.warn('Attempt with missing username/password.');
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  if (password.length < 8) {
    reqLogger.warn(`Attempt with short password by user ${username}.`);
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  try {
    const existingUser = await getUserByUsername(username);
    if (existingUser) {
      reqLogger.warn(`Attempt to register existing username: ${username}.`);
      return res.status(409).json({ error: 'Username already taken.' }); // 409 Conflict
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const displayName = profile?.displayName?.trim() || username;
    const userStatus = profile?.status || 'offline';

    await dbQuery(
      'INSERT INTO users(username, password_hash, public_key, display_name, status) VALUES ($1, $2, $3, $4, $5)',
      [username, passwordHash, publicKey, displayName, userStatus]
    );
    systemLogger.log(`User registered: ${username}`);
    res.status(201).json({ message: 'User registered successfully.' });
  } catch (err) {
    reqLogger.error('Registration processing failed.', err);
    res.status(500).json({ error: 'Server error during registration. Please try again later.' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password, publicKey: clientPublicKey } = req.body;
  const remoteIp = req.ip;
  const reqLogger = getLogger(`login-${username || remoteIp}`);

  const attemptsInfo = loginAttempts.get(remoteIp) || { count: 0, lastAttemptTime: 0 };
  if (attemptsInfo.count >= MAX_LOGIN_ATTEMPTS_PER_IP && (Date.now() - attemptsInfo.lastAttemptTime) < LOCKOUT_DURATION_MS) {
    const timeLeft = Math.ceil((LOCKOUT_DURATION_MS - (Date.now() - attemptsInfo.lastAttemptTime)) / 60000);
    reqLogger.warn(`Locked out IP ${remoteIp} tried to log in as ${username}.`);
    return res.status(429).json({ error: `Too many failed login attempts from this IP. Please try again in ${timeLeft} minutes.` });
  }

  try {
    const user = await getUserByUsername(username);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      attemptsInfo.count++;
      attemptsInfo.lastAttemptTime = Date.now();
      loginAttempts.set(remoteIp, attemptsInfo);
      reqLogger.warn(`Invalid login attempt for ${username}. IP Attempt: ${attemptsInfo.count}`);
      return res.status(401).json({ error: 'Invalid username or password.' });
    }
    
    loginAttempts.delete(remoteIp); // Clear attempts for this IP on successful login

    let keyToUpdate = user.public_key;
    if (clientPublicKey && clientPublicKey !== "dummy-public-key-for-testing" && user.public_key !== clientPublicKey) {
        await dbQuery('UPDATE users SET public_key = $1 WHERE username = $2', [clientPublicKey, username]);
        reqLogger.log(`Public key updated for ${username} during login.`);
        keyToUpdate = clientPublicKey;
    }
    
    await dbQuery('UPDATE users SET status = $1 WHERE username = $2', ['online', username]);
    reqLogger.log(`User ${username} logged in successfully.`);
    res.json({ message: 'Login successful.', username: user.username, displayName: user.display_name, publicKey: keyToUpdate });
  } catch (err) {
    reqLogger.error('Login processing error.', err);
    res.status(500).json({ error: 'Server error during login. Please try again later.' });
  }
});

app.post('/update-key', async (req, res) => {
    // This endpoint should be authenticated to ensure only the correct user updates their key.
    // For simplicity, we'll assume an auth middleware would populate req.user if this were fully built out.
    // Here, we rely on the client sending its username.
    const { username, publicKey } = req.body;
    const reqLogger = getLogger(`update-key-${username || req.ip}`);

    if (!username || !publicKey) {
        reqLogger.warn('Attempt with missing username or public key.');
        return res.status(400).json({ error: 'Username and publicKey are required.' });
    }
    // Add proper authorization check here: if (req.user.username !== username) return res.status(403).json({error: "Forbidden"});

    try {
        const result = await dbQuery('UPDATE users SET public_key = $1 WHERE username = $2', [publicKey, username]);
        if (result.rowCount > 0) {
            reqLogger.log(`Public key updated for user: ${username}`);
            // Notify connected WebSocket instance for this user if any, about key update? (might be complex)
            res.json({ message: 'Public key updated successfully.' });
        } else {
            reqLogger.warn(`User not found for key update: ${username}`);
            res.status(404).json({ error: 'User not found.' });
        }
    } catch (err) {
        reqLogger.error('Error updating public key in DB.', err);
        res.status(500).json({ error: 'Server error updating public key.' });
    }
});


app.get('/public-keys', async (req, res) => {
  const reqLogger = getLogger(`public-keys-${req.ip}`);
  try {
    const result = await dbQuery("SELECT username, public_key FROM users WHERE public_key IS NOT NULL AND public_key != '' AND public_key != 'dummy-public-key-for-testing'", []);
    const keys = {};
    result.rows.forEach(r => { keys[r.username] = r.public_key; });
    // reqLogger.log(`Workspaceed ${Object.keys(keys).length} public keys.`);
    res.json(keys);
  } catch (err) {
    reqLogger.error('Failed to fetch public keys.', err);
    res.status(500).json({ error: 'Could not retrieve public keys.' });
  }
});

app.get('/user-profiles', async (req, res) => {
  const reqLogger = getLogger(`user-profiles-${req.ip}`);
  try {
    const result = await dbQuery('SELECT username, display_name, status FROM users', []);
    const profiles = {};
    result.rows.forEach(r => profiles[r.username] = { displayName: r.display_name, status: r.status });
    // reqLogger.log(`Workspaceed ${Object.keys(profiles).length} user profiles.`);
    res.json(profiles);
  } catch (err) {
    reqLogger.error('Failed to fetch user profiles.', err);
    res.status(500).json({ error: 'Could not retrieve user profiles.' });
  }
});

app.post('/update-profile', async (req, res) => {
  // TODO: Add authentication to ensure req.user.username matches req.body.username
  const { username, profile } = req.body;
  const reqLogger = getLogger(`update-profile-${username || req.ip}`);
  if (!username || !profile || !profile.displayName || !profile.status) {
    reqLogger.warn("Attempt with missing profile data.");
    return res.status(400).json({error: "Username, displayName, and status are required."});
  }
  // Add authorization: if (req.authUsername !== username) return res.status(403).json(...)
  try {
    const result = await dbQuery(
      'UPDATE users SET display_name = $1, status = $2 WHERE username = $3',
      [profile.displayName, profile.status, username]
    );
    if (result.rowCount > 0) {
        reqLogger.log(`Profile updated for ${username}.`);
        broadcastWsMessage({ 
            type: 'profile_update', 
            username, 
            profile: {displayName: profile.displayName, status: profile.status } 
        });
        res.json({ message: 'Profile updated successfully.' });
    } else {
        reqLogger.warn(`User not found for profile update: ${username}`);
        res.status(404).json({error: "User not found."});
    }
  } catch (err) {
    reqLogger.error('Profile update DB error.', err);
    res.status(500).json({ error: 'Server error updating profile.' });
  }
});

app.get('/message-history', async (req, res) => {
  const reqLogger = getLogger(`message-history-${req.ip}`);
  try {
    // Fetch both text messages and file messages, then combine and sort by time
    const messagesResult = await dbQuery(
      `SELECT id, sender as username, recipient, content, is_encrypted as encrypted, timestamp as time, 'message' as type, formatted, 
              NULL as filename, NULL as file_url, NULL as file_type, NULL as encrypted_key, NULL as iv 
       FROM messages 
       ORDER BY timestamp DESC LIMIT 100`, // Limit history for performance
      []
    );
    const filesResult = await dbQuery(
      `SELECT id, sender as username, recipient, NULL as content, is_encrypted as encrypted, timestamp as time, 'file' as type, false as formatted, 
              filename, file_url, file_type, encrypted_key, iv 
       FROM files 
       ORDER BY timestamp DESC LIMIT 50`, // Separate limit for files
      []
    );
    
    const combinedHistory = [...messagesResult.rows, ...filesResult.rows];
    combinedHistory.sort((a, b) => new Date(a.time) - new Date(b.time)); // Sort ascending by time

    // reqLogger.log(`Retrieved ${combinedHistory.length} items for message history.`);
    res.json(combinedHistory);
  } catch (err) {
    reqLogger.error('Failed to retrieve message history.', err);
    res.status(500).json({ error: 'Could not retrieve message history.' });
  }
});

app.get('/health', (req, res) => {
  dbQuery('SELECT NOW() AS db_time')
    .then(dbRes => res.json({ status: 'ok', database: 'connected', serverTime: new Date().toISOString(), dbTime: dbRes.rows[0].db_time }))
    .catch(dbErr => {
        systemLogger.error("Health check DB error:", dbErr);
        res.status(503).json({ status: 'error', database: 'disconnected', serverTime: new Date().toISOString(), error: "Database connection failed" });
    });
});


// --- WebSocket Server Logic ---
function broadcastWsMessage(message, excludeWs = null) {
    const messageString = JSON.stringify(message);
    connections.forEach((wsInstance, username) => {
        if (wsInstance !== excludeWs && wsInstance.readyState === WebSocket.OPEN) {
            // More nuanced broadcast:
            // - System messages: usually to all
            // - Profile updates: usually to all
            // - Online users: usually to all
            // - Messages/Files: only if recipient is 'all' or matches 'username'
            let shouldSend = false;
            if (message.type === 'system' || message.type === 'profile_update' || message.type === 'online_users' || message.type === 'typing_indicator') {
                if (message.type === 'typing_indicator') { // Typing indicator specific logic
                    if (message.recipient === 'all' || message.recipient === username) { // if public typing or typing for me
                       shouldSend = true;
                    }
                } else {
                    shouldSend = true; // Send other general broadcasts
                }
            } else if (message.recipient === 'all' || message.recipient === username) {
                shouldSend = true; // Message is public or directly for this user
            }
            
            if (shouldSend) {
                wsInstance.send(messageString, (err) => {
                    if (err) getLogger(username).error("WS send error during broadcast:", err);
                });
            }
        }
    });
}

function sendWsMessageToUser(targetUsername, message) {
    const destWs = connections.get(targetUsername);
    if (destWs && destWs.readyState === WebSocket.OPEN) {
        destWs.send(JSON.stringify(message), (err) => {
            if (err) getLogger(targetUsername).error("WS send error to user:", err);
        });
        return true;
    }
    return false;
}

wss.on('connection', (ws, req) => {
  const ip = req.socket.remoteAddress;
  const connLogger = getLogger(`ws-conn-${ip}`);
  connLogger.log('WebSocket connection initiated.');
  ws.isAlive = true; // For ping/pong keep-alive

  ws.on('pong', () => { ws.isAlive = true; }); // Standard pong reply

  ws.on('message', async rawMessage => {
    let data;
    try {
      // Ensure rawMessage is a string or Buffer before parsing
      const messageStr = Buffer.isBuffer(rawMessage) ? rawMessage.toString() : rawMessage;
      data = JSON.parse(messageStr);
    } catch (parseError) {
      connLogger.error('Failed to parse WS message:', parseError);
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type: 'system', message: 'Error: Invalid message format.'}));
      return;
    }

    const currentUser = ws.username; // Should be set after 'auth'
    const currentLogger = currentUser ? getLogger(currentUser) : connLogger;

    if (data.type === 'auth') {
      const { username, password, publicKey: clientAuthPublicKey } = data;
      if (!username || !password) {
        currentLogger.warn("WS auth failed: Missing credentials.");
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'system', message: 'Authentication failed: Missing credentials.' }));
        ws.close(1008, "Missing credentials"); return;
      }
      
      try {
        const user = await getUserByUsername(username);
        if (user && await bcrypt.compare(password, user.password_hash)) {
          ws.username = username; // Crucial: Associate WS with username
          ws.isAlive = true;
          const oldWs = connections.get(username);
          if (oldWs && oldWs !== ws) {
            getLogger(username).log("Closing stale WebSocket connection for user.");
            oldWs.close(4001, "New connection established by the same user.");
          }
          connections.set(username, ws);
          
          if (clientAuthPublicKey && clientAuthPublicKey !== "dummy-public-key-for-testing" && user.public_key !== clientAuthPublicKey) {
              await dbQuery('UPDATE users SET public_key = $1 WHERE username = $2', [clientAuthPublicKey, username]);
              getLogger(username).log(`Public key updated via WS auth for ${username}.`);
          }
          await dbQuery('UPDATE users SET status = $1 WHERE username = $2', ['online', username]);

          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'system', message: `Authenticated as ${username}. Welcome!` }));
          const onlineUsernames = Array.from(connections.keys());
          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'online_users', users: onlineUsernames })); 
          
          broadcastWsMessage({ type: 'system', message: `${username} has connected.` }, ws);
          broadcastWsMessage({ type: 'online_users', users: onlineUsernames });

          getLogger(username).log('WebSocket authenticated successfully.');
        } else {
          getLogger(username || ip).warn('WS auth failed: Invalid credentials.');
          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'system', message: 'Authentication failed.' }));
          ws.close(1008, "Invalid credentials");
        }
      } catch (authError) {
        getLogger(username || ip).error('Error during WS auth:', authError);
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'system', message: 'Server error during authentication.' }));
        ws.close(1011, "Server error");
      }
      return;
    }

    if (!currentUser) { 
      currentLogger.warn('WS message received before authentication.');
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'system', message: 'Not authenticated.' }));
      return;
    }

    // --- Handle Authenticated Messages ---
    try {
        switch (data.type) {
            case 'message': {
              const msg = {
                type: 'message', id: data.messageId || generateUniqueId(),
                username: currentUser, content: data.content, encrypted: !!data.encrypted,
                formatted: !!data.formatted, recipient: data.recipient || 'all',
                time: new Date().toISOString()
              };
              await dbQuery(
                'INSERT INTO messages(id, sender, recipient, content, is_encrypted, timestamp, formatted) VALUES($1,$2,$3,$4,$5,$6,$7)',
                [msg.id, msg.username, msg.recipient, msg.content, msg.encrypted, msg.time, msg.formatted || false]
              );
              currentLogger.log(`Msg to ${msg.recipient}: ${msg.encrypted ? '[E2E]' : (msg.content.substring(0,30) + '...')}`);

              if (msg.recipient !== 'all') {
                sendWsMessageToUser(msg.recipient, msg); 
                if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg)); // Echo to sender
              } else {
                broadcastWsMessage(msg); 
              }
              if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'read_receipt', messageId: msg.id, status: 'delivered', byServer: true }));
              break;
            }
            case 'file': {
              const fileMsg = {
                type: 'file', id: data.messageId || generateUniqueId(),
                username: currentUser, fileUrl: data.fileUrl, filename: data.filename,
                fileType: data.fileType, encrypted: !!data.encrypted,
                encryptedKey: data.encryptedKey, iv: data.iv, // Pass these along for E2EE files
                recipient: data.recipient || 'all', time: new Date().toISOString()
              };
              await dbQuery(
                'INSERT INTO files(id, sender, recipient, filename, file_url, file_type, is_encrypted, timestamp, encrypted_key, iv) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
                [fileMsg.id, fileMsg.username, fileMsg.recipient, fileMsg.filename, fileMsg.fileUrl, fileMsg.fileType, fileMsg.encrypted, fileMsg.time, fileMsg.encryptedKey, fileMsg.iv]
              );
              currentLogger.log(`File to ${fileMsg.recipient}: ${fileMsg.filename} ${fileMsg.encrypted ? '[E2E]' : ''}`);
              
              if (fileMsg.recipient !== 'all') {
                sendWsMessageToUser(fileMsg.recipient, fileMsg);
                if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(fileMsg)); 
              } else {
                broadcastWsMessage(fileMsg);
              }
              if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'read_receipt', messageId: fileMsg.id, status: 'delivered', byServer: true }));
              break;
            }
            case 'typing': { // Client indicates typing start/stop
              broadcastWsMessage({ 
                  type: 'typing_indicator', 
                  username: currentUser, 
                  isTyping: data.isTyping, 
                  recipient: data.recipient || 'all' // So client can filter if it's for them
              }, ws); // Exclude self
              break;
            }
            case 'read_receipt': { // Client A tells server they read message X from Client B
              sendWsMessageToUser(data.sender, { // Notify Client B (original sender)
                  type: 'read_receipt', messageId: data.messageId, 
                  reader: currentUser, status: 'read', time: new Date().toISOString() 
              });
              currentLogger.log(`Read receipt for msg ${data.messageId} by ${currentUser} forwarded to ${data.sender}`);
              break;
            }
            case 'ping': // Client-initiated ping (different from server's keep-alive)
              if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'pong', clientTime: data.time, serverTime: new Date().toISOString() }));
              break;
            default:
              currentLogger.warn(`Unknown WS message type: ${data.type}`);
              if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'system', message: `Unknown command: ${data.type}`}));
          }
    } catch (handlerError) {
        currentLogger.error(`Error handling WS message (type ${data.type}):`, handlerError);
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'system', message: 'Error processing your request.'}));
    }
  });

  ws.on('close', async (code, reason) => {
    const closedUser = ws.username; 
    if (closedUser) {
        const closeLogger = getLogger(closedUser);
        closeLogger.log(`WS connection closed. Code: ${code}, Reason: ${reason ? reason.toString() : 'N/A'}`);
        if (connections.get(closedUser) === ws) { // Only delete if it's the current connection for that user
            connections.delete(closedUser);
            try {
                await dbQuery('UPDATE users SET status = $1 WHERE username = $2', ['offline', closedUser]);
                closeLogger.log('User status set to offline.');
                const onlineUsernames = Array.from(connections.keys());
                broadcastWsMessage({ type: 'system', message: `${closedUser} has disconnected.` });
                broadcastWsMessage({ type: 'online_users', users: onlineUsernames });
            } catch (err) {
                closeLogger.error('Error during user disconnect cleanup:', err);
            }
        } else {
            closeLogger.log("Closed WS was stale/already replaced for user.");
        }
    } else {
        connLogger.log(`Unauthenticated WS connection closed. Code: ${code}, Reason: ${reason ? reason.toString() : 'N/A'}`);
    }
  });

  ws.on('error', (error) => {
    const errorLogger = ws.username ? getLogger(ws.username) : connLogger;
    errorLogger.error('WebSocket instance error:', error);
    // ws.on('close') should naturally follow and handle cleanup.
  });
});

// --- Server Keep-Alive for WebSockets ---
const wsKeepAliveInterval = setInterval(() => {
  connections.forEach((wsInstance, username) => {
    if (!wsInstance.isAlive) {
      getLogger(username).warn("WebSocket keep-alive failed. Terminating connection.");
      wsInstance.terminate(); // Force close if no pong received
      // connections.delete(username); // Removed here, ws.on('close') handles this
      return;
    }
    wsInstance.isAlive = false; // Expect a pong back to set this to true
    wsInstance.ping(null, false, (err) => { // Send a standard WebSocket ping
        if(err) getLogger(username).error("Error sending keep-alive ping:", err);
    });
  });
}, 30000); // Check every 30 seconds

wss.on('close', () => { // When the entire WebSocket server closes
  clearInterval(wsKeepAliveInterval);
  systemLogger.log("WebSocket server closed. Cleared keep-alive interval.");
});


// --- Start Server ---
const PORT = process.env.PORT || 3001; // Render sets PORT env var
server.listen(PORT, '0.0.0.0', () => {
  systemLogger.log(`Server listening on http://0.0.0.0:${PORT}`);
  systemLogger.log(`WebSocket server is ready and listening on the same port.`);
  systemLogger.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// --- Graceful Shutdown ---
function gracefulShutdown(signal) {
  systemLogger.log(`${signal} signal received. Closing server gracefully...`);
  server.close(() => {
    systemLogger.log('HTTP server closed.');
    wss.clients.forEach(client => client.terminate()); // Close all WebSocket connections
    wss.close(() => {
        systemLogger.log('WebSocket server closed.');
        pool.end(() => {
          systemLogger.log('PostgreSQL pool has ended.');
          process.exit(0);
        });
    });
  });

  // Healthcheck route for uptime monitoring
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

  // If server hasn't finished in a timeout, force exit
  setTimeout(() => {
    systemLogger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000); // 10 seconds
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT')); // For Ctrl+C in local dev