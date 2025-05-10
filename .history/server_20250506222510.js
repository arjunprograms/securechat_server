// Enhanced server.js with additional security features
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const { formidable } = require('formidable');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt'); // New dependency for password hashing
const mysql = require('mysql2/promise');

// MySQL Database connection
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'sql102.infinityfree.com',
  user: process.env.DB_USER || 'if0_38921113',
  password: process.env.DB_PASSWORD || '', 
  database: process.env.DB_NAME || 'if0_38921113_securechat_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Create Express app and HTTP server
const app = express();
const server = http.createServer(app);

// Initialize WebSocket server on the same HTTP server
const wss = new WebSocket.Server({ server });

// Use CORS middleware to allow cross-origin requests
app.use(cors());
// Parse JSON bodies for HTTP endpoints
app.use(express.json());

// Ensure the uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Ensure the logs directory exists
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

// Serve uploaded files statically so clients can download them
app.use('/uploads', express.static(uploadDir));

// Store user connections and their public keys
const connections = new Map();

// Track typing status
const typingUsers = new Set();

// Track failed login attempts
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes in milliseconds

// User database functions
async function getUserByUsername(username) {
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    return rows[0];
  } catch (error) {
    console.error('Database error:', error);
    return null;
  }
}

async function getAllUsers() {
  try {
    const [rows] = await pool.query('SELECT * FROM users');
    return rows;
  } catch (error) {
    console.error('Database error:', error);
    return [];
  }
}

// Setup logging
function createLogger(username) {
  const date = new Date().toISOString().replace(/:/g, '-');
  const logFile = path.join(logsDir, `${username}_${date}.txt`);
  
  return {
    log: (message) => {
      const timestamp = new Date().toISOString();
      const logEntry = `[${timestamp}] ${message}\n`;
      fs.appendFileSync(logFile, logEntry);
    }
  };
}

// --- File Upload Endpoint ---
app.post('/upload', async (req, res) => {
  // Configure formidable for file upload processing
  const form = formidable({
    uploadDir: uploadDir,
    keepExtensions: true,
    maxFileSize: 10 * 1024 * 1024  // Limit file size to 10MB
  });

  try {
    // Parse the incoming form data
    const [fields, files] = await form.parse(req);
    // Get the first file from the parsed files object
    const fileKey = Object.keys(files)[0];
    const file = files[fileKey]?.[0];

    // If no file was uploaded, return an error
    if (!file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Use the original filename if available
    const filename = file.originalFilename || 'uploaded-file';
    const newPath = path.join(uploadDir, filename);

    // Rename/move the file from temporary location to our uploads folder
    fs.renameSync(file.filepath, newPath);

    // Respond with file details so the client can construct a download link
    res.json({
      url: '/uploads/' + filename,
      filename: filename,
      type: file.mimetype
    });
  } catch (error) {
    console.error('File upload error:', error);
    res.status(500).json({ error: 'Upload failed: ' + error.message });
  }
});

// --- User Registration Endpoint ---
app.post('/register', async (req, res) => {
  const { username, password, publicKey, profile } = req.body;
  
  // Basic validation
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  try {
    // Check if user exists
    const existingUser = await getUserByUsername(username);
    if (existingUser) {
      return res.status(400).json({ error: 'Username already taken' });
    }
    
    // Hash the password with bcrypt (10 rounds of salt)
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Create user in database
    await pool.query(
      'INSERT INTO users (username, password_hash, public_key, display_name, status) VALUES (?, ?, ?, ?, ?)',
      [
        username, 
        hashedPassword, 
        publicKey,
        profile?.displayName || username,
        'offline'
      ]
    );
    
    const logger = createLogger('system');
    logger.log(`User registered: ${username}`);
    
    res.json({ message: 'Registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed: ' + error.message });
  }
});

// --- User Login Endpoint ---
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Check if account is locked due to too many failed attempts
  if (loginAttempts.has(username)) {
    const attempts = loginAttempts.get(username);
    
    if (attempts.count >= MAX_LOGIN_ATTEMPTS && (Date.now() - attempts.lastAttempt) < LOCKOUT_TIME) {
      // Account is locked
      const remainingLockTime = Math.ceil((LOCKOUT_TIME - (Date.now() - attempts.lastAttempt)) / 60000);
      return res.status(429).json({ 
        error: `Account is temporarily locked. Try again in ${remainingLockTime} minutes.` 
      });
    }
    
    // Reset counter if lockout period has passed
    if ((Date.now() - attempts.lastAttempt) >= LOCKOUT_TIME) {
      loginAttempts.delete(username);
    }
  }
  
  try {
    // Get user from database
    const user = await getUserByUsername(username);
    
    // If user doesn't exist
    if (!user) {
      // Record failed attempt
      recordFailedLoginAttempt(username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Compare passwords using bcrypt
    const match = await bcrypt.compare(password, user.password_hash);
    
    if (!match) {
      // Record failed attempt
      recordFailedLoginAttempt(username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Reset failed login attempts on successful login
    loginAttempts.delete(username);
    
    // Update user status
    await pool.query('UPDATE users SET status = ? WHERE username = ?', ['online', username]);
    
    // Create a session log
    const logger = createLogger(username);
    logger.log(`User logged in: ${username}`);
    
    res.json({ 
      message: 'Logged in successfully',
      publicKey: user.public_key
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed: ' + error.message });
  }
});

// Record failed login attempt
function recordFailedLoginAttempt(username) {
  if (!loginAttempts.has(username)) {
    loginAttempts.set(username, { count: 1, lastAttempt: Date.now() });
  } else {
    const attempts = loginAttempts.get(username);
    attempts.count += 1;
    attempts.lastAttempt = Date.now();
  }
  
  const logger = createLogger('security');
  logger.log(`Failed login attempt for user: ${username} (Attempt ${loginAttempts.get(username).count})`);
  
  // If max attempts reached, log it
  if (loginAttempts.get(username).count >= MAX_LOGIN_ATTEMPTS) {
    logger.log(`Account locked: ${username} - Too many failed login attempts`);
  }
}

// --- Get Public Keys Endpoint ---
app.get('/public-keys', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT username, public_key FROM users');
    const publicKeys = {};
    
    rows.forEach(user => {
      if (user.public_key) {
        publicKeys[user.username] = user.public_key;
      }
    });
    
    res.json(publicKeys);
  } catch (error) {
    console.error('Error fetching public keys:', error);
    res.status(500).json({ error: 'Failed to fetch public keys' });
  }
});

// --- Get User Profiles ---
app.get('/user-profiles', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT username, display_name, status FROM users');
    const profiles = {};
    
    rows.forEach(user => {
      profiles[user.username] = {
        displayName: user.display_name,
        status: user.status
      };
    });
    
    res.json(profiles);
  } catch (error) {
    console.error('Error fetching user profiles:', error);
    res.status(500).json({ error: 'Failed to fetch user profiles' });
  }
});

// --- Update User Profile ---
app.post('/update-profile', async (req, res) => {
  const { username, profile } = req.body;
  
  try {
    // Check if user exists
    const [result] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    
    if (result.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Update the profile fields in database
    await pool.query(
      'UPDATE users SET display_name = ?, status = ? WHERE username = ?',
      [profile.displayName, profile.status, username]
    );
    
    // Broadcast profile update to all connected clients
    broadcast({
      type: 'profile_update',
      username,
      profile: {
        displayName: profile.displayName,
        status: profile.status
      }
    });
    
    // Log the profile update
    const logger = createLogger(username);
    logger.log(`Profile updated for user: ${username}`);
    
    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// --- Get Message History ---
app.get('/message-history', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, sender as username, recipient, content, is_encrypted as encrypted, timestamp as time FROM messages ORDER BY timestamp'
    );
    
    res.json(rows);
  } catch (error) {
    console.error('Error retrieving message history:', error);
    res.status(500).json({ error: 'Failed to retrieve message history' });
  }
});

// --- WebSocket Connection Handler ---
wss.on('connection', (ws) => {
  let username = null;
  let logger = null;

  // Handle incoming WebSocket messages
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);

      // Authentication message: validate and store username for this connection
      if (data.type === 'auth') {
        try {
          // Get user from database
          const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [data.username]);
          const user = rows[0];
          
          // Verify user and password
          if (user) {
            const match = await bcrypt.compare(data.password, user.password_hash);
            
            if (match) {
              username = data.username;
              logger = createLogger(username);
              
              // Store the connection with the username
              connections.set(username, ws);
              
              // Update user's public key if provided
              if (data.publicKey) {
                await pool.query('UPDATE users SET public_key = ? WHERE username = ?', [data.publicKey, username]);
              }
              
              // Update user status
              await pool.query('UPDATE users SET status = ? WHERE username = ?', ['online', username]);
              
              // Send welcome message to the newly authenticated client
              ws.send(JSON.stringify({ 
                type: 'system', 
                message: `Welcome ${username}!` 
              }));
              
              // Send the list of online users
              const onlineUsers = Array.from(connections.keys());
              ws.send(JSON.stringify({
                type: 'online_users',
                users: onlineUsers
              }));
              
              // Broadcast that a new user has joined (excluding the sender)
              broadcast({ 
                type: 'system', 
                message: `${username} joined the chat` 
              }, ws);
              
              // Broadcast updated online users list to all clients
              broadcast({
                type: 'online_users',
                users: onlineUsers
              });
              
              logger.log(`User authenticated and connected via WebSocket`);
            }
          }
        } catch (error) {
          console.error('WebSocket authentication error:', error);
        }
        return;
      }

      // If the client is not authenticated, ignore messages
      if (!username) return;

      // Handle a text message
      if (data.type === 'message') {
        const messageData = {
          type: 'message',
          id: data.messageId || generateUniqueId(),
          username: username,
          content: data.content,
          encrypted: data.encrypted || false,
          formatted: data.formatted || false,
          recipient: data.recipient, // For direct messages
          time: new Date().toISOString()
        };
        
        // Store message in database
        await storeMessage(messageData);
        
        // Log the message
        logger.log(`Message sent to ${data.recipient || 'all'}: ${data.encrypted ? '[ENCRYPTED]' : data.content.substring(0, 50) + (data.content.length > 50 ? '...' : '')}`);
        
        // If it's a direct message, send only to the recipient
        if (data.recipient && data.recipient !== 'all') {
          const recipientWs = connections.get(data.recipient);
          if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
            recipientWs.send(JSON.stringify(messageData));
          }
          // Also send to the sender for their own record
          ws.send(JSON.stringify(messageData));
        } else {
          // Broadcast to all
          broadcast(messageData);
        }
        
        // Send read receipt
        ws.send(JSON.stringify({
          type: 'read_receipt',
          messageId: messageData.id,
          status: 'delivered'
        }));
      }
      // Handle typing indicator
      else if (data.type === 'typing') {
        if (data.isTyping) {
          typingUsers.add(username);
        } else {
          typingUsers.delete(username);
        }
        
        // Broadcast typing status to all except the sender
        broadcast({
          type: 'typing_indicator',
          username: username,
          isTyping: data.isTyping,
          recipient: data.recipient || 'all'
        }, ws);
      }
      // Handle ping messages (for connection heartbeat)
      else if (data.type === 'ping') {
        ws.send(JSON.stringify({
          type: 'pong',
          time: new Date().toISOString()
        }));
      }
      // Handle a file message (after successful upload on the client)
      else if (data.type === 'file') {
        const fileData = {
          type: 'file',
          id: generateUniqueId(),
          username: username,
          fileUrl: data.fileUrl,
          filename: data.filename,
          fileType: data.fileType,
          encrypted: data.encrypted || false,
          recipient: data.recipient, // For direct file sharing
          time: new Date().toISOString()
        };
        
        // Store file info in database
        await storeFileInfo(fileData);
        
        // Log the file share
        logger.log(`File shared with ${data.recipient || 'all'}: ${data.filename}`);
        
        // If it's a direct file share, send only to the recipient
        if (data.recipient && data.recipient !== 'all') {
          const recipientWs = connections.get(data.recipient);
          if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
            recipientWs.send(JSON.stringify(fileData));
          }
          // Also send to the sender for their own record
          ws.send(JSON.stringify(fileData));
        } else {
          // Broadcast to all
          broadcast(fileData);
        }
      }
      // Handle read receipt acknowledgment
      else if (data.type === 'read_receipt_ack') {
        const senderWs = connections.get(data.sender);
        if (senderWs && senderWs.readyState === WebSocket.OPEN) {
          senderWs.send(JSON.stringify({
            type: 'read_receipt',
            messageId: data.messageId,
            reader: username,
            status: 'read',
            time: new Date().toISOString()
          }));
        }
      }
    } catch (error) {
      console.error('Error processing message:', error);
    }
  });

  // Handle client disconnection
  ws.on('close', async () => {
    if (username) {
      // Remove user from connections
      connections.delete(username);
      
      // Remove from typing users if they were typing
      typingUsers.delete(username);
      
      try {
        // Update user's profile status in database
        await pool.query('UPDATE users SET status = ? WHERE username = ?', ['offline', username]);
        
        // Log the disconnection
        if (logger) {
          logger.log(`User disconnected from WebSocket`);
        }
        
        // Broadcast leave message when a user disconnects
        broadcast({ 
          type: 'system', 
          message: `${username} left the chat` 
        });
        
        // Broadcast updated online users list
        broadcast({
          type: 'online_users',
          users: Array.from(connections.keys())
        });
      } catch (error) {
        console.error('Error updating status on disconnect:', error);
      }
    }
  });
});

// Store message in MySQL database
async function storeMessage(message) {
  try {
    // Generate a unique ID if not provided
    const messageId = message.id || generateUniqueId();
    const timestamp = message.time || new Date().toISOString();
    const isEncrypted = message.encrypted ? 1 : 0;
    
    await pool.query(
      'INSERT INTO messages (id, sender, recipient, content, is_encrypted, timestamp) VALUES (?, ?, ?, ?, ?, ?)',
      [
        messageId,
        message.username,
        message.recipient || 'all',
        message.content,
        isEncrypted,
        timestamp
      ]
    );
    
    return true;
  } catch (error) {
    console.error('Error storing message:', error);
    return false;
  }
}

// Store file information in MySQL database
async function storeFileInfo(fileData) {
  try {
    await pool.query(
      'INSERT INTO files (id, sender, recipient, filename, file_url, file_type, is_encrypted, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [
        fileData.id,
        fileData.username,
        fileData.recipient || 'all',
        fileData.filename,
        fileData.fileUrl,
        fileData.fileType,
        fileData.encrypted ? 1 : 0,
        fileData.time
      ]
    );
    return true;
  } catch (error) {
    console.error('Error storing file info:', error);
    return false;
  }
}

// Generate unique ID for messages
function generateUniqueId() {
  return Date.now() + '-' + crypto.randomBytes(8).toString('hex');
}

// Broadcast function to send a message to all connected WebSocket clients,
// optionally excluding one client (e.g., the sender)
function broadcast(message, exclude = null) {
  // Don't broadcast direct messages to everyone
  if (message.recipient && message.recipient !== 'all') {
    return;
  }
  
  wss.clients.forEach(client => {
    if (client !== exclude && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

// Start the server on port from environment variable or default to 3001
const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT} (0.0.0.0)`);
});