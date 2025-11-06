ginger/
├─ server.js
├─ package.json
├─ src/
│  ├─ auth.js
│  ├─ db.js
│  ├─ signaling.js
│  ├─ stripe.js
│  └─ routes/
│     ├─ users.js
│     ├─ messages.js
│     └─ ... 
├─ public/
│  ├─ index.html
│  ├─ app.js
│  └─ libsodium.js (CDN)
├─ docker-compose.yml
├─ nginx/
│  ├─ nginx.conf
│  └─ site.conf
└─ README.md
{
  "name": "ginger-backend",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "NODE_ENV=development nodemon server.js"
  },
  "dependencies": {
    "better-sqlite3": "^8.4.0",
    "bcrypt": "^5.1.0",
    "cors": "^2.8.5",
    "express": "^4.18.2",
    "express-rate-limit": "^6.7.0",
    "helmet": "^7.0.0",
    "jsonwebtoken": "^9.0.0",
    "ws": "^8.13.0",
    "body-parser": "^1.20.2",
    "stripe": "^12.0.0",
    "express-validator": "^7.0.1",
    "uuid": "^9.0.0"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  }
}
// server.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const bodyParser = require('body-parser');
const { initDb } = require('./src/db');
const { registerRoutes } = require('./src/routes/users');
const { registerMessageRoutes } = require('./src/routes/messages');
const { startSignaling } = require('./src/signaling');
const { stripeRouter } = require('./src/stripe');

const app = express();
const server = http.createServer(app);

// Basic middleware
app.use(helmet({
  contentSecurityPolicy: false // CSP можно включить отдельно после настройки фронтенда
}));
app.use(cors({
  origin: process.env.CLIENT_ORIGIN || 'https://your-domain.example', // изменить на реальный домен
  credentials: true
}));
app.use(bodyParser.json({ limit: '1mb' }));

// rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests, try later.' }
});
app.use(limiter);

// init DB
initDb();

// routes
registerRoutes(app);       // /api/auth, /api/user/keys etc
registerMessageRoutes(app);// /api/messages (encrypted messages ops)
app.use('/stripe', stripeRouter); // /stripe/webhook & /stripe/create-checkout-session

// static frontend (if deploying in same server)
app.use(express.static('public'));

// WebSocket signaling (uses same http server)
startSignaling(server, { jwtSecret: process.env.JWT_SECRET || 'dev-secret' });

// start
const PORT = process.env.PORT || 3000;
server.listen(PORT, ()=> console.log(`Server listening on ${PORT}`));
// src/db.js
const Database = require('better-sqlite3');
let db;

function initDb(){
  db = new Database(process.env.DB_FILE || 'ginger.sqlite');
  db.pragma('journal_mode = WAL');

  db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    password_hash TEXT,
    created_at INTEGER,
    public_key TEXT,
    rocket INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT,
    expires_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    from_user TEXT,
    to_user TEXT,
    ciphertext TEXT,
    created_at INTEGER,
    channel_id TEXT
  );
  `);
}

function getDb(){ if(!db) initDb(); return db; }

module.exports = { initDb, getDb };
// src/routes/users.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { getDb } = require('../db');
const { body, validationResult } = require('express-validator');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const JWT_EXPIRES = '15m';
const REFRESH_EXPIRES_MS = 1000*60*60*24*7; // 7 days

function signAccess(payload){ return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES }); }

function registerRoutes(app){
  const router = express.Router();

  router.post('/register',
    body('email').isEmail(),
    body('password').isLength({min:8}),
    async (req, res) => {
      const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
      const { email, password, publicKey } = req.body;
      const db = getDb();
      const existing = db.prepare('SELECT id FROM users WHERE email=?').get(email);
      if(existing) return res.status(409).json({ error: 'Email exists' });
      const hash = await bcrypt.hash(password, 12);
      const id = uuidv4();
      db.prepare('INSERT INTO users (id,email,password_hash,created_at,public_key) VALUES (?,?,?,?,?)').run(id, email, hash, Date.now(), publicKey || null);
      const access = signAccess({ sub:id, email });
      const refresh = uuidv4();
      db.prepare('INSERT INTO refresh_tokens (token,user_id,expires_at) VALUES (?,?,?)').run(refresh, id, Date.now()+REFRESH_EXPIRES_MS);
      res.json({ accessToken: access, refreshToken: refresh, user:{ id, email } });
    });

  router.post('/login', body('email').isEmail(), body('password').isString(), async (req,res)=>{
    const { email, password } = req.body;
    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if(!user) return res.status(401).json({ error:'Invalid' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if(!ok) return res.status(401).json({ error:'Invalid' });
    const access = signAccess({ sub:user.id, email });
    const refresh = uuidv4();
    db.prepare('INSERT INTO refresh_tokens (token,user_id,expires_at) VALUES (?,?,?)').run(refresh, user.id, Date.now()+REFRESH_EXPIRES_MS);
    res.json({ accessToken: access, refreshToken: refresh, user:{ id:user.id, email } });
  });

  router.post('/refresh', body('refreshToken').isString(), (req,res)=>{
    const { refreshToken } = req.body;
    const db = getDb();
    const r = db.prepare('SELECT * FROM refresh_tokens WHERE token=?').get(refreshToken);
    if(!r || r.expires_at < Date.now()) return res.status(401).json({ error:'invalid_refresh' });
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(r.user_id);
    if(!user) return res.status(401).json({ error:'user_missing' });
    const access = signAccess({ sub:user.id, email:user.email });
    res.json({ accessToken: access });
  });

  // protected: update public key
  const authMiddleware = (req,res,next)=>{
    const auth = req.headers.authorization;
    if(!auth) return res.status(401).json({ error:'no_auth' });
    const token = auth.split(' ')[1];
    try{
      const payload = jwt.verify(token, JWT_SECRET);
      req.user = payload;
      next();
    }catch(e){ return res.status(401).json({ error:'invalid_token' }); }
  };

  router.post('/me/key', authMiddleware, body('publicKey').isString().notEmpty(), (req,res)=>{
    const { publicKey } = req.body;
    const db = getDb();
    db.prepare('UPDATE users SET public_key=? WHERE id=?').run(publicKey, req.user.sub);
    res.json({ ok:true });
  });

  // get user public key by id or email
  router.get('/user/:id/key', (req,res)=>{
    const db = getDb();
    const u = db.prepare('SELECT id,public_key FROM users WHERE id=?').get(req.params.id);
    if(!u) return res.status(404).json({ error:'notfound' });
    res.json({ id: u.id, publicKey: u.public_key });
  });

  app.use('/api', router);
}
module.exports = { registerRoutes };
// src/routes/messages.js
const express = require('express');
const { getDb } = require('../db');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

function auth(req,res,next){
  const h = req.headers.authorization; if(!h) return res.status(401).json({ error:'noauth' });
  const token = h.split(' ')[1];
  try{ req.user = jwt.verify(token, JWT_SECRET); next(); } catch(e){ return res.status(401).json({ error:'invalid' }); }
}

function registerMessageRoutes(app){
  const router = express.Router();

  router.post('/send', auth,
    body('toUser').isString().notEmpty(),
    body('ciphertext').isString().notEmpty(),
    body('channelId').optional().isString(),
    (req,res)=>{
      const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
      const { toUser, ciphertext, channelId } = req.body;
      const db = getDb();
      const id = require('uuid').v4();
      db.prepare('INSERT INTO messages (id,from_user,to_user,ciphertext,created_at,channel_id) VALUES (?,?,?,?,?,?)')
        .run(id, req.user.sub, toUser, ciphertext, Date.now(), channelId || null);
      res.json({ ok:true, id });
    });

  // get messages for user (returns ciphertext only)
  router.get('/inbox', auth, (req,res)=>{
    const db = getDb();
    const rows = db.prepare('SELECT id,from_user,to_user,ciphertext,created_at,channel_id FROM messages WHERE to_user = ? OR from_user = ? ORDER BY created_at ASC').all(req.user.sub, req.user.sub);
    res.json({ messages: rows });
  });

  app.use('/api', router);
}
module.exports = { registerMessageRoutes };
// src/signaling.js
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const { getDb } = require('./db');

function startSignaling(server, opts = {}){
  const wss = new WebSocket.Server({ server, path: '/ws' });
  const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
  const rooms = new Map(); // roomId -> Set(ws)

  wss.on('connection', (ws, req) => {
    const params = new URLSearchParams(req.url.split('?')[1]);
    const token = params.get('token');
    if(!token){ ws.close(4001, 'no token'); return; }
    let user;
    try { user = jwt.verify(token, JWT_SECRET); }
    catch(e){ ws.close(4002, 'invalid token'); return; }
    ws.user = user;

    ws.on('message', (raw) => {
      let msg;
      try{ msg = JSON.parse(raw.toString()); } catch(e){ return; }
      // msg: { type, room, ... }
      const { type, room } = msg;
      if(type === 'join' && room){
        if(!rooms.has(room)) rooms.set(room, new Set());
        rooms.get(room).add(ws);
        ws.room = room;
        // notify others
        rooms.get(room).forEach(client => {
          if(client !== ws && client.readyState === WebSocket.OPEN) client.send(JSON.stringify({ type:'peer-joined', userId: user.sub }));
        });
      } else if(room){
        // Broadcast to others in same room
        const set = rooms.get(room);
        if(!set) return;
        set.forEach(client=>{
          if(client !== ws && client.readyState === WebSocket.OPEN){
            client.send(JSON.stringify({ ...msg, from: user.sub }));
          }
        });
      }
    });

    ws.on('close', ()=> {
      const r = ws.room;
      if(r && rooms.has(r)){
        rooms.get(r).delete(ws);
        if(rooms.get(r).size === 0) rooms.delete(r);
      }
    });
  });
}
module.exports = { startSignaling };
// src/stripe.js
const express = require('express');
const router = express.Router();
const stripeKey = process.env.STRIPE_SECRET_KEY || '';
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET || '';
const stripe = stripeKey ? require('stripe')(stripeKey) : null;
const { getDb } = require('../db');
const jwt = require('jsonwebtoken');

router.post('/create-checkout-session', async (req,res)=>{
  if(!stripe) return res.status(500).json({ error:'stripe_not_configured' });
  const { priceId } = req.body;
  try{
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: (req.headers.origin || 'https://your-domain.example') + '/?checkout=success',
      cancel_url: (req.headers.origin || 'https://your-domain.example') + '/?checkout=cancel',
    });
    res.json({ url: session.url });
  } catch(err){ res.status(500).json({ error: err.message }); }
});

// webhook endpoint
router.post('/webhook', express.raw({ type: 'application/json' }), (req,res)=>{
  if(!stripe) return res.status(500).end('stripe not configured');
  const sig = req.headers['stripe-signature'];
  let event;
  try{
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch(err){ console.error(err); return res.status(400).send(`Webhook error: ${err.message}`); }
  // handle checkout.session.completed
  if(event.type === 'checkout.session.completed'){
    const session = event.data.object;
    // TODO: map session.customer / metadata to user in DB
    // Example: save subscription status for user by email or metadata
    // If you used metadata: session.metadata.userId -> mark db user rocket = 1
    if(session.customer_email){
      const db = getDb();
      const u = db.prepare('SELECT id FROM users WHERE email = ?').get(session.customer_email);
      if(u) db.prepare('UPDATE users SET rocket = 1 WHERE id = ?').run(u.id);
    }
  }
  res.json({ received: true });
});

module.exports = { stripeRouter: router };
<!-- public/index.html (фрагмент) -->
<!doctype html><html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>GINGER — secure demo</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/libsodium-wrappers/0.7.10/libsodium-wrappers.js"></script>
</head><body>
<!-- регистрация/вход формы, UI чатов (как в предыдущем коде) -->
<script>
(async ()=> {
  await sodium.ready;
  const sodiumLib = sodium;

  // helper: generate keypair and store private locally
  function generateKeypair(){
    const kp = sodiumLib.crypto_box_keypair();
    // store secretKey encrypted in localStorage with a passphrase? here — store raw (warning)
    localStorage.setItem('ginger:priv', sodiumLib.to_base64(kp.privateKey));
    localStorage.setItem('ginger:pub', sodiumLib.to_base64(kp.publicKey));
    return kp;
  }

  function getLocalKeys(){
    const privB64 = localStorage.getItem('ginger:priv');
    const pubB64 = localStorage.getItem('ginger:pub');
    if(!privB64 || !pubB64) return null;
    return {
      privateKey: sodiumLib.from_base64(privB64),
      publicKey: sodiumLib.from_base64(pubB64)
    };
  }

  // sealed box encrypt (recipient's public key)
  function encryptFor(recipientPubKeyBase64, plaintext){
    const pk = sodiumLib.from_base64(recipientPubKeyBase64);
    const cipher = sodiumLib.crypto_box_seal(plaintext, pk);
    return sodiumLib.to_base64(cipher);
  }

  // sealed box decrypt (requires private key)
  function decryptSealed(cipherB64){
    const sk = getLocalKeys().privateKey;
    const c = sodiumLib.from_base64(cipherB64);
    const msg = sodiumLib.crypto_box_seal_open(c, getLocalKeys().publicKey, sk);
    return new TextDecoder().decode(msg);
  }

  // register flow example
  async function register(email, password){
    let keys = getLocalKeys();
    if(!keys) keys = generateKeypair();
    const pub = sodiumLib.to_base64(keys.publicKey);
    const resp = await fetch('/api/register', {
      method:'POST',
      headers:{ 'content-type':'application/json' },
      body: JSON.stringify({ email, password, publicKey: pub })
    });
    const data = await resp.json();
    if(resp.ok){ localStorage.setItem('access', data.accessToken); localStorage.setItem('refresh', data.refreshToken); alert('registered'); }
    else alert(JSON.stringify(data));
  }

  // sending encrypted message to user:
  async function sendEncrypted(toUserId, recipientPubKeyB64, plainText){
    const cipher = encryptFor(recipientPubKeyB64, new TextEncoder().encode(plainText));
    const token = localStorage.getItem('access');
    await fetch('/api/send', {
      method:'POST', headers:{ 'content-type':'application/json', 'authorization':'Bearer '+token },
      body: JSON.stringify({ toUser: toUserId, ciphertext: cipher })
    });
  }

  // receiving messages: call /api/inbox and decrypt where possible
})();
</script>
</body></html>
version: '3.8'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - JWT_SECRET=your_jwt_secret
      - STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY}
      - STRIPE_WEBHOOK_SECRET=${STRIPE_WEBHOOK_SECRET}
    volumes:
      - ./public:/usr/src/app/public
      - ./data:/usr/src/app/data
  nginx:
    image: nginx:stable
    volumes:
      - ./nginx/site.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs:/etc/letsencrypt
    ports:
      - "80:80"
      - "443:443"
server {
  listen 80;
  server_name your-domain.example;
  location /.well-known/acme-challenge/ { root /var/www/certbot; }
  location / { proxy_pass http://app:3000; proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade"; }
}
# После получения сертификатов — включаем 443 с SSL сертификатами от Let's Encrypt
PORT=3000
JWT_SECRET=verysecret
CLIENT_ORIGIN=http://localhost:3000
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=
