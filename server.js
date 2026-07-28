require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const FormData = require('form-data');
const basicAuth = require('express-basic-auth');
const mongoose = require('mongoose');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const nodemailer = require('nodemailer');
const validator = require('validator');
const rateLimit = require('express-rate-limit');

const User = require('./models/User');
const Order = require('./models/Order');
const Message = require('./models/Message');
const Notification = require('./models/Notification');
const BanRecord = require('./models/BanRecord');
const Appeal = require('./models/Appeal');
const SuspiciousActivity = require('./models/SuspiciousActivity');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATA_FILE = path.join(__dirname, 'data.json');

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set. Add it to your .env file before starting the server.');
  process.exit(1);
}
if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET is not set — falling back to JWT_SECRET for the session store. Set SESSION_SECRET separately for better security.');
}

// ============================================================
// MONGODB CONNECTION
// ============================================================
let mongoReady = false;
if (process.env.MONGO_URI) {
  mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
      mongoReady = true;
      console.log('MongoDB connected.');
    })
    .catch((err) => {
      console.error('MongoDB connection failed — falling back to data.json for user/order/message/notification data:', err.message);
    });
  mongoose.connection.on('disconnected', () => {
    mongoReady = false;
    console.warn('MongoDB disconnected — falling back to data.json until it reconnects.');
  });
  mongoose.connection.on('connected', () => {
    mongoReady = true;
  });
} else {
  console.warn('WARNING: MONGO_URI is not set — running on data.json only for user/order/message/notification data.');
}

// ============================================================
// EMAIL (Nodemailer via Gmail) — order-approved notifications only
// ============================================================
let mailTransporter = null;
if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
  mailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD },
  });
} else {
  console.warn('WARNING: GMAIL_USER / GMAIL_APP_PASSWORD not set — order-approved emails will be skipped.');
}

async function sendOrderApprovedEmail(order, user) {
  if (!mailTransporter || !user || !user.email) return;
  try {
    const itemLines = order.items
      .map((it) => `  • ${it.name} x${it.qty} — ${(it.price * it.qty).toLocaleString()} Ks`)
      .join('\n');
    await mailTransporter.sendMail({
      from: `"Neko Shop" <${process.env.GMAIL_USER}>`,
      to: user.email,
      subject: `Your order ${order.order_id} has been approved!`,
      text:
        `Hi${user.name ? ' ' + user.name : ''},\n\n` +
        `Great news — your order has been approved and is being prepared.\n\n` +
        `Order ID: ${order.order_id}\n` +
        `Items:\n${itemLines}\n\n` +
        `Total: ${order.total_amount.toLocaleString()} Ks\n` +
        `Delivery address: ${order.address}\n\n` +
        `Thank you for shopping with Neko Shop!`,
    });
  } catch (err) {
    console.error('Order-approved email failed:', err.message);
  }
}

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(helmet());
app.use(cors());
// Base64 receipt images can be large, so raise the body size limit.
app.use(bodyParser.json({ limit: '15mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '15mb' }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 10 * 60 * 1000 },
  })
);
app.use(passport.initialize());
app.use(passport.session());

// ---- Rate limiting: max 200 requests / 15 min per IP, tighter on auth routes ----
app.use(
  '/api',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests — please slow down and try again shortly.' },
  })
);
app.use(
  ['/api/auth/login', '/api/auth/signup'],
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login/signup attempts — please try again later.' },
  })
);

// ============================================================
// GOOGLE OAUTH (Passport)
// ============================================================
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REDIRECT_URI) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_REDIRECT_URI,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          if (!mongoReady) return done(new Error('Account sign-in requires the database to be connected.'));
          const email = profile.emails && profile.emails[0] && profile.emails[0].value;
          if (!email) return done(new Error('Google account has no email.'));

          let user = await User.findOne({ $or: [{ googleId: profile.id }, { email: email.toLowerCase() }] });
          if (!user) {
            const nextCustomerNumber = (await User.countDocuments({})) + 1;
            user = await User.create({
              email: email.toLowerCase(),
              name: profile.displayName || '',
              googleId: profile.id,
              customer_number: nextCustomerNumber,
            });
            mirrorUserToDataJson(user);
          } else if (!user.googleId) {
            user.googleId = profile.id;
            await user.save();
            mirrorUserToDataJson(user);
          }
          return done(null, user);
        } catch (err) {
          return done(err);
        }
      }
    )
  );
  passport.serializeUser((user, done) => done(null, user._id.toString()));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (err) {
      done(err);
    }
  });
} else {
  console.warn('WARNING: Google OAuth env vars not fully set — /api/auth/google will be unavailable.');
}

// ============================================================
// data.json helpers (Products / Categories / Settings — unchanged —
// PLUS mirrored copies of Users/Orders/Messages/Notifications used only
// as a fallback when MongoDB is unreachable or not yet populated)
// ============================================================
let writeQueue = Promise.resolve();

function readData() {
  const raw = fs.readFileSync(DATA_FILE, 'utf-8');
  const data = JSON.parse(raw);
  if (!Array.isArray(data.notifications)) data.notifications = [];
  if (!Array.isArray(data.messages)) data.messages = [];
  if (!Array.isArray(data.users)) data.users = [];
  if (!Array.isArray(data.orders)) data.orders = [];
  if (!Array.isArray(data.categories)) {
    const fromProducts = [...new Set((data.products || []).map((p) => p.category).filter(Boolean))];
    data.categories = fromProducts.length ? fromProducts : ['figures', 'clothing', 'accessories'];
  }
  (data.products || []).forEach((p) => {
    if (!Array.isArray(p.categories)) {
      p.categories = p.category ? [p.category] : [];
    }
  });
  return data;
}

function writeData(data) {
  writeQueue = writeQueue.then(
    () =>
      new Promise((resolve, reject) => {
        const tmpFile = `${DATA_FILE}.tmp`;
        fs.writeFile(tmpFile, JSON.stringify(data, null, 2), (err) => {
          if (err) return reject(err);
          fs.rename(tmpFile, DATA_FILE, (err2) => {
            if (err2) return reject(err2);
            resolve();
          });
        });
      })
  );
  return writeQueue;
}

// ---- Mirror helpers: best-effort copy of a Mongo write into data.json ----
// These never throw — a mirror failure should never break the real
// (MongoDB) write that already succeeded.
function mirrorUserToDataJson(user) {
  try {
    const data = readData();
    const plain = user.toJSON ? user.toJSON() : user;
    const idx = data.users.findIndex((u) => u.id === plain.id);
    if (idx === -1) data.users.push(plain);
    else data.users[idx] = plain;
    writeData(data).catch((err) => console.error('Mirror (user) write failed:', err.message));
  } catch (err) {
    console.error('Mirror (user) failed:', err.message);
  }
}

function mirrorOrderToDataJson(order) {
  try {
    const data = readData();
    const plain = order.toJSON ? order.toJSON() : order;
    const idx = data.orders.findIndex((o) => o.order_id === plain.order_id);
    if (idx === -1) data.orders.push(plain);
    else data.orders[idx] = plain;
    writeData(data).catch((err) => console.error('Mirror (order) write failed:', err.message));
  } catch (err) {
    console.error('Mirror (order) failed:', err.message);
  }
}

function mirrorMessageToDataJson(message) {
  try {
    const data = readData();
    data.messages.push(message.toJSON ? message.toJSON() : message);
    writeData(data).catch((err) => console.error('Mirror (message) write failed:', err.message));
  } catch (err) {
    console.error('Mirror (message) failed:', err.message);
  }
}

function mirrorNotificationToDataJson(n) {
  try {
    const data = readData();
    data.notifications.push(n.toJSON ? n.toJSON() : n);
    writeData(data).catch((err) => console.error('Mirror (notification) write failed:', err.message));
  } catch (err) {
    console.error('Mirror (notification) failed:', err.message);
  }
}

// ---- Hybrid reads: MongoDB first, data.json fallback ----
async function hybridFindUsers(filterFn) {
  if (mongoReady) {
    try {
      const users = await User.find({});
      if (users.length > 0) return users.map((u) => u.toJSON()).filter(filterFn || (() => true));
    } catch (err) {
      console.error('Mongo read (users) failed, falling back to data.json:', err.message);
    }
  }
  const data = readData();
  return (data.users || []).filter(filterFn || (() => true));
}

async function hybridFindOrders(filterFn) {
  if (mongoReady) {
    try {
      const orders = await Order.find({});
      if (orders.length > 0) return orders.map((o) => o.toJSON()).filter(filterFn || (() => true));
    } catch (err) {
      console.error('Mongo read (orders) failed, falling back to data.json:', err.message);
    }
  }
  const data = readData();
  return (data.orders || []).filter(filterFn || (() => true));
}

// ============================================================
// GENERAL HELPERS
// ============================================================
function nextId(collection) {
  return collection.length ? Math.max(...collection.map((item) => item.id)) + 1 : 1;
}

function nextProductNumber(products) {
  return products.reduce((max, p) => Math.max(max, p.product_number || 0), 0) + 1;
}

// 0->A, 1->B, ... 25->Z, 26->AA, 27->AB, ...
function letterCode(index) {
  let n = index;
  let code = '';
  do {
    code = String.fromCharCode(65 + (n % 26)) + code;
    n = Math.floor(n / 26) - 1;
  } while (n >= 0);
  return code;
}

function buildVariantCodes(sizes, colors) {
  const sizeList = sizes && sizes.length ? sizes : [null];
  const colorList = colors && colors.length ? colors : [null];
  const codes = {};
  let i = 0;
  sizeList.forEach((size) => {
    colorList.forEach((color) => {
      const key = `${size || '-'}|${color || '-'}`;
      codes[key] = letterCode(i);
      i++;
    });
  });
  return codes;
}

function variantLabel(product, size, color) {
  if (!product || !product.variant_codes) return '';
  const key = `${size || '-'}|${color || '-'}`;
  return product.variant_codes[key] || '';
}

function variantPrice(product, size, color) {
  if (!product) return null;
  const key = `${size || '-'}|${color || '-'}`;
  if (product.variant_prices && product.variant_prices[key] !== undefined && product.variant_prices[key] !== null) {
    return Number(product.variant_prices[key]);
  }
  return product.price;
}

function generateOrderId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let suffix = '';
  for (let i = 0; i < 6; i++) suffix += chars[Math.floor(Math.random() * chars.length)];
  return `CID-${suffix}`;
}

// ---------- Input validation (server-side, regardless of frontend checks) ----------
function validateSignupInput({ email, phone, password }) {
  const errors = [];
  if (!email || !validator.isEmail(String(email))) errors.push('Valid email is required.');
  if (phone && !validator.isMobilePhone(String(phone), 'any', { strictMode: false })) errors.push('Invalid phone number.');
  if (!password || String(password).length < 6) errors.push('Password must be at least 6 characters.');
  return errors;
}

function validateOrderInput({ customer_name, phone, address }) {
  const errors = [];
  if (!customer_name || !validator.isLength(String(customer_name).trim(), { min: 2, max: 100 })) errors.push('Valid name is required.');
  if (!phone || !validator.isMobilePhone(String(phone), 'any', { strictMode: false })) errors.push('Valid phone number is required.');
  if (!address || !validator.isLength(String(address).trim(), { min: 5, max: 300 })) errors.push('Valid address is required.');
  return errors;
}

// ---------- Suspicious-content detection (defense in depth) ----------
// Flags obvious SQL/script-injection style payloads in free-text fields.
// Mongoose/parameterized queries already prevent real injection, but the
// business ask here is specifically to detect + log + block this pattern
// of input regardless, and surface it to admin as a "Suspicious Users" list.
const SUSPICIOUS_PATTERNS = [
  { name: 'SQL keyword', re: /\b(SELECT|DROP|DELETE|INSERT|UPDATE)\b/i },
  { name: 'SQL comment/terminator', re: /(--|;)/ },
  { name: "SQL tautology ' OR '1'='1", re: /'\s*OR\s*'?1'?\s*=\s*'?1/i },
  { name: 'script tag', re: /<\s*script/i },
];

function findSuspiciousMatch(value) {
  const str = String(value || '');
  for (const p of SUSPICIOUS_PATTERNS) {
    if (p.re.test(str)) return p.name;
  }
  return null;
}

async function checkSuspiciousFields(fields, req) {
  // fields: { fieldName: value, ... }
  for (const [field, value] of Object.entries(fields)) {
    const match = findSuspiciousMatch(value);
    if (match) {
      if (mongoReady) {
        try {
          await SuspiciousActivity.create({
            ip: req.ip,
            user_id: req.user ? req.user.id : null,
            field,
            matched_pattern: match,
            value_snippet: String(value).slice(0, 120),
          });
        } catch (err) {
          console.error('Logging suspicious activity failed:', err.message);
        }
      }
      return field;
    }
  }
  return null;
}

// ---------- Auth middleware ----------
function authenticateCustomer(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header.' });
  }
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

// Like authenticateCustomer, but never blocks the request — used on routes
// (like placing an order) that must work for guests too.
function optionalAuth(req, res, next) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    try {
      req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    } catch (err) {
      // invalid/expired token — proceed as guest rather than failing checkout
    }
  }
  next();
}

const adminAuth = basicAuth({
  users: { [process.env.ADMIN_USERNAME]: process.env.ADMIN_PASSWORD },
  challenge: true,
  unauthorizedResponse: () => ({ error: 'Unauthorized.' }),
});

function maskPhone(phone) {
  const digits = String(phone || '').replace(/\D/g, '');
  if (digits.length < 7) return phone;
  const head = digits.slice(0, 2);
  const tail = digits.slice(-2);
  return `${head}${'•'.repeat(Math.max(digits.length - 4, 5))}${tail}`;
}

// ============================================================
// RECOMMENDATION ENGINE
// ============================================================
// Every time a customer views a product, bump its score (and its
// category's aggregate score) in their viewHistory. Recently-viewed items
// score higher (simple time-decay), so "what they're into today" wins over
// something they looked at once a month ago.
async function recordProductView(userId, productId, category) {
  if (!userId || !mongoReady) return;
  try {
    const user = await User.findById(userId);
    if (!user) return;
    const existing = user.viewHistory.find((v) => v.productId === productId);
    if (existing) {
      existing.score += 1;
      existing.lastViewedAt = new Date();
    } else {
      user.viewHistory.push({ productId, category, score: 1, lastViewedAt: new Date() });
    }
    // Cap history size so it doesn't grow forever.
    if (user.viewHistory.length > 200) {
      user.viewHistory.sort((a, b) => new Date(b.lastViewedAt) - new Date(a.lastViewedAt));
      user.viewHistory = user.viewHistory.slice(0, 200);
    }
    await user.save();
  } catch (err) {
    console.error('recordProductView failed:', err.message);
  }
}

// Sorts a product list for a given user: favorite categories first (based
// on recent view score, decayed by age), then brand-new products, then
// everything else — falls back to "newest first" for guests/no history.
function personalizeProductOrder(products, viewHistory) {
  const now = Date.now();
  const categoryScore = {};
  (viewHistory || []).forEach((v) => {
    const ageDays = (now - new Date(v.lastViewedAt).getTime()) / 86400000;
    const decayed = v.score * Math.exp(-ageDays / 14); // ~2-week half-life
    if (v.category) categoryScore[v.category] = (categoryScore[v.category] || 0) + decayed;
  });

  const isNew = (p) => (now - new Date(p.created_at || 0).getTime()) / 86400000 < 7;

  return [...products].sort((a, b) => {
    const aCats = a.categories || [a.category];
    const bCats = b.categories || [b.category];
    const aScore = Math.max(0, ...aCats.map((c) => categoryScore[c] || 0));
    const bScore = Math.max(0, ...bCats.map((c) => categoryScore[c] || 0));
    if (aScore !== bScore) return bScore - aScore;
    if (isNew(a) !== isNew(b)) return isNew(a) ? -1 : 1;
    return (b.product_number || 0) - (a.product_number || 0);
  });
}

// ============================================================
// TELEGRAM (3 separate bots: orders / archive / chat)
// ============================================================
async function sendTelegramCard(botToken, chatId, order, { title, footer }) {
  if (!botToken || !chatId) {
    console.warn('Telegram credentials not configured; skipping notification.');
    return;
  }
  const placedAt = new Date(order.created_at).toLocaleString('en-GB', {
    timeZone: 'Asia/Yangon',
    dateStyle: 'medium',
    timeStyle: 'short',
  });
  const itemLines = order.items
    .map((item) => {
      const tag = item.item_id ? `[${item.item_id}${item.letter_code ? `-${item.letter_code}` : ''}] ` : '';
      const variant = [item.size, item.color].filter(Boolean).join('/');
      return `  • ${tag}${item.name}${variant ? ` (${variant})` : ''} x${item.qty} = ${(item.qty * item.price).toLocaleString()} Ks`;
    })
    .join('\n');
  const caption =
    `${title}\n` +
    `━━━━━━━━━━━━━━━━━━━━━━\n` +
    `📦 Order ID: ${order.order_id}\n` +
    `🕒 Placed at: ${placedAt} (MMT)\n` +
    `👤 Name: ${order.customer_name}\n` +
    `📞 Phone: ${order.phone}\n` +
    `📍 Address: ${order.address}\n` +
    `💳 Payment: ${order.payment_method}\n` +
    (order.customer_notes ? `📝 Note: ${order.customer_notes}\n` : '') +
    `────────────────────\n` +
    `🛒 Items:\n${itemLines}\n` +
    `────────────────────\n` +
    `💰 Total: ${order.total_amount.toLocaleString()} Ks\n` +
    (footer ? `${footer}\n` : '');

  try {
    const match = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/.exec(order.receipt_image || '');
    if (match) {
      const buffer = Buffer.from(match[2], 'base64');
      const form = new FormData();
      form.append('chat_id', chatId);
      form.append('caption', caption.slice(0, 1024));
      form.append('photo', buffer, { filename: `${order.order_id}.jpg` });
      await axios.post(`https://api.telegram.org/bot${botToken}/sendPhoto`, form, { headers: form.getHeaders() });
    } else {
      await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, { chat_id: chatId, text: caption });
    }
  } catch (err) {
    console.error('Telegram notification failed:', err.response?.data || err.message);
  }
}

function sendTelegramOrderNotification(order) {
  return sendTelegramCard(process.env.ORDER_BOT_TOKEN, process.env.ADMIN_CHAT_ID, order, {
    title: '🆕 New Order Arrived!',
    footer: '💬 Please approve via Admin Dashboard.',
  });
}

function sendTelegramArchiveNotification(order) {
  return sendTelegramCard(process.env.ARCHIVE_BOT_TOKEN, process.env.ADMIN_CHAT_ID, order, {
    title: '🗄️ Archived Order (removed from database)',
    footer: `📌 Final status: ${order.status}`,
  });
}

async function sendTelegramChatNotification(text, user) {
  const token = process.env.CHAT_BOT_TOKEN;
  const chatId = process.env.ADMIN_CHAT_ID;
  if (!token || !chatId) return;
  const label = user ? `${user.email} (Customer #${user.customer_number || user.id})` : 'Unknown customer';
  try {
    await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
      chat_id: chatId,
      text: `💬 New message from ${label}:\n"${text}"`,
    });
  } catch (err) {
    console.error('Telegram chat notify failed:', err.response?.data || err.message);
  }
}

// ============================================================
// AUTO-ARCHIVE OLD ORDERS (MongoDB-first, mirrors the deletion to data.json)
// ============================================================
const GLOBAL_ORDER_LIMIT = 10;
const CUSTOMER_ORDER_LIMIT = 7;
const ARCHIVABLE_STATUSES = ['approved', 'shipped', 'cancelled'];
const byOldestFirst = (a, b) => new Date(a.created_at) - new Date(b.created_at);

async function archiveOrdersIfNeeded() {
  try {
    const allOrders = await hybridFindOrders((o) => ARCHIVABLE_STATUSES.includes(o.status));
    const toArchiveMap = new Map();

    if (allOrders.length > GLOBAL_ORDER_LIMIT) {
      const excess = allOrders.length - GLOBAL_ORDER_LIMIT;
      [...allOrders].sort(byOldestFirst).slice(0, excess).forEach((o) => toArchiveMap.set(o.order_id, o));
    }

    const byUser = {};
    allOrders.forEach((o) => {
      if (!o.user_id) return;
      (byUser[o.user_id] = byUser[o.user_id] || []).push(o);
    });
    Object.values(byUser).forEach((userOrders) => {
      if (userOrders.length > CUSTOMER_ORDER_LIMIT) {
        const excess = userOrders.length - CUSTOMER_ORDER_LIMIT;
        [...userOrders].sort(byOldestFirst).slice(0, excess).forEach((o) => toArchiveMap.set(o.order_id, o));
      }
    });

    const toArchive = [...toArchiveMap.values()];
    if (toArchive.length === 0) return;

    for (const order of toArchive) {
      await sendTelegramArchiveNotification(order);
    }

    const ids = toArchive.map((o) => o.order_id);
    if (mongoReady) {
      try {
        await Order.deleteMany({ order_id: { $in: ids } });
      } catch (err) {
        console.error('Mongo archive delete failed:', err.message);
      }
    }
    const data = readData();
    data.orders = data.orders.filter((o) => !ids.includes(o.order_id));
    await writeData(data);
  } catch (err) {
    console.error('Order archival failed:', err);
  }
}

// Notification cap: keep at most 20 per customer.
const NOTIFICATION_LIMIT_PER_USER = 20;
async function trimNotifications(userId) {
  if (!mongoReady) return;
  try {
    const mine = await Notification.find({ user_id: userId }).sort({ created_at: 1 });
    if (mine.length > NOTIFICATION_LIMIT_PER_USER) {
      const excess = mine.slice(0, mine.length - NOTIFICATION_LIMIT_PER_USER);
      await Notification.deleteMany({ _id: { $in: excess.map((n) => n._id) } });
    }
  } catch (err) {
    console.error('trimNotifications failed:', err.message);
  }
}

const ORDER_STATUS_MESSAGES = {
  approved: (id) => `✅ သင့်အော်ဒါ ${id} ကို admin က လက်ခံလိုက်ပါပြီ။`,
  shipped: (id) => `🚚 သင့်အော်ဒါ ${id} ကို ပို့ဆောင်နေပါပြီ။`,
  cancelled: (id) => `❌ သင့်အော်ဒါ ${id} ကို ပယ်ချလိုက်ပါသည်။`,
};

async function pushNotification(userId, orderId, status) {
  const build = ORDER_STATUS_MESSAGES[status];
  if (!userId || !build) return;
  const message = build(orderId);
  if (mongoReady) {
    try {
      const n = await Notification.create({ user_id: userId, order_id: orderId, status, message });
      mirrorNotificationToDataJson(n);
      await trimNotifications(userId);
      return;
    } catch (err) {
      console.error('pushNotification (Mongo) failed, falling back to data.json:', err.message);
    }
  }
  const data = readData();
  data.notifications.push({
    id: `N-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    user_id: userId,
    order_id: orderId,
    status,
    message,
    created_at: new Date().toISOString(),
    read: false,
  });
  await writeData(data);
}

// Chat message retention: delete anything older than 30 days.
const MESSAGE_RETENTION_DAYS = 30;
async function cleanupOldMessages() {
  const cutoff = new Date(Date.now() - MESSAGE_RETENTION_DAYS * 24 * 60 * 60 * 1000);
  if (mongoReady) {
    try {
      await Message.deleteMany({ created_at: { $lt: cutoff } });
    } catch (err) {
      console.error('cleanupOldMessages (Mongo) failed:', err.message);
    }
  }
  try {
    const data = readData();
    const before = data.messages.length;
    data.messages = data.messages.filter((m) => new Date(m.created_at) >= cutoff);
    if (data.messages.length !== before) await writeData(data);
  } catch (err) {
    console.error('cleanupOldMessages (data.json) failed:', err.message);
  }
}

// ============================================================
// PUBLIC ROUTES
// ============================================================

// Products are still stored in data.json. If the request is from a logged-in
// customer, personalize the order based on their view history (MongoDB).
app.get('/api/products', optionalAuth, async (req, res) => {
  const data = readData();
  let products = data.products;
  if (req.user && mongoReady) {
    try {
      const user = await User.findById(req.user.id);
      if (user) products = personalizeProductOrder(products, user.viewHistory);
    } catch (err) {
      console.error('Personalization failed, showing default order:', err.message);
    }
  }
  res.json(products);
});

// Track a product view for the recommendation engine. Fire-and-forget from
// the frontend — logged-in customers only (guests have no history to build).
app.post('/api/products/:id/view', optionalAuth, async (req, res) => {
  if (!req.user) return res.json({ tracked: false });
  const data = readData();
  const product = data.products.find((p) => p.id === Number(req.params.id));
  if (!product) return res.status(404).json({ error: 'Product not found.' });
  recordProductView(req.user.id, product.id, (product.categories && product.categories[0]) || product.category)
    .catch((err) => console.error('recordProductView error:', err.message));
  res.json({ tracked: true });
});

app.get('/api/categories', (req, res) => {
  const data = readData();
  res.json(data.categories);
});

app.get('/api/settings', (req, res) => {
  const data = readData();
  const { kbz, aya, wave } = data.settings || {};
  res.json({ kbz, aya, wave });
});

// ============================================================
// AUTH (Email OTP) - Gmail 3 Round-Robin
// ============================================================

// Gmail 3 ခု အလှည့်ကျသုံးရန် Setup
const otpGmailAccounts = [
    { email: process.env.GMAIL_1_EMAIL, pass: process.env.GMAIL_1_APP_PASSWORD },
    { email: process.env.GMAIL_2_EMAIL, pass: process.env.GMAIL_2_APP_PASSWORD },
    { email: process.env.GMAIL_3_EMAIL, pass: process.env.GMAIL_3_APP_PASSWORD }
];
let currentGmailIndex = 0;

function getNextGmail() {
    const account = otpGmailAccounts[currentGmailIndex];
    currentGmailIndex = (currentGmailIndex + 1) % otpGmailAccounts.length;
    return account;
}

// OTP Schema (MongoDB) — models/OTP.js မလိုအောင် server.js ထဲမှာပဲ ရေးထားပါတယ်
const otpSchema = new mongoose.Schema({
    email: { type: String, required: true, index: true },
    otp: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 300 } // 5 minutes TTL
});
const OTP = mongoose.model('OTP', otpSchema);

async function sendOTPEmail(email, otp) {
    const account = getNextGmail();
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: account.email, pass: account.pass }
    });
    await transporter.sendMail({
        from: `"Neko Shop" <${account.email}>`,
        to: email,
        subject: 'Neko Shop - OTP Code',
        text: `သင့်ရဲ့ OTP ကုဒ်ကတော့ ${otp} ဖြစ်ပါတယ်။ (သက်တမ်း ၅ မိနစ်)`
    });
}

// OTP ပို့ရန် (Send)
app.post('/api/auth/email-otp/send', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !validator.isEmail(email)) {
            return res.status(400).json({ error: 'Valid Gmail is required.' });
        }
        if (!mongoReady) return res.status(503).json({ error: 'System unavailable.' });

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        await OTP.findOneAndDelete({ email });
        await OTP.create({ email, otp });
        
        try {
            await sendOTPEmail(email, otp);
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ error: 'Email sending failed. Please try again.' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Failed to send OTP.' });
    }
});

// OTP ပြန်ပို့ရန် (Resend)
app.post('/api/auth/email-otp/resend', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !validator.isEmail(email)) {
            return res.status(400).json({ error: 'Valid Gmail is required.' });
        }
        await OTP.findOneAndDelete({ email });
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        await OTP.create({ email, otp });
        
        try {
            await sendOTPEmail(email, otp);
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ error: 'Resend failed. Please try again.' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Failed to resend OTP.' });
    }
});

// OTP အတည်ပြုရန် (Verify)
app.post('/api/auth/email-otp/verify', async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required.' });
        if (!mongoReady) return res.status(503).json({ error: 'System unavailable.' });

        const record = await OTP.findOne({ email });
        if (!record) return res.status(400).json({ error: 'OTP သက်တမ်းကုန်သွားပါပြီ။ ပြန်ပို့ပါ။' });
        if (record.otp !== String(otp)) return res.status(400).json({ error: 'OTP မှားယွင်းနေပါသည်။' });

        await OTP.findOneAndDelete({ email });

        // User ရှိမရှိ စစ်၊ မရှိရင် အသစ်ဆောက်
        let user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            const nextCustomerNumber = (await User.countDocuments({})) + 1;
            user = await User.create({
                email: email.toLowerCase(),
                phone: '',
                name: '',
                customer_number: nextCustomerNumber,
            });
        }

        const token = jwt.sign({ id: user._id.toString(), email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: user.toJSON() });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to verify OTP.' });
    }
});

// ============================================================
// ORDERS
// ============================================================
app.post('/api/orders', optionalAuth, async (req, res) => {
  try {
    const { customer_name, phone, address, customer_notes, payment_method, items, receipt_image } = req.body;
    const errors = validateOrderInput({ customer_name, phone, address });
    if (!payment_method || !Array.isArray(items) || items.length === 0) errors.push('payment_method and items are required.');
    if (errors.length) return res.status(400).json({ error: errors.join(' ') });

    const suspiciousField = await checkSuspiciousFields({ customer_name, address, customer_notes, phone }, req);
    if (suspiciousField) {
      return res.status(400).json({ error: 'သင့်ရဲ့ အချက်အလက်ထဲမှာ ခွင့်မပြုထားသော စာလုံးများ ပါဝင်နေပါတယ်။ ပြန်စစ်ပေးပါ။' });
    }

    const data = readData();

    // Stock check — products with stock === null/undefined are treated as untracked.
    for (const item of items) {
      const product = data.products.find((p) => p.id === item.productId);
      if (product && product.stock !== null && product.stock !== undefined && product.stock < Number(item.qty)) {
        return res.status(400).json({ error: `"${product.name}" ပစ္စည်းကုန်သွားပါပြီ (လက်ကျန် ${product.stock} ခုပဲ ရှိပါတော့တယ်)။` });
      }
    }

    const total_amount = items.reduce((sum, item) => sum + Number(item.price) * Number(item.qty), 0);
    const enrichedItems = items.map((item) => {
      const product = data.products.find((p) => p.id === item.productId);
      return {
        ...item,
        product_number: product ? product.product_number : null,
        item_id: product ? product.item_id : null,
        letter_code: product ? product.letter_code : null,
        variant_code: variantLabel(product, item.size, item.color),
      };
    });

    const orderPayload = {
      order_id: generateOrderId(),
      user_id: req.user ? req.user.id : null,
      customer_name,
      phone,
      address,
      payment_method,
      customer_notes: customer_notes || '',
      items: enrichedItems,
      total_amount,
      receipt_image: receipt_image || null,
      status: 'pending',
      created_at: new Date(),
    };

    let savedOrder = orderPayload;
    if (mongoReady) {
      try {
        const order = await Order.create(orderPayload);
        mirrorOrderToDataJson(order);
        savedOrder = order.toJSON();
      } catch (err) {
        console.error('Order create (Mongo) failed, saving to data.json only:', err.message);
        data.orders.push({ ...orderPayload, created_at: orderPayload.created_at.toISOString() });
        await writeData(data);
      }
    } else {
      data.orders.push({ ...orderPayload, created_at: orderPayload.created_at.toISOString() });
      await writeData(data);
    }

    // Decrement stock now that the order is accepted.
    items.forEach((item) => {
      const product = data.products.find((p) => p.id === item.productId);
      if (product && product.stock !== null && product.stock !== undefined) {
        product.stock = Math.max(0, product.stock - Number(item.qty));
      }
    });
    await writeData(data);

    sendTelegramOrderNotification(savedOrder);

    res.status(201).json({ order: savedOrder });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to place order.' });
  }
});

app.get('/api/orders/mine', authenticateCustomer, async (req, res) => {
  const mine = await hybridFindOrders((o) => String(o.user_id) === String(req.user.id));
  mine.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(mine);
});

// ============================================================
// CHAT (customer <-> admin)
// ============================================================
app.get('/api/messages/mine', authenticateCustomer, async (req, res) => {
  if (mongoReady) {
    try {
      const mine = await Message.find({ user_id: req.user.id }).sort({ created_at: 1 });
      return res.json(mine.map((m) => m.toJSON()));
    } catch (err) {
      console.error('Messages read (Mongo) failed, falling back:', err.message);
    }
  }
  const data = readData();
  res.json(data.messages.filter((m) => String(m.user_id) === String(req.user.id)).sort((a, b) => new Date(a.created_at) - new Date(b.created_at)));
});

app.post('/api/messages', authenticateCustomer, async (req, res) => {
  try {
    const text = (req.body.text || '').trim();
    if (!text) return res.status(400).json({ error: 'Message text is required.' });

    let message = { user_id: req.user.id, sender: 'customer', text, created_at: new Date().toISOString() };
    let user = null;
    if (mongoReady) {
      try {
        const doc = await Message.create({ user_id: req.user.id, sender: 'customer', text });
        mirrorMessageToDataJson(doc);
        message = doc.toJSON();
        user = await User.findById(req.user.id);
      } catch (err) {
        console.error('Message create (Mongo) failed, saving to data.json only:', err.message);
        const data = readData();
        data.messages.push({ id: `MSG-${Date.now()}`, ...message });
        await writeData(data);
      }
    } else {
      const data = readData();
      data.messages.push({ id: `MSG-${Date.now()}`, ...message });
      await writeData(data);
    }

    sendTelegramChatNotification(text, user).catch(() => {});
    res.status(201).json({ message });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send message.' });
  }
});

// ============================================================
// NOTIFICATIONS
// ============================================================
app.get('/api/notifications/mine', authenticateCustomer, async (req, res) => {
  if (mongoReady) {
    try {
      const mine = await Notification.find({ user_id: req.user.id }).sort({ created_at: -1 });
      return res.json(mine.map((n) => n.toJSON()));
    } catch (err) {
      console.error('Notifications read (Mongo) failed, falling back:', err.message);
    }
  }
  const data = readData();
  res.json(data.notifications.filter((n) => String(n.user_id) === String(req.user.id)).sort((a, b) => new Date(b.created_at) - new Date(a.created_at)));
});

// ============================================================
// ADMIN — CATEGORIES (unchanged, still data.json)
// ============================================================
app.post('/api/admin/categories', adminAuth, async (req, res) => {
  try {
    const name = (req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: 'Category name is required.' });
    const data = readData();
    if (data.categories.some((c) => c.toLowerCase() === name.toLowerCase())) {
      return res.status(400).json({ error: 'That category already exists.' });
    }
    data.categories.push(name);
    await writeData(data);
    res.status(201).json({ categories: data.categories });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add category.' });
  }
});

app.put('/api/admin/categories/:name', adminAuth, async (req, res) => {
  try {
    const oldName = req.params.name;
    const newName = (req.body.name || '').trim();
    if (!newName) return res.status(400).json({ error: 'New category name is required.' });
    const data = readData();
    const idx = data.categories.findIndex((c) => c === oldName);
    if (idx === -1) return res.status(404).json({ error: 'Category not found.' });
    data.categories[idx] = newName;
    data.products.forEach((p) => {
      if (p.category === oldName) p.category = newName;
      if (Array.isArray(p.categories)) {
        p.categories = p.categories.map((c) => (c === oldName ? newName : c));
      }
    });
    await writeData(data);
    res.json({ categories: data.categories });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to rename category.' });
  }
});

app.delete('/api/admin/categories/:name', adminAuth, async (req, res) => {
  try {
    const data = readData();
    const name = req.params.name;
    if (data.products.some((p) => (p.categories || [p.category]).includes(name))) {
      return res.status(400).json({ error: 'ဒီ category ကို သုံးနေတဲ့ ပစ္စည်းများ ရှိနေပါသေးတယ် — အရင်ပြောင်းပါ။' });
    }
    data.categories = data.categories.filter((c) => c !== name);
    await writeData(data);
    res.json({ categories: data.categories });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete category.' });
  }
});

// ============================================================
// ADMIN — PRODUCTS (unchanged, still data.json)
// ============================================================
app.post('/api/admin/products', adminAuth, async (req, res) => {
  try {
    const { name, price, oldPrice, category, categories, image, images, variant_images, video, desc, sizes, colors, stock, payment_type, estimated_delivery, variant_prices } = req.body;
    const finalCategories = Array.isArray(categories) && categories.length ? categories : (category ? [category] : []);
    if (!name || !price || finalCategories.length === 0) {
      return res.status(400).json({ error: 'name, price, and at least one category are required.' });
    }
    const data = readData();
    const finalSizes = Array.isArray(sizes) ? sizes : [];
    const finalColors = Array.isArray(colors) ? colors : [];
    const finalVariantPrices = variant_prices && typeof variant_prices === 'object' ? variant_prices : {};
    const variantPriceValues = Object.values(finalVariantPrices).map(Number).filter((n) => !isNaN(n));
    const productNumber = nextProductNumber(data.products);
    const product = {
      id: nextId(data.products),
      product_number: productNumber,
      item_id: `ITM-${String(productNumber).padStart(3, '0')}`,
      letter_code: letterCode(productNumber - 1),
      name,
      price: variantPriceValues.length ? Math.min(...variantPriceValues) : Number(price),
      oldPrice: oldPrice ? Number(oldPrice) : null,
      categories: finalCategories,
      category: finalCategories[0],
      image: image || 'https://picsum.photos/400/400',
      images: images && typeof images === 'object' ? images : {},
      variant_images: variant_images && typeof variant_images === 'object' ? variant_images : {},
      video: video || '',
      desc: desc || '',
      sizes: finalSizes,
      colors: finalColors,
      variant_codes: buildVariantCodes(finalSizes, finalColors),
      variant_prices: finalVariantPrices,
      stock: stock !== undefined && stock !== '' ? Number(stock) : null,
      payment_type: payment_type === 'cod' ? 'cod' : 'prepay',
      estimated_delivery: estimated_delivery || '',
      created_at: new Date().toISOString(),
    };
    data.products.push(product);
    await writeData(data);
    res.status(201).json({ product });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add product.' });
  }
});

app.put('/api/admin/products/:id', adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { name, price, oldPrice, category, categories, image, images, variant_images, video, desc, sizes, colors, stock, payment_type, estimated_delivery, variant_prices } = req.body;

    const data = readData();
    const product = data.products.find((p) => p.id === id);
    if (!product) return res.status(404).json({ error: 'Product not found.' });

    if (name !== undefined) product.name = name;
    if (price !== undefined) product.price = Number(price);
    if (oldPrice !== undefined) product.oldPrice = oldPrice ? Number(oldPrice) : null;
    if (categories !== undefined) {
      product.categories = Array.isArray(categories) ? categories : [];
      product.category = product.categories[0] || '';
    } else if (category !== undefined) {
      product.categories = [category];
      product.category = category;
    }
    if (image !== undefined) product.image = image;
    if (images !== undefined) product.images = images && typeof images === 'object' ? images : {};
    if (variant_images !== undefined) product.variant_images = variant_images && typeof variant_images === 'object' ? variant_images : {};
    if (video !== undefined) product.video = video;
    if (desc !== undefined) product.desc = desc;
    if (sizes !== undefined) product.sizes = Array.isArray(sizes) ? sizes : [];
    if (colors !== undefined) product.colors = Array.isArray(colors) ? colors : [];
    if (sizes !== undefined || colors !== undefined) {
      product.variant_codes = buildVariantCodes(product.sizes, product.colors);
    }
    if (variant_prices !== undefined) {
      product.variant_prices = variant_prices && typeof variant_prices === 'object' ? variant_prices : {};
      const values = Object.values(product.variant_prices).map(Number).filter((n) => !isNaN(n));
      if (values.length) product.price = Math.min(...values);
    }
    if (stock !== undefined) product.stock = stock !== '' ? Number(stock) : null;
    if (payment_type !== undefined) product.payment_type = payment_type === 'cod' ? 'cod' : 'prepay';
    if (estimated_delivery !== undefined) product.estimated_delivery = estimated_delivery;

    await writeData(data);
    res.json({ product });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update product.' });
  }
});

app.delete('/api/admin/products/:id', adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const data = readData();
    const index = data.products.findIndex((p) => p.id === id);
    if (index === -1) return res.status(404).json({ error: 'Product not found.' });
    data.products.splice(index, 1);
    await writeData(data);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete product.' });
  }
});

// ============================================================
// ADMIN — SETTINGS (unchanged, still data.json)
// ============================================================
app.get('/api/admin/settings', adminAuth, (req, res) => {
  const data = readData();
  res.json(data.settings || {});
});

app.post('/api/admin/settings', adminAuth, async (req, res) => {
  try {
    const { kbz, aya, wave } = req.body;
    const data = readData();
    data.settings = {
      ...data.settings,
      ...(kbz !== undefined ? { kbz } : {}),
      ...(aya !== undefined ? { aya } : {}),
      ...(wave !== undefined ? { wave } : {}),
    };
    await writeData(data);
    res.json({ settings: data.settings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update settings.' });
  }
});

// ============================================================
// ADMIN — ORDERS
// ============================================================
app.get('/api/admin/orders', adminAuth, async (req, res) => {
  const orders = await hybridFindOrders();
  orders.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(orders);
});

app.put('/api/admin/orders/:orderId', adminAuth, async (req, res) => {
  try {
    const { status } = req.body;
    const allowed = ['pending', 'approved', 'shipped', 'cancelled'];
    if (!allowed.includes(status)) {
      return res.status(400).json({ error: `status must be one of: ${allowed.join(', ')}` });
    }

    const data = readData();
    let order = null;
    let mongoOrderDoc = null;

    if (mongoReady) {
      try {
        mongoOrderDoc = await Order.findOne({ order_id: req.params.orderId });
      } catch (err) {
        console.error('Mongo order lookup failed:', err.message);
      }
    }
    if (mongoOrderDoc) order = mongoOrderDoc.toJSON();
    else order = data.orders.find((o) => o.order_id === req.params.orderId);

    if (!order) return res.status(404).json({ error: 'Order not found.' });

    const previousStatus = order.status;

    // Restore stock if newly cancelled.
    if (status === 'cancelled' && previousStatus !== 'cancelled') {
      order.items.forEach((item) => {
        const product = data.products.find((p) => p.id === item.productId);
        if (product && product.stock !== null && product.stock !== undefined) {
          product.stock += Number(item.qty);
        }
      });
      await writeData(data);
    }

    // Persist the status change.
    if (mongoOrderDoc) {
      mongoOrderDoc.status = status;
      await mongoOrderDoc.save();
      mirrorOrderToDataJson(mongoOrderDoc);
      order = mongoOrderDoc.toJSON();
    } else {
      const idx = data.orders.findIndex((o) => o.order_id === req.params.orderId);
      if (idx !== -1) {
        data.orders[idx].status = status;
        await writeData(data);
        order = data.orders[idx];
      }
    }

    // Notify the customer only when the status actually changes.
    if (status !== previousStatus && order.user_id) {
      pushNotification(order.user_id, order.order_id, status).catch((err) => console.error(err));

      // Email only on approval, per spec.
      if (status === 'approved' && mongoReady) {
        try {
          const user = await User.findById(order.user_id);
          sendOrderApprovedEmail(order, user).catch((err) => console.error(err));
        } catch (err) {
          console.error('Lookup user for approval email failed:', err.message);
        }
      }
    }

    archiveOrdersIfNeeded();

    res.json({ order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update order.' });
  }
});

// ============================================================
// ADMIN — USERS / BAN / APPEALS
// ============================================================
app.get('/api/admin/users', adminAuth, async (req, res) => {
  const users = await hybridFindUsers();
  const orders = await hybridFindOrders();
  const withCounts = users.map((u) => ({
    ...u,
    order_count: orders.filter((o) => String(o.user_id) === String(u.id)).length,
  }));
  withCounts.sort((a, b) => (b.customer_number || 0) - (a.customer_number || 0));
  res.json(withCounts);
});

app.put('/api/admin/users/:id/password', adminAuth, async (req, res) => {
  try {
    const newPassword = (req.body.new_password || '').trim();
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    if (!mongoReady) return res.status(503).json({ error: 'Database unavailable.' });
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    mirrorUserToDataJson(user);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to reset password.' });
  }
});

// Ban a user, with a required reason. Auto-expires (unbans) after 30 days
// via the BanRecord TTL index regardless of whether an appeal happens.
app.post('/api/admin/users/:id/ban', adminAuth, async (req, res) => {
  try {
    const reason = (req.body.reason || '').trim();
    if (!reason) return res.status(400).json({ error: 'A ban reason is required.' });
    if (!mongoReady) return res.status(503).json({ error: 'Database unavailable.' });

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    user.isBlocked = true;
    await user.save();
    mirrorUserToDataJson(user);

    const ban = await BanRecord.create({ user_id: user._id, reason });
    res.status(201).json({ ban: ban.toJSON() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to ban user.' });
  }
});

app.post('/api/admin/users/:id/unban', adminAuth, async (req, res) => {
  try {
    if (!mongoReady) return res.status(503).json({ error: 'Database unavailable.' });
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    user.isBlocked = false;
    await user.save();
    mirrorUserToDataJson(user);
    await BanRecord.updateMany({ user_id: user._id, status: { $ne: 'lifted' } }, { status: 'lifted' });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to unban user.' });
  }
});

// "Suspicious Users" admin page data.
app.get('/api/admin/suspicious-activity', adminAuth, async (req, res) => {
  if (!mongoReady) return res.json([]);
  try {
    const activity = await SuspiciousActivity.find({}).sort({ created_at: -1 }).limit(200).populate('user_id', 'email customer_number');
    res.json(activity.map((a) => a.toJSON()));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load suspicious activity.' });
  }
});

// Customer-facing: submit an appeal against their own ban.
app.post('/api/appeals', authenticateCustomer, async (req, res) => {
  try {
    const message = (req.body.message || '').trim();
    if (!message) return res.status(400).json({ error: 'Please describe why your account should be unbanned.' });
    if (!mongoReady) return res.status(503).json({ error: 'Database unavailable.' });

    const activeBan = await BanRecord.findOne({ user_id: req.user.id, status: { $in: ['active', 'appealed'] } }).sort({ created_at: -1 });
    if (!activeBan) return res.status(400).json({ error: 'No active ban found on your account.' });

    const appeal = await Appeal.create({ user_id: req.user.id, ban_id: activeBan._id, message });
    activeBan.status = 'appealed';
    await activeBan.save();
    res.status(201).json({ appeal: appeal.toJSON() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to submit appeal.' });
  }
});

app.get('/api/admin/appeals', adminAuth, async (req, res) => {
  if (!mongoReady) return res.json([]);
  try {
    const appeals = await Appeal.find({ status: 'pending' }).sort({ created_at: -1 }).populate('user_id', 'email customer_number');
    res.json(appeals.map((a) => a.toJSON()));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load appeals.' });
  }
});

app.post('/api/admin/appeals/:id/approve', adminAuth, async (req, res) => {
  try {
    if (!mongoReady) return res.status(503).json({ error: 'Database unavailable.' });
    const appeal = await Appeal.findById(req.params.id);
    if (!appeal) return res.status(404).json({ error: 'Appeal not found.' });
    appeal.status = 'approved';
    await appeal.save();

    const user = await User.findById(appeal.user_id);
    if (user) {
      user.isBlocked = false;
      await user.save();
      mirrorUserToDataJson(user);
    }
    await BanRecord.findByIdAndUpdate(appeal.ban_id, { status: 'lifted' });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to approve appeal.' });
  }
});

app.post('/api/admin/appeals/:id/reject', adminAuth, async (req, res) => {
  try {
    if (!mongoReady) return res.status(503).json({ error: 'Database unavailable.' });
    await Appeal.findByIdAndUpdate(req.params.id, { status: 'rejected' });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to reject appeal.' });
  }
});

// ============================================================
// ADMIN — MESSAGES
// ============================================================
app.get('/api/admin/conversations', adminAuth, async (req, res) => {
  if (!mongoReady) return res.json([]);
  try {
    const messages = await Message.find({}).sort({ created_at: -1 });
    const byUser = {};
    messages.forEach((m) => {
      const key = String(m.user_id);
      (byUser[key] = byUser[key] || []).push(m);
    });
    const conversations = await Promise.all(
      Object.entries(byUser).map(async ([userId, msgs]) => {
        const user = await User.findById(userId).catch(() => null);
        return {
          user_id: userId,
          customer_number: user?.customer_number || null,
          email: user?.email || 'Unknown',
          last_message: msgs[0]?.text || '',
          last_message_at: msgs[0]?.created_at || null,
          unread: msgs.filter((m) => m.sender === 'customer' && !m.read_by_admin).length,
        };
      })
    );
    conversations.sort((a, b) => new Date(b.last_message_at) - new Date(a.last_message_at));
    res.json(conversations);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load conversations.' });
  }
});

app.get('/api/admin/messages/:userId', adminAuth, async (req, res) => {
  if (!mongoReady) return res.json([]);
  try {
    const thread = await Message.find({ user_id: req.params.userId }).sort({ created_at: 1 });
    await Message.updateMany({ user_id: req.params.userId, sender: 'customer', read_by_admin: false }, { read_by_admin: true });
    res.json(thread.map((m) => m.toJSON()));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load messages.' });
  }
});

app.post('/api/admin/messages/:userId', adminAuth, async (req, res) => {
  try {
    const text = (req.body.text || '').trim();
    if (!text) return res.status(400).json({ error: 'Message text is required.' });
    if (!mongoReady) return res.status(503).json({ error: 'Database unavailable.' });
    const message = await Message.create({ user_id: req.params.userId, sender: 'admin', text });
    mirrorMessageToDataJson(message);
    res.status(201).json({ message: message.toJSON() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send message.' });
  }
});

// ============================================================
// ADMIN — INSIGHTS
// ============================================================
app.get('/api/admin/insights', adminAuth, async (req, res) => {
  try {
    const orders = await hybridFindOrders((o) => o.status !== 'cancelled');
    const data = readData();
    const allUsers = await hybridFindUsers();
    const totalCustomers = allUsers.length;

    const salesByProduct = {};
    orders.forEach((o) => {
      o.items.forEach((item) => {
        const key = item.productId;
        salesByProduct[key] = salesByProduct[key] || { productId: key, name: item.name, qty: 0, revenue: 0 };
        salesByProduct[key].qty += Number(item.qty);
        salesByProduct[key].revenue += Number(item.qty) * Number(item.price);
      });
    });
    const topSelling = Object.values(salesByProduct).sort((a, b) => b.qty - a.qty).slice(0, 10);

    let mostViewed = [];
    if (mongoReady) {
      try {
        const users = await User.find({}, 'viewHistory');
        const viewsByProduct = {};
        users.forEach((u) => {
          u.viewHistory.forEach((v) => {
            viewsByProduct[v.productId] = (viewsByProduct[v.productId] || 0) + v.score;
          });
        });
        mostViewed = Object.entries(viewsByProduct)
          .map(([productId, score]) => {
            const product = data.products.find((p) => p.id === Number(productId));
            return { productId: Number(productId), name: product ? product.name : 'Unknown', score };
          })
          .sort((a, b) => b.score - a.score)
          .slice(0, 10);
      } catch (err) {
        console.error('Insights (most-viewed) failed:', err.message);
      }
    }

    res.json({ topSelling, mostViewed, totalCustomers });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load insights.' });
  }
});

// ---------- Fallback ----------
app.use((req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// Periodic jobs
cleanupOldMessages();
setInterval(cleanupOldMessages, 24 * 60 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`Neko Shop backend running on port ${PORT}`);
});
