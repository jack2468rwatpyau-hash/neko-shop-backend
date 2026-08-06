// ============================================================
// NEKO SHOP BACKEND — data.json only (no MongoDB)
// All original features preserved (orders, chat, reviews, admin, trending, music, banners, etc.)
// ============================================================
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const basicAuth = require('express-basic-auth');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const FormData = require('form-data');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATA_FILE = path.join(__dirname, 'data.json');

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set. Add it to your .env file.');
  process.exit(1);
}

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '15mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '15mb' }));

app.use(
  '/api',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests — please slow down.' },
  })
);
app.use(
  ['/api/auth/login', '/api/auth/signup'],
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login/signup attempts — try again later.' },
  })
);

// ============================================================
// data.json HELPERS
// ============================================================
let writeQueue = Promise.resolve();

function readData() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf-8');
    const data = JSON.parse(raw);
    if (!Array.isArray(data.users)) data.users = [];
    if (!Array.isArray(data.orders)) data.orders = [];
    if (!Array.isArray(data.messages)) data.messages = [];
    if (!Array.isArray(data.notifications)) data.notifications = [];
    if (!Array.isArray(data.products)) data.products = [];
    if (!Array.isArray(data.categories)) data.categories = [];
    if (!Array.isArray(data.banners)) data.banners = [];
    if (!Array.isArray(data.songs)) data.songs = [];
    if (!Array.isArray(data.reviews)) data.reviews = [];
    if (!data.settings) data.settings = {};
    return data;
  } catch (err) {
    return {
      users: [],
      orders: [],
      messages: [],
      notifications: [],
      products: [],
      categories: [],
      banners: [],
      songs: [],
      reviews: [],
      settings: {},
    };
  }
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

// ============================================================
// HELPERS
// ============================================================
function nextId(arr) {
  if (!arr || !arr.length) return 1;
  return Math.max(...arr.map((item) => Number(item.id) || 0)) + 1;
}

function generateOrderId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let suffix = '';
  for (let i = 0; i < 6; i++) suffix += chars[Math.floor(Math.random() * chars.length)];
  return `CID-${suffix}`;
}

function formatKs(n) {
  return `${Number(n || 0).toLocaleString()} Ks`;
}

function timeAgo(iso) {
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function buildVariantCodes(sizes, colors) {
  const sizeList = sizes && sizes.length ? sizes : [null];
  const colorList = colors && colors.length ? colors : [null];
  const codes = {};
  let i = 0;
  sizeList.forEach((size) => {
    colorList.forEach((color) => {
      const key = `${size || '-'}|${color || '-'}`;
      codes[key] = String.fromCharCode(65 + i);
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

// ============================================================
// 🔥 NEW: INACTIVE USER CLEANUP (ရက် ၂၀ ပစ္စည်းမကြည့်ရင် ဖျက်မယ်)
// ============================================================
const INACTIVE_DAYS = 20;

async function cleanupInactiveUsers() {
  try {
    const data = readData();
    const now = Date.now();
    const cutoff = now - INACTIVE_DAYS * 24 * 60 * 60 * 1000;

    // ဖျက်မယ့် users တွေကို စစ်ပါ
    const toDelete = data.users.filter((user) => {
      // အော်ဒါရှိရင် မဖျက်ရ
      const hasOrders = data.orders.some((o) => String(o.user_id) === String(user.id));
      if (hasOrders) return false;

      // lastProductView မရှိရင် အသစ်ဖွင့်ထားတာ ဒါမှမဟုတ် မကြည့်ရသေးဘူး
      if (!user.lastProductView) return true;

      // lastProductView က cutoff ထက်ဟောင်းရင် ဖျက်မယ်
      return new Date(user.lastProductView).getTime() < cutoff;
    });

    if (toDelete.length === 0) return;

    const deleteIds = new Set(toDelete.map((u) => String(u.id)));

    // Users ဖျက်မယ်
    data.users = data.users.filter((u) => !deleteIds.has(String(u.id)));

    // သူတို့ရဲ့ messages, notifications, reviews တွေလည်း ဖျက်မယ်
    data.messages = data.messages.filter((m) => !deleteIds.has(String(m.user_id)));
    data.notifications = data.notifications.filter((n) => !deleteIds.has(String(n.user_id)));
    data.reviews = data.reviews.filter((r) => !deleteIds.has(String(r.user_id)));

    await writeData(data);
    console.log(`🗑️ Cleaned up ${toDelete.length} inactive users (no orders, no views for ${INACTIVE_DAYS} days)`);
  } catch (err) {
    console.error('Cleanup inactive users failed:', err.message);
  }
}

// ============================================================
// TELEGRAM NOTIFICATIONS (3 Bots — Order, Archive, Chat)
// ============================================================
async function sendTelegramMessage(botToken, chatId, text, imageBase64 = null) {
  if (!botToken || !chatId) return;
  try {
    if (imageBase64) {
      const match = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/.exec(imageBase64);
      if (match) {
        const buffer = Buffer.from(match[2], 'base64');
        const form = new FormData();
        form.append('chat_id', chatId);
        form.append('caption', text.slice(0, 1024));
        form.append('photo', buffer, { filename: 'receipt.jpg' });
        await axios.post(`https://api.telegram.org/bot${botToken}/sendPhoto`, form, {
          headers: form.getHeaders(),
        });
        return;
      }
    }
    await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      chat_id: chatId,
      text: text.slice(0, 4096),
    });
  } catch (err) {
    console.error('Telegram send failed:', err.response?.data || err.message);
  }
}

// ---- ၁။ Order Bot (အော်ဒါအသစ်) ----
async function sendTelegramOrderNotification(order) {
  const token = process.env.ORDER_BOT_TOKEN;
  const chatId = process.env.ADMIN_CHAT_ID;
  if (!token || !chatId) return;

  const placedAt = new Date(order.created_at).toLocaleString('en-GB', {
    timeZone: 'Asia/Yangon',
    dateStyle: 'medium',
    timeStyle: 'short',
  });

  const itemLines = (order.items || [])
    .map((item) => {
      const variant = [item.size, item.color].filter(Boolean).join('/');
      return `  • ${item.name}${variant ? ` (${variant})` : ''} x${item.qty} = ${(item.qty * item.price).toLocaleString()} Ks`;
    })
    .join('\n');

  const caption =
    `🆕 New Order Arrived!\n` +
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
    (order.subtotal ? `Subtotal: ${order.subtotal.toLocaleString()} Ks\n` : '') +
    (order.service_fee ? `+ ဝန်ဆောင်ခ: ${order.service_fee.toLocaleString()} Ks\n` : '') +
    (order.purchase_tax ? `+ ဝယ်ယူခွန်: ${order.purchase_tax.toLocaleString()} Ks\n` : '') +
    (order.trade_tax ? `+ ကုန်သွယ်ခွန်: ${order.trade_tax.toLocaleString()} Ks\n` : '') +
    `💰 Total: ${order.total_amount.toLocaleString()} Ks\n` +
    `💬 Please approve via Admin Dashboard.`;

  await sendTelegramMessage(token, chatId, caption, order.receipt_image);
}

// ---- ၂။ Archive Bot (အော်ဒါအဟောင်း မဖျက်ခင်) ----
async function sendTelegramArchiveNotification(order) {
  const token = process.env.ARCHIVE_BOT_TOKEN;
  const chatId = process.env.ADMIN_CHAT_ID;
  if (!token || !chatId) return;

  const placedAt = new Date(order.created_at).toLocaleString('en-GB', {
    timeZone: 'Asia/Yangon',
    dateStyle: 'medium',
    timeStyle: 'short',
  });

  const itemLines = (order.items || [])
    .map((item) => {
      const variant = [item.size, item.color].filter(Boolean).join('/');
      return `  • ${item.name}${variant ? ` (${variant})` : ''} x${item.qty} = ${(item.qty * item.price).toLocaleString()} Ks`;
    })
    .join('\n');

  const caption =
    `🗄️ Archived Order (removed from database)\n` +
    `━━━━━━━━━━━━━━━━━━━━━━\n` +
    `📦 Order ID: ${order.order_id}\n` +
    `🕒 Placed at: ${placedAt} (MMT)\n` +
    `👤 Name: ${order.customer_name}\n` +
    `📞 Phone: ${order.phone}\n` +
    `📍 Address: ${order.address}\n` +
    `💳 Payment: ${order.payment_method}\n` +
    `📌 Final status: ${order.status}\n` +
    (order.customer_notes ? `📝 Note: ${order.customer_notes}\n` : '') +
    `────────────────────\n` +
    `🛒 Items:\n${itemLines}\n` +
    `────────────────────\n` +
    `💰 Total: ${order.total_amount.toLocaleString()} Ks\n` +
    `📌 Archived automatically (limit exceeded)`;

  await sendTelegramMessage(token, chatId, caption);
}

// ---- ၃။ Chat Bot (ဖောက်သည်က Chat ပို့တဲ့အခါ) ----
async function sendTelegramChatNotification(text, user) {
  const token = process.env.CHAT_BOT_TOKEN;
  const chatId = process.env.ADMIN_CHAT_ID;
  if (!token || !chatId) return;
  const label = user ? `${user.email} (Customer #${user.customer_number || user.id})` : 'Unknown customer';
  await sendTelegramMessage(token, chatId, `💬 New message from ${label}:\n"${text}"`);
}

// ============================================================
// AUTO-ARCHIVE OLD ORDERS (Original feature: send to Telegram then delete)
// ============================================================
const GLOBAL_ORDER_LIMIT = 10;
const CUSTOMER_ORDER_LIMIT = 7;
const ARCHIVABLE_STATUSES = ['approved', 'shipped', 'delivered', 'cancelled'];
const byOldestFirst = (a, b) => new Date(a.created_at) - new Date(b.created_at);

async function archiveOrdersIfNeeded() {
  try {
    const data = readData();
    const allOrders = data.orders || [];

    const archivable = allOrders.filter((o) => ARCHIVABLE_STATUSES.includes(o.status));
    const toArchiveMap = new Map();

    // Global limit: 10 orders total
    if (archivable.length > GLOBAL_ORDER_LIMIT) {
      const excess = archivable.length - GLOBAL_ORDER_LIMIT;
      [...archivable].sort(byOldestFirst).slice(0, excess).forEach((o) => {
        toArchiveMap.set(o.order_id, o);
      });
    }

    // Per-customer limit: 7 orders per user
    const byUser = {};
    archivable.forEach((o) => {
      if (!o.user_id) return;
      (byUser[o.user_id] = byUser[o.user_id] || []).push(o);
    });
    Object.values(byUser).forEach((userOrders) => {
      if (userOrders.length > CUSTOMER_ORDER_LIMIT) {
        const excess = userOrders.length - CUSTOMER_ORDER_LIMIT;
        [...userOrders].sort(byOldestFirst).slice(0, excess).forEach((o) => {
          toArchiveMap.set(o.order_id, o);
        });
      }
    });

    const toArchive = [...toArchiveMap.values()];
    if (toArchive.length === 0) return;

    // 1. Send to Telegram Archive Bot
    for (const order of toArchive) {
      await sendTelegramArchiveNotification(order);
    }

    // 2. Delete from data.json
    const ids = toArchive.map((o) => o.order_id);
    data.orders = data.orders.filter((o) => !ids.includes(o.order_id));
    data.notifications = data.notifications.filter((n) => !ids.includes(n.order_id));
    await writeData(data);

    console.log(`🗑️ Archived ${toArchive.length} old orders (kept latest ${GLOBAL_ORDER_LIMIT} total, ${CUSTOMER_ORDER_LIMIT} per user)`);
  } catch (err) {
    console.error('Archive orders failed:', err.message);
  }
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
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

function optionalAuth(req, res, next) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    try {
      req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    } catch (err) {}
  }
  next();
}

const adminAuth = basicAuth({
  users: { [process.env.ADMIN_USERNAME]: process.env.ADMIN_PASSWORD },
  challenge: true,
  unauthorizedResponse: () => ({ error: 'Unauthorized.' }),
});

// ============================================================
// PUBLIC ROUTES
// ============================================================

// ---- Products (with personalization) ----
app.get('/api/products', optionalAuth, async (req, res) => {
  const data = readData();
  let products = data.products || [];

  if (req.user) {
    const user = data.users.find((u) => String(u.id) === String(req.user.id));
    if (user && user.viewHistory) {
      const catScore = {};
      user.viewHistory.forEach((v) => {
        if (v.category) catScore[v.category] = (catScore[v.category] || 0) + v.score;
      });
      products.sort((a, b) => {
        const aCats = a.categories || [a.category];
        const bCats = b.categories || [b.category];
        const aScore = Math.max(0, ...aCats.map((c) => catScore[c] || 0));
        const bScore = Math.max(0, ...bCats.map((c) => catScore[c] || 0));
        return bScore - aScore;
      });
    }
  }
  res.json(products);
});

// ---- Track product view ----
app.post('/api/products/:id/view', optionalAuth, async (req, res) => {
  const data = readData();
  const product = data.products.find((p) => p.id === Number(req.params.id));
  if (!product) return res.status(404).json({ error: 'Product not found.' });

  product.views = (product.views || 0) + 1;
  await writeData(data);

  if (req.user) {
    const user = data.users.find((u) => String(u.id) === String(req.user.id));
    if (user) {
      user.lastProductView = new Date().toISOString();
      if (!Array.isArray(user.viewHistory)) user.viewHistory = [];
      const existing = user.viewHistory.find((v) => v.productId === product.id);
      if (existing) {
        existing.score += 1;
        existing.lastViewedAt = new Date().toISOString();
      } else {
        user.viewHistory.push({
          productId: product.id,
          category: (product.categories || [product.category])[0] || '',
          score: 1,
          lastViewedAt: new Date().toISOString(),
        });
      }
      if (user.viewHistory.length > 100) {
        user.viewHistory.sort((a, b) => new Date(b.lastViewedAt) - new Date(a.lastViewedAt));
        user.viewHistory = user.viewHistory.slice(0, 100);
      }
      await writeData(data);
    }
  }
  res.json({ tracked: true });
});

// ---- Categories ----
app.get('/api/categories', (req, res) => {
  const data = readData();
  res.json(data.categories || []);
});

// ---- Settings ----
app.get('/api/settings', (req, res) => {
  const data = readData();
  const { kbz, kbz_name, aya, aya_name, wave, wave_name, service_fee, purchase_tax_per_item, trade_tax } = data.settings || {};
  res.json({ kbz, kbz_name, aya, aya_name, wave, wave_name, service_fee, purchase_tax_per_item, trade_tax });
});

// ---- Songs ----
app.get('/api/songs', (req, res) => {
  const data = readData();
  res.json(data.songs || []);
});

// ---- Banners ----
app.get('/api/banners', (req, res) => {
  const data = readData();
  res.json(data.banners || []);
});

// ---- Trending ----
app.get('/api/trending', async (req, res) => {
  try {
    const data = readData();
    const orders = data.orders || [];

    const salesByProduct = {};
    orders.forEach((o) => {
      (o.items || []).forEach((item) => {
        salesByProduct[item.productId] = (salesByProduct[item.productId] || 0) + Number(item.qty);
      });
    });

    const bestSelling = (data.products || [])
      .map((p) => ({ ...p, sold: salesByProduct[p.id] || 0 }))
      .sort((a, b) => b.sold - a.sold)
      .slice(0, 20);

    const mostViewed = (data.products || [])
      .map((p) => ({ ...p, views: p.views || 0 }))
      .sort((a, b) => b.views - a.views)
      .slice(0, 20);

    res.json({ bestSelling, mostViewed });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load trending.' });
  }
});

// ============================================================
// AUTH (Signup / Login / Profile)
// ============================================================

// ---- Signup ----
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, phone, password } = req.body;
    if (!email || !password || password.length < 6) {
      return res.status(400).json({ error: 'Email နဲ့ စကားဝှက် (အနည်းဆုံး ၆ လုံး) လိုအပ်ပါတယ်။' });
    }

    const data = readData();
    const existing = data.users.find((u) => u.email === email.toLowerCase());
    if (existing) {
      return res.status(400).json({ error: 'ဒီ Email နဲ့ အကောင့်ရှိပြီးသားပါ။' });
    }

    const hash = await bcrypt.hash(password, 10);
    const newUser = {
      id: `user_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
      email: email.toLowerCase(),
      phone: phone || '',
      password: hash,
      name: '',
      profileImage: '',
      customer_number: data.users.length + 1,
      isBlocked: false,
      role: 'customer',
      lastProductView: new Date().toISOString(),
      viewHistory: [],
      created_at: new Date().toISOString(),
    };

    data.users.push(newUser);
    await writeData(data);

    const token = jwt.sign(
      { id: newUser.id, email: newUser.email, role: newUser.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({ token, user: { ...newUser, password: undefined } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Signup failed.' });
  }
});

// ---- Login ----
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email နဲ့ စကားဝှက် လိုအပ်ပါတယ်။' });
    }

    const data = readData();
    const user = data.users.find((u) => u.email === email.toLowerCase());
    if (!user || !user.password) {
      return res.status(401).json({ error: 'Email သို့မဟုတ် စကားဝှက် မှားနေပါသည်။' });
    }
    if (user.isBlocked) {
      return res.status(403).json({ error: 'ဒီအကောင့်ကို ပိတ်ထားပါသည်။' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Email သို့မဟုတ် စကားဝှက် မှားနေပါသည်။' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token, user: { ...user, password: undefined } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed.' });
  }
});

// ---- Update profile ----
app.put('/api/auth/complete-profile', authenticateCustomer, async (req, res) => {
  try {
    const { name, phone } = req.body;
    const data = readData();
    const user = data.users.find((u) => String(u.id) === String(req.user.id));
    if (!user) return res.status(404).json({ error: 'User not found.' });

    if (name !== undefined) user.name = name.trim();
    if (phone !== undefined) user.phone = phone.trim();
    await writeData(data);

    res.json({ user: { ...user, password: undefined } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update profile.' });
  }
});

// ---- Profile image ----
app.put('/api/auth/profile-image', authenticateCustomer, async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'Image URL is required.' });

    const data = readData();
    const user = data.users.find((u) => String(u.id) === String(req.user.id));
    if (!user) return res.status(404).json({ error: 'User not found.' });

    user.profileImage = url;
    await writeData(data);

    res.json({ user: { ...user, password: undefined } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update profile image.' });
  }
});

// ============================================================
// ORDERS
// ============================================================

// ---- Place order ----
app.post('/api/orders', optionalAuth, async (req, res) => {
  try {
    const { customer_name, phone, address, customer_notes, payment_method, items, receipt_image } = req.body;

    if (!customer_name || !phone || !address || !payment_method || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const data = readData();

    // Stock check
    for (const item of items) {
      const product = data.products.find((p) => p.id === item.productId);
      if (product && product.stock !== null && product.stock !== undefined && product.stock < Number(item.qty)) {
        return res.status(400).json({ error: `"${product.name}" ပစ္စည်းကုန်သွားပါပြီ (လက်ကျန် ${product.stock} ခုပဲ ရှိပါတော့တယ်)။` });
      }
    }

    const subtotal = items.reduce((sum, item) => sum + Number(item.price) * Number(item.qty), 0);
    const totalQty = items.reduce((sum, item) => sum + Number(item.qty), 0);
    const feeSettings = data.settings || {};
    const service_fee = Number(feeSettings.service_fee) || 0;
    const purchase_tax = (Number(feeSettings.purchase_tax_per_item) || 0) * totalQty;
    const trade_tax = Number(feeSettings.trade_tax) || 0;
    const total_amount = subtotal + service_fee + purchase_tax + trade_tax;

    const order = {
      order_id: generateOrderId(),
      user_id: req.user ? req.user.id : null,
      customer_name,
      phone,
      address,
      payment_method,
      customer_notes: customer_notes || '',
      items: items.map((item) => {
        const product = data.products.find((p) => p.id === item.productId);
        return {
          ...item,
          product_number: product ? product.product_number : null,
          item_id: product ? product.item_id : null,
          variant_code: variantLabel(product, item.size, item.color),
        };
      }),
      subtotal,
      service_fee,
      purchase_tax,
      trade_tax,
      total_amount,
      receipt_image: receipt_image || null,
      status: 'pending',
      created_at: new Date().toISOString(),
    };

    data.orders.push(order);
    await writeData(data);

    // Decrease stock
    items.forEach((item) => {
      const product = data.products.find((p) => p.id === item.productId);
      if (product && product.stock !== null && product.stock !== undefined) {
        product.stock = Math.max(0, product.stock - Number(item.qty));
      }
    });
    await writeData(data);

    // Send Telegram Order Notification
    await sendTelegramOrderNotification(order);

    res.status(201).json({ order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to place order.' });
  }
});

// ---- Get my orders ----
app.get('/api/orders/mine', authenticateCustomer, async (req, res) => {
  const data = readData();
  const mine = data.orders.filter((o) => String(o.user_id) === String(req.user.id));
  mine.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(mine);
});

// ============================================================
// MESSAGES (Chat)
// ============================================================

// ---- Get my messages ----
app.get('/api/messages/mine', authenticateCustomer, async (req, res) => {
  const data = readData();
  const mine = data.messages.filter((m) => String(m.user_id) === String(req.user.id));
  mine.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
  res.json(mine);
});

// ---- Send message ----
app.post('/api/messages', authenticateCustomer, async (req, res) => {
  try {
    const text = (req.body.text || '').trim();
    if (!text) return res.status(400).json({ error: 'Message is required.' });

    const data = readData();
    const user = data.users.find((u) => String(u.id) === String(req.user.id));

    const message = {
      id: `msg_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
      user_id: req.user.id,
      sender: 'customer',
      text,
      read_by_admin: false,
      created_at: new Date().toISOString(),
    };

    data.messages.push(message);
    await writeData(data);

    // Send Telegram Chat Notification
    await sendTelegramChatNotification(text, user);

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
  const data = readData();
  const mine = data.notifications.filter((n) => String(n.user_id) === String(req.user.id));
  mine.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(mine);
});

// ============================================================
// REVIEWS
// ============================================================

app.get('/api/reviews/:productId', async (req, res) => {
  const data = readData();
  const reviews = (data.reviews || [])
    .filter((r) => r.product_id === Number(req.params.productId))
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  const withUser = reviews.map((r) => {
    const user = data.users.find((u) => String(u.id) === String(r.user_id));
    return { ...r, user_id: user ? { email: user.email, customer_number: user.customer_number } : null };
  });
  res.json(withUser);
});

app.post('/api/reviews', authenticateCustomer, async (req, res) => {
  try {
    const { product_id, order_id, rating, comment, images } = req.body;
    if (!product_id || !order_id || !rating || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'product_id, order_id, and rating (1-5) are required.' });
    }

    const data = readData();
    const order = data.orders.find((o) => o.order_id === order_id && String(o.user_id) === String(req.user.id));
    if (!order) return res.status(403).json({ error: 'You can only review products you have purchased.' });

    const bought = (order.items || []).some((it) => it.productId === Number(product_id));
    if (!bought) return res.status(403).json({ error: 'You can only review products you have purchased.' });

    const existing = (data.reviews || []).find(
      (r) => r.product_id === Number(product_id) && String(r.user_id) === String(req.user.id) && r.order_id === order_id
    );
    if (existing) return res.status(400).json({ error: 'You already reviewed this product for this order.' });

    if (!Array.isArray(data.reviews)) data.reviews = [];

    const review = {
      id: `rev_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
      product_id: Number(product_id),
      user_id: req.user.id,
      order_id,
      rating: Number(rating),
      comment: (comment || '').trim(),
      images: Array.isArray(images) ? images.slice(0, 5) : [],
      created_at: new Date().toISOString(),
    };

    data.reviews.push(review);
    await writeData(data);

    res.status(201).json({ review });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to submit review.' });
  }
});

// ============================================================
// ADMIN ROUTES
// ============================================================

// ---- Products (Admin) ----
app.post('/api/admin/products', adminAuth, async (req, res) => {
  try {
    const { name, price, oldPrice, categories, image, gallery, video, desc, sizes, colors, stock, payment_type, estimated_delivery, variant_prices, variant_images } = req.body;
    const finalCategories = Array.isArray(categories) && categories.length ? categories : [];
    if (!name || !price || finalCategories.length === 0) {
      return res.status(400).json({ error: 'name, price, and categories are required.' });
    }

    const data = readData();
    const product = {
      id: nextId(data.products),
      name,
      price: Number(price),
      oldPrice: oldPrice ? Number(oldPrice) : null,
      categories: finalCategories,
      category: finalCategories[0],
      image: image || 'https://picsum.photos/400/400',
      gallery: Array.isArray(gallery) ? gallery.slice(0, 8) : [],
      video: video || '',
      desc: desc || '',
      sizes: Array.isArray(sizes) ? sizes : [],
      colors: Array.isArray(colors) ? colors : [],
      variant_prices: variant_prices && typeof variant_prices === 'object' ? variant_prices : {},
      variant_images: variant_images && typeof variant_images === 'object' ? variant_images : {},
      stock: stock !== undefined && stock !== '' ? Number(stock) : null,
      payment_type: payment_type === 'cod' ? 'cod' : 'prepay',
      estimated_delivery: estimated_delivery || '',
      views: 0,
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
    const data = readData();
    const product = data.products.find((p) => p.id === id);
    if (!product) return res.status(404).json({ error: 'Product not found.' });

    const { name, price, oldPrice, categories, image, gallery, video, desc, sizes, colors, stock, payment_type, estimated_delivery, variant_prices, variant_images } = req.body;

    if (name !== undefined) product.name = name;
    if (price !== undefined) product.price = Number(price);
    if (oldPrice !== undefined) product.oldPrice = oldPrice ? Number(oldPrice) : null;
    if (categories !== undefined) {
      product.categories = Array.isArray(categories) ? categories : [];
      product.category = product.categories[0] || '';
    }
    if (image !== undefined) product.image = image;
    if (gallery !== undefined) product.gallery = Array.isArray(gallery) ? gallery.slice(0, 8) : [];
    if (video !== undefined) product.video = video;
    if (desc !== undefined) product.desc = desc;
    if (sizes !== undefined) product.sizes = Array.isArray(sizes) ? sizes : [];
    if (colors !== undefined) product.colors = Array.isArray(colors) ? colors : [];
    if (variant_prices !== undefined) product.variant_prices = variant_prices && typeof variant_prices === 'object' ? variant_prices : {};
    if (variant_images !== undefined) product.variant_images = variant_images && typeof variant_images === 'object' ? variant_images : {};
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
    data.products = data.products.filter((p) => p.id !== id);
    await writeData(data);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete product.' });
  }
});

// ---- Categories (Admin) ----
app.post('/api/admin/categories', adminAuth, async (req, res) => {
  try {
    const name = (req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: 'Category name is required.' });
    const data = readData();
    if (!Array.isArray(data.categories)) data.categories = [];
    if (data.categories.some((c) => c.toLowerCase() === name.toLowerCase())) {
      return res.status(400).json({ error: 'Category already exists.' });
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
    const name = req.params.name;
    const data = readData();
    const used = data.products.some((p) => (p.categories || [p.category]).includes(name));
    if (used) {
      return res.status(400).json({ error: 'ဒီ category ကို သုံးနေတဲ့ ပစ္စည်းများ ရှိနေပါသေးတယ်။' });
    }
    data.categories = data.categories.filter((c) => c !== name);
    await writeData(data);
    res.json({ categories: data.categories });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete category.' });
  }
});

// ---- Orders (Admin) ----
app.get('/api/admin/orders', adminAuth, async (req, res) => {
  const data = readData();
  const orders = [...(data.orders || [])];
  orders.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(orders);
});

app.put('/api/admin/orders/:orderId', adminAuth, async (req, res) => {
  try {
    const { status } = req.body;
    const allowed = ['pending', 'approved', 'shipped', 'delivered', 'cancelled'];
    if (!allowed.includes(status)) {
      return res.status(400).json({ error: `status must be one of: ${allowed.join(', ')}` });
    }

    const data = readData();
    const order = data.orders.find((o) => o.order_id === req.params.orderId);
    if (!order) return res.status(404).json({ error: 'Order not found.' });

    const previousStatus = order.status;

    // Restore stock if cancelled
    if (status === 'cancelled' && previousStatus !== 'cancelled') {
      (order.items || []).forEach((item) => {
        const product = data.products.find((p) => p.id === item.productId);
        if (product && product.stock !== null && product.stock !== undefined) {
          product.stock += Number(item.qty);
        }
      });
    }

    order.status = status;
    await writeData(data);

    // Push notification to customer
    if (order.user_id) {
      const msg = {
        approved: `✅ သင့်အော်ဒါ ${order.order_id} ကို admin က လက်ခံလိုက်ပါပြီ။`,
        shipped: `🚚 သင့်အော်ဒါ ${order.order_id} ကို ပို့ဆောင်နေပါပြီ။`,
        delivered: `📦 သင့်အော်ဒါ ${order.order_id} ရောက်ရှိပါပြီ။`,
        cancelled: `❌ သင့်အော်ဒါ ${order.order_id} ကို ပယ်ချလိုက်ပါသည်။`,
      }[status];
      if (msg) {
        if (!Array.isArray(data.notifications)) data.notifications = [];
        data.notifications.push({
          id: `notif_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
          user_id: order.user_id,
          order_id: order.order_id,
          status,
          message: msg,
          read: false,
          created_at: new Date().toISOString(),
        });
        await writeData(data);
      }
    }

    // Run order archive (auto-delete old orders)
    await archiveOrdersIfNeeded();

    res.json({ order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update order.' });
  }
});

// ---- Users (Admin) ----
app.get('/api/admin/users', adminAuth, async (req, res) => {
  const data = readData();
  const users = (data.users || []).map((u) => {
    const orderCount = data.orders.filter((o) => String(o.user_id) === String(u.id)).length;
    return { ...u, order_count: orderCount, password: undefined };
  });
  users.sort((a, b) => (b.customer_number || 0) - (a.customer_number || 0));
  res.json(users);
});

// ---- Reset password (Admin) ----
app.put('/api/admin/users/:id/password', adminAuth, async (req, res) => {
  try {
    const newPassword = (req.body.new_password || '').trim();
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

    const data = readData();
    const user = data.users.find((u) => String(u.id) === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    user.password = await bcrypt.hash(newPassword, 10);
    await writeData(data);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to reset password.' });
  }
});

// ---- Ban / Unban (Admin) ----
app.post('/api/admin/users/:id/ban', adminAuth, async (req, res) => {
  try {
    const reason = (req.body.reason || '').trim();
    if (!reason) return res.status(400).json({ error: 'Ban reason is required.' });

    const data = readData();
    const user = data.users.find((u) => String(u.id) === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    user.isBlocked = true;
    if (!Array.isArray(user.banRecords)) user.banRecords = [];
    user.banRecords.push({ reason, banned_at: new Date().toISOString() });
    await writeData(data);

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to ban user.' });
  }
});

app.post('/api/admin/users/:id/unban', adminAuth, async (req, res) => {
  try {
    const data = readData();
    const user = data.users.find((u) => String(u.id) === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    user.isBlocked = false;
    await writeData(data);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to unban user.' });
  }
});

// ---- Messages (Admin) ----
app.get('/api/admin/conversations', adminAuth, async (req, res) => {
  const data = readData();
  const byUser = {};
  (data.messages || []).forEach((m) => {
    const key = String(m.user_id);
    (byUser[key] = byUser[key] || []).push(m);
  });

  const result = await Promise.all(
    Object.entries(byUser).map(async ([userId, msgs]) => {
      const user = data.users.find((u) => String(u.id) === userId);
      return {
        user_id: userId,
        customer_number: user?.customer_number || null,
        email: user?.email || 'Unknown',
        last_message: msgs[msgs.length - 1]?.text || '',
        last_message_at: msgs[msgs.length - 1]?.created_at || null,
        unread: msgs.filter((m) => m.sender === 'customer' && !m.read_by_admin).length,
      };
    })
  );
  result.sort((a, b) => new Date(b.last_message_at) - new Date(a.last_message_at));
  res.json(result);
});

app.get('/api/admin/messages/:userId', adminAuth, async (req, res) => {
  const data = readData();
  const thread = (data.messages || []).filter((m) => String(m.user_id) === req.params.userId);
  thread.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

  thread.forEach((m) => {
    if (m.sender === 'customer') m.read_by_admin = true;
  });
  await writeData(data);

  res.json(thread);
});

app.post('/api/admin/messages/:userId', adminAuth, async (req, res) => {
  try {
    const text = (req.body.text || '').trim();
    if (!text) return res.status(400).json({ error: 'Message is required.' });

    const data = readData();
    const message = {
      id: `msg_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
      user_id: req.params.userId,
      sender: 'admin',
      text,
      read_by_admin: true,
      created_at: new Date().toISOString(),
    };

    data.messages.push(message);
    await writeData(data);
    res.status(201).json({ message });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send message.' });
  }
});

// ---- Settings (Admin) ----
app.get('/api/admin/settings', adminAuth, (req, res) => {
  const data = readData();
  res.json(data.settings || {});
});

app.post('/api/admin/settings', adminAuth, async (req, res) => {
  try {
    const data = readData();
    data.settings = { ...data.settings, ...req.body };
    await writeData(data);
    res.json({ settings: data.settings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update settings.' });
  }
});

// ---- Banners (Admin) ----
app.post('/api/admin/banners', adminAuth, async (req, res) => {
  try {
    const { image, link } = req.body;
    if (!image) return res.status(400).json({ error: 'Banner image is required.' });

    const data = readData();
    if (!Array.isArray(data.banners)) data.banners = [];
    data.banners.push({ id: nextId(data.banners), image, link: link || '', created_at: new Date().toISOString() });
    await writeData(data);
    res.status(201).json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add banner.' });
  }
});

app.delete('/api/admin/banners/:id', adminAuth, async (req, res) => {
  try {
    const data = readData();
    data.banners = (data.banners || []).filter((b) => b.id !== Number(req.params.id));
    await writeData(data);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete banner.' });
  }
});

// ---- Songs (Admin) ----
app.post('/api/admin/songs', adminAuth, async (req, res) => {
  try {
    const { name, url } = req.body;
    if (!name || !url) return res.status(400).json({ error: 'Name and URL are required.' });

    const data = readData();
    if (!Array.isArray(data.songs)) data.songs = [];
    data.songs.push({ id: nextId(data.songs), name, url, created_at: new Date().toISOString() });
    await writeData(data);
    res.status(201).json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add song.' });
  }
});

app.put('/api/admin/songs/:id', adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { name, url } = req.body;
    const data = readData();
    const song = data.songs.find((s) => s.id === id);
    if (!song) return res.status(404).json({ error: 'Song not found.' });
    if (name !== undefined) song.name = name;
    if (url !== undefined) song.url = url;
    await writeData(data);
    res.json({ song });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update song.' });
  }
});

app.delete('/api/admin/songs/:id', adminAuth, async (req, res) => {
  try {
    const data = readData();
    data.songs = (data.songs || []).filter((s) => s.id !== Number(req.params.id));
    await writeData(data);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete song.' });
  }
});

// ---- Reorder songs (Admin) ----
app.put('/api/admin/songs-reorder', adminAuth, async (req, res) => {
  try {
    const { order } = req.body;
    if (!Array.isArray(order)) return res.status(400).json({ error: 'order must be an array.' });
    const data = readData();
    const byId = new Map(data.songs.map((s) => [s.id, s]));
    const reordered = order.map((id) => byId.get(Number(id))).filter(Boolean);
    data.songs.forEach((s) => { if (!order.includes(s.id)) reordered.push(s); });
    data.songs = reordered;
    await writeData(data);
    res.json({ songs: data.songs });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to reorder songs.' });
  }
});

// ---- Insights (Admin) ----
app.get('/api/admin/insights', adminAuth, async (req, res) => {
  try {
    const data = readData();
    const orders = data.orders || [];

    const salesByProduct = {};
    orders.forEach((o) => {
      (o.items || []).forEach((item) => {
        const key = item.productId;
        if (!salesByProduct[key]) salesByProduct[key] = { productId: key, name: item.name, qty: 0, revenue: 0 };
        salesByProduct[key].qty += Number(item.qty);
        salesByProduct[key].revenue += Number(item.qty) * Number(item.price);
      });
    });
    const topSelling = Object.values(salesByProduct).sort((a, b) => b.qty - a.qty).slice(0, 10);

    const mostViewed = (data.products || [])
      .map((p) => ({ name: p.name, score: p.views || 0 }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 10);

    res.json({ topSelling, mostViewed, totalCustomers: data.users.length });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load insights.' });
  }
});

// ---- Suspicious Activity (Admin) ----
app.get('/api/admin/suspicious-activity', adminAuth, (req, res) => {
  // data.json မှာ suspicious activity မသိမ်းတာမို့ အလွတ်ပြန်မယ်
  res.json([]);
});

// ---- Appeals (Admin) ----
app.get('/api/admin/appeals', adminAuth, (req, res) => {
  // data.json မှာ appeals မသိမ်းတာမို့ အလွတ်ပြန်မယ်
  res.json([]);
});

// ---- Customer Appeal (for banned users) ----
app.post('/api/appeals', authenticateCustomer, async (req, res) => {
  try {
    const message = (req.body.message || '').trim();
    if (!message) return res.status(400).json({ error: 'Please describe why your account should be unbanned.' });

    const data = readData();
    const user = data.users.find((u) => String(u.id) === String(req.user.id));
    if (!user) return res.status(404).json({ error: 'User not found.' });
    if (!user.isBlocked) return res.status(400).json({ error: 'Your account is not banned.' });

    // Save appeal (simple storage in user object)
    if (!Array.isArray(user.appeals)) user.appeals = [];
    user.appeals.push({ message, status: 'pending', created_at: new Date().toISOString() });
    await writeData(data);

    res.status(201).json({ success: true, message: 'Appeal submitted. Admin will review it.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to submit appeal.' });
  }
});

// ---- Admin Approve/Reject Appeal ----
app.post('/api/admin/appeals/:id/approve', adminAuth, async (req, res) => {
  try {
    const data = readData();
    // Find user with pending appeal
    let targetUser = null;
    let appealIndex = -1;
    for (const user of data.users) {
      if (Array.isArray(user.appeals)) {
        const idx = user.appeals.findIndex((a) => a.id === req.params.id && a.status === 'pending');
        if (idx !== -1) {
          targetUser = user;
          appealIndex = idx;
          break;
        }
      }
    }
    if (!targetUser) return res.status(404).json({ error: 'Appeal not found.' });

    targetUser.appeals[appealIndex].status = 'approved';
    targetUser.isBlocked = false;
    await writeData(data);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to approve appeal.' });
  }
});

app.post('/api/admin/appeals/:id/reject', adminAuth, async (req, res) => {
  try {
    const data = readData();
    let found = false;
    for (const user of data.users) {
      if (Array.isArray(user.appeals)) {
        const idx = user.appeals.findIndex((a) => a.id === req.params.id && a.status === 'pending');
        if (idx !== -1) {
          user.appeals[idx].status = 'rejected';
          found = true;
          break;
        }
      }
    }
    if (!found) return res.status(404).json({ error: 'Appeal not found.' });
    await writeData(data);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to reject appeal.' });
  }
});

// ---- Upload image (Cloudinary) ----
app.post('/api/upload-image', authenticateCustomer, async (req, res) => {
  try {
    const { image, folder } = req.body;
    if (!image) return res.status(400).json({ error: 'Image data is required.' });
    // For data.json only mode, we just return a placeholder URL
    // or we can implement a simple base64 storage, but better to keep Cloudinary if configured.
    // If Cloudinary is configured, use it.
    if (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET) {
      const cloudinary = require('cloudinary').v2;
      cloudinary.config({
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
        api_key: process.env.CLOUDINARY_API_KEY,
        api_secret: process.env.CLOUDINARY_API_SECRET,
      });
      const result = await cloudinary.uploader.upload(image, {
        folder: `neko-shop/${folder || 'misc'}`,
        resource_type: 'image',
      });
      return res.json({ url: result.secure_url });
    } else {
      // No Cloudinary: just return the base64 as-is (not recommended for production)
      return res.json({ url: image });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Upload failed.' });
  }
});

app.post('/api/admin/upload-image', adminAuth, async (req, res) => {
  try {
    const { image, folder } = req.body;
    if (!image) return res.status(400).json({ error: 'Image data is required.' });
    if (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET) {
      const cloudinary = require('cloudinary').v2;
      cloudinary.config({
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
        api_key: process.env.CLOUDINARY_API_KEY,
        api_secret: process.env.CLOUDINARY_API_SECRET,
      });
      const result = await cloudinary.uploader.upload(image, {
        folder: `neko-shop/${folder || 'products'}`,
        resource_type: 'image',
      });
      return res.json({ url: result.secure_url });
    } else {
      return res.json({ url: image });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Upload failed.' });
  }
});

// ---- Fallback ----
app.use((req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// ============================================================
// START SERVER
// ============================================================

// Run cleanup tasks on startup
cleanupInactiveUsers();
archiveOrdersIfNeeded();

// Cleanup old messages (>30 days)
const MESSAGE_RETENTION_DAYS = 30;
function cleanupOldMessages() {
  try {
    const data = readData();
    const cutoff = new Date(Date.now() - MESSAGE_RETENTION_DAYS * 24 * 60 * 60 * 1000);
    const before = data.messages.length;
    data.messages = (data.messages || []).filter((m) => new Date(m.created_at) >= cutoff);
    if (data.messages.length !== before) {
      writeData(data).catch(() => {});
      console.log(`🗑️ Cleaned up ${before - data.messages.length} old messages`);
    }
  } catch (err) {
    console.error('cleanupOldMessages failed:', err.message);
  }
}

cleanupOldMessages();

// Schedule periodic tasks (every 24 hours)
setInterval(cleanupInactiveUsers, 24 * 60 * 60 * 1000);
setInterval(archiveOrdersIfNeeded, 24 * 60 * 60 * 1000);
setInterval(cleanupOldMessages, 24 * 60 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`🚀 Neko Shop backend running on port ${PORT}`);
  console.log(`📁 Using data.json at ${DATA_FILE}`);
  console.log(`🧹 Inactive user cleanup: ${INACTIVE_DAYS} days with no views and no orders`);
  console.log(`🗄️ Order archive: keep ${GLOBAL_ORDER_LIMIT} total, ${CUSTOMER_ORDER_LIMIT} per user`);
  console.log(`💬 Message retention: ${MESSAGE_RETENTION_DAYS} days`);
});