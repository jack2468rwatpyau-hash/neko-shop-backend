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
const basicAuth = require('express-basic-auth');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATA_FILE = path.join(__dirname, 'data.json');

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set. Add it to your .env file before starting the server.');
  process.exit(1);
}

// ---------- Middleware ----------
app.use(helmet());
app.use(cors());
// Base64 receipt images can be large, so raise the body size limit.
app.use(bodyParser.json({ limit: '15mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '15mb' }));

// ---------- JSON "database" helpers ----------
// A simple write queue prevents concurrent writes from corrupting data.json
// when multiple requests land at the same time.
let writeQueue = Promise.resolve();

function readData() {
  const raw = fs.readFileSync(DATA_FILE, 'utf-8');
  return JSON.parse(raw);
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

function nextId(collection) {
  return collection.length ? Math.max(...collection.map((item) => item.id)) + 1 : 1;
}

function generateOrderId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let suffix = '';
  for (let i = 0; i < 6; i++) suffix += chars[Math.floor(Math.random() * chars.length)];
  return `CID-${suffix}`;
}

function maskPhone(phone) {
  // Keeps the first 5 and last 2 characters visible, e.g. 09-67•••••81
  const digits = String(phone || '');
  if (digits.length <= 7) return digits;
  const head = digits.slice(0, 5);
  const tail = digits.slice(-2);
  return `${head}${'•'.repeat(Math.max(digits.length - 7, 5))}${tail}`;
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

const adminAuth = basicAuth({
  users: { [process.env.ADMIN_USERNAME]: process.env.ADMIN_PASSWORD },
  challenge: true,
  unauthorizedResponse: () => ({ error: 'Admin authentication required.' }),
});

// ---------- Telegram notification ----------
async function sendTelegramOrderNotification(order) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.ADMIN_TELEGRAM_ID;
  if (!token || !chatId) {
    console.warn('Telegram credentials not configured; skipping notification.');
    return;
  }

  const itemLines = order.items
    .map((item) => `  • ${item.name} x${item.qty} = ${(item.qty * item.price).toLocaleString()} Ks`)
    .join('\n');

  const receiptNote = order.receipt_image ? '(Base64 image attached in dashboard)' : 'Not provided';

  const message =
    `🆕 New Order Arrived!\n` +
    `━━━━━━━━━━━━━━━━━━━━━━\n` +
    `📦 Order ID: ${order.order_id}\n` +
    `👤 Name: ${order.customer_name}\n` +
    `📞 Phone: ${maskPhone(order.phone)}\n` +
    `📍 Address: ${order.address}\n` +
    `💳 Payment: ${order.payment_method}\n` +
    `────────────────────\n` +
    `🛒 Items:\n${itemLines}\n` +
    `────────────────────\n` +
    `💰 Total: ${order.total_amount.toLocaleString()} Ks\n` +
    `📎 Receipt: ${receiptNote}\n` +
    `────────────────────\n` +
    `💬 Please approve via Admin Dashboard.`;

  try {
    await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
      chat_id: chatId,
      text: message,
    });
  } catch (err) {
    console.error('Telegram notification failed:', err.response?.data || err.message);
  }
}

// ============================================================
// PUBLIC ROUTES
// ============================================================

app.get('/api/products', (req, res) => {
  const data = readData();
  res.json(data.products);
});

// Public: payment merchant numbers shown on the checkout screen.
// (Separate from /api/admin/settings, which requires admin auth.)
app.get('/api/settings', (req, res) => {
  const data = readData();
  const { kbz, aya, wave } = data.settings || {};
  res.json({ kbz, aya, wave });
});

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, phone, password } = req.body;
    if (!email || !phone || !password) {
      return res.status(400).json({ error: 'email, phone, and password are required.' });
    }
    const data = readData();

    const existing = data.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const hash = await bcrypt.hash(password, 10);
    const newUser = {
      id: nextId(data.users),
      email,
      phone,
      password: hash,
      isBlocked: false,
      role: 'customer',
      created_at: new Date().toISOString(),
    };
    data.users.push(newUser);
    await writeData(data);

    const { password: _pw, ...safeUser } = newUser;
    res.status(201).json({ user: safeUser });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Signup failed.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required.' });
    }
    const data = readData();
    const user = data.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
    if (!user) return res.status(401).json({ error: 'Invalid email or password.' });
    if (user.isBlocked) return res.status(403).json({ error: 'This account has been blocked.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid email or password.' });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, {
      expiresIn: '7d',
    });
    const { password: _pw, ...safeUser } = user;
    res.json({ token, user: safeUser });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed.' });
  }
});

app.post('/api/orders', async (req, res) => {
  try {
    const { customer_name, phone, address, payment_method, items, receipt_image } = req.body;
    if (!customer_name || !phone || !address || !payment_method || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'customer_name, phone, address, payment_method, and items are required.' });
    }

    const total_amount = items.reduce((sum, item) => sum + Number(item.price) * Number(item.qty), 0);

    const data = readData();
    const order = {
      order_id: generateOrderId(),
      customer_name,
      phone,
      address,
      payment_method,
      items,
      total_amount,
      receipt_image: receipt_image || null,
      status: 'pending',
      created_at: new Date().toISOString(),
    };
    data.orders.push(order);
    await writeData(data);

    // Fire-and-forget: order is saved regardless of Telegram delivery.
    sendTelegramOrderNotification(order);

    res.status(201).json({ order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to place order.' });
  }
});

// ============================================================
// ADMIN ROUTES (Basic Auth)
// ============================================================

app.get('/api/admin/orders', adminAuth, (req, res) => {
  const data = readData();
  res.json(data.orders);
});

app.put('/api/admin/orders/:orderId', adminAuth, async (req, res) => {
  try {
    const { status } = req.body;
    const allowed = ['pending', 'approved', 'shipped', 'cancelled'];
    if (!allowed.includes(status)) {
      return res.status(400).json({ error: `status must be one of: ${allowed.join(', ')}` });
    }
    const data = readData();
    const order = data.orders.find((o) => o.order_id === req.params.orderId);
    if (!order) return res.status(404).json({ error: 'Order not found.' });

    order.status = status;
    await writeData(data);
    res.json({ order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update order.' });
  }
});

app.post('/api/admin/products', adminAuth, async (req, res) => {
  try {
    const { name, price, oldPrice, category, image, desc, sizes, colors } = req.body;
    if (!name || !price || !category) {
      return res.status(400).json({ error: 'name, price, and category are required.' });
    }
    const data = readData();
    const product = {
      id: nextId(data.products),
      name,
      price: Number(price),
      oldPrice: oldPrice ? Number(oldPrice) : null,
      category,
      image: image || 'https://picsum.photos/400/400',
      desc: desc || '',
      sizes: Array.isArray(sizes) ? sizes : [],
      colors: Array.isArray(colors) ? colors : [],
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
    const { name, price, oldPrice, category, image, desc, sizes, colors } = req.body;

    const data = readData();
    const product = data.products.find((p) => p.id === id);
    if (!product) return res.status(404).json({ error: 'Product not found.' });

    if (name !== undefined) product.name = name;
    if (price !== undefined) product.price = Number(price);
    if (oldPrice !== undefined) product.oldPrice = oldPrice ? Number(oldPrice) : null;
    if (category !== undefined) product.category = category;
    if (image !== undefined) product.image = image;
    if (desc !== undefined) product.desc = desc;
    if (sizes !== undefined) product.sizes = Array.isArray(sizes) ? sizes : [];
    if (colors !== undefined) product.colors = Array.isArray(colors) ? colors : [];

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

// ---------- Fallback ----------
app.use((req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

app.listen(PORT, () => {
  console.log(`Neko Shop backend running on port ${PORT}`);
});
