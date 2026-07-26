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
  const data = JSON.parse(raw);
  if (!Array.isArray(data.notifications)) data.notifications = [];
  if (!Array.isArray(data.categories)) {
    const fromProducts = [...new Set((data.products || []).map((p) => p.category).filter(Boolean))];
    data.categories = fromProducts.length ? fromProducts : ['figures', 'clothing', 'accessories'];
  }
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

// Builds { "S-Red": "A", "S-Black": "B", "M-Red": "C", ... } for every
// size × color combination, in order, so each variant has a stable letter.
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

// Like authenticateCustomer, but never blocks the request — used on routes
// (like placing an order) that must work for guests too. If a valid token
// is present, req.user is attached so the order can be linked to the account.
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
  unauthorizedResponse: () => ({ error: 'Admin authentication required.' }),
});

// ---------- Telegram notification ----------
async function sendTelegramOrderCard(order, { title, footer }) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.ADMIN_TELEGRAM_ID;
  if (!token || !chatId) {
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
    `📞 Phone: ${maskPhone(order.phone)}\n` +
    `📍 Address: ${order.address}\n` +
    `💳 Payment: ${order.payment_method}\n` +
    (order.customer_notes ? `📝 Note: ${order.customer_notes}\n` : '') +
    `────────────────────\n` +
    `🛒 Items:\n${itemLines}\n` +
    `────────────────────\n` +
    `💰 Total: ${order.total_amount.toLocaleString()} Ks\n` +
    (footer ? `${footer}\n` : '');

  try {
    // receipt_image is a data URL like "data:image/png;base64,AAAA..."
    const match = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/.exec(order.receipt_image || '');
    if (match) {
      const buffer = Buffer.from(match[2], 'base64');
      const form = new FormData();
      form.append('chat_id', chatId);
      form.append('caption', caption.slice(0, 1024)); // Telegram photo-caption limit
      form.append('photo', buffer, { filename: `${order.order_id}.jpg` });
      await axios.post(`https://api.telegram.org/bot${token}/sendPhoto`, form, {
        headers: form.getHeaders(),
      });
    } else {
      await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
        chat_id: chatId,
        text: caption,
      });
    }
  } catch (err) {
    console.error('Telegram notification failed:', err.response?.data || err.message);
  }
}

function sendTelegramOrderNotification(order) {
  return sendTelegramOrderCard(order, {
    title: '🆕 New Order Arrived!',
    footer: '💬 Please approve via Admin Dashboard.',
  });
}

// ============================================================
// AUTO-ARCHIVE OLD ORDERS
// ============================================================
// Two independent cleanup rules, both only ever touch finished orders
// (approved / shipped / cancelled) — pending orders are never removed.
// They run independently and are merged (not mutually exclusive), so the
// per-customer cap always applies even if the shop-wide total is high too:
//   1) Global: keep at most 10 finished orders shop-wide.
//   2) Per-customer: keep at most 7 finished orders per logged-in customer.
// Every deletion is preceded by a Telegram send (with receipt photo),
// so nothing is ever lost — it just moves from data.json to Telegram.
const GLOBAL_ORDER_LIMIT = 10;
const CUSTOMER_ORDER_LIMIT = 7;
const ARCHIVABLE_STATUSES = ['approved', 'shipped', 'cancelled'];

function sendTelegramArchiveNotification(order) {
  return sendTelegramOrderCard(order, {
    title: '🗄️ Archived Order (removed from database)',
    footer: `📌 Final status: ${order.status}`,
  });
}

const byOldestFirst = (a, b) => new Date(a.created_at) - new Date(b.created_at);

async function archiveOrdersIfNeeded() {
  try {
    const data = readData();
    const archivable = data.orders.filter((o) => ARCHIVABLE_STATUSES.includes(o.status));

    const toArchiveMap = new Map(); // order_id -> order (dedup between the two rules)

    // Rule 1: global cap.
    if (archivable.length > GLOBAL_ORDER_LIMIT) {
      const excess = archivable.length - GLOBAL_ORDER_LIMIT;
      [...archivable].sort(byOldestFirst).slice(0, excess)
        .forEach((o) => toArchiveMap.set(o.order_id, o));
    }

    // Rule 2: per-customer cap — always checked, independent of rule 1.
    const byUser = {};
    archivable.forEach((o) => {
      if (!o.user_id) return; // guest orders have no account history to cap
      (byUser[o.user_id] = byUser[o.user_id] || []).push(o);
    });
    Object.values(byUser).forEach((userOrders) => {
      if (userOrders.length > CUSTOMER_ORDER_LIMIT) {
        const excess = userOrders.length - CUSTOMER_ORDER_LIMIT;
        [...userOrders].sort(byOldestFirst).slice(0, excess)
          .forEach((o) => toArchiveMap.set(o.order_id, o));
      }
    });

    const toArchive = [...toArchiveMap.values()];
    if (toArchive.length === 0) return;

    for (const order of toArchive) {
      await sendTelegramArchiveNotification(order);
    }

    const ids = new Set(toArchive.map((o) => o.order_id));
    const fresh = readData();
    fresh.orders = fresh.orders.filter((o) => !ids.has(o.order_id));
    await writeData(fresh);
  } catch (err) {
    console.error('Order archival failed:', err);
  }
}

// ============================================================
// PUBLIC ROUTES
// ============================================================

app.get('/api/products', (req, res) => {
  const data = readData();
  res.json(data.products);
});

// Public: category list, used for the home page filter tabs and the Categories page.
app.get('/api/categories', (req, res) => {
  const data = readData();
  res.json(data.categories);
});

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
    // Keep existing products pointing at the renamed category.
    data.products.forEach((p) => { if (p.category === oldName) p.category = newName; });
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
    if (data.products.some((p) => p.category === name)) {
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
    const nextCustomerNumber = data.users.reduce((max, u) => Math.max(max, u.customer_number || 0), 0) + 1;
    const newUser = {
      id: nextId(data.users),
      customer_number: nextCustomerNumber,
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
    const token = jwt.sign({ id: newUser.id, email: newUser.email, role: newUser.role }, JWT_SECRET, {
      expiresIn: '7d',
    });
    res.status(201).json({ token, user: safeUser });
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

app.post('/api/orders', optionalAuth, async (req, res) => {
  try {
    const { customer_name, phone, address, customer_notes, payment_method, items, receipt_image } = req.body;
    if (!customer_name || !phone || !address || !payment_method || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'customer_name, phone, address, payment_method, and items are required.' });
    }

    const total_amount = items.reduce((sum, item) => sum + Number(item.price) * Number(item.qty), 0);

    const data = readData();

    // Stock check — products with stock === null/undefined are treated as untracked (unlimited).
    for (const item of items) {
      const product = data.products.find((p) => p.id === item.productId);
      if (product && product.stock !== null && product.stock !== undefined && product.stock < Number(item.qty)) {
        return res.status(400).json({ error: `"${product.name}" ပစ္စည်းကုန်သွားပါပြီ (လက်ကျန် ${product.stock} ခုပဲ ရှိပါတော့တယ်)။` });
      }
    }

    const order = {
      order_id: generateOrderId(),
      user_id: req.user ? req.user.id : null,
      customer_name,
      phone,
      address,
      customer_notes: customer_notes || '',
      payment_method,
      items: items.map((item) => {
        const product = data.products.find((p) => p.id === item.productId);
        return {
          ...item,
          product_number: product ? product.product_number : null,
          item_id: product ? product.item_id : null,
          letter_code: product ? product.letter_code : null,
          variant_code: variantLabel(product, item.size, item.color),
        };
      }),
      total_amount,
      receipt_image: receipt_image || null,
      status: 'pending',
      created_at: new Date().toISOString(),
    };
    data.orders.push(order);

    // Decrement stock now that the order is accepted.
    items.forEach((item) => {
      const product = data.products.find((p) => p.id === item.productId);
      if (product && product.stock !== null && product.stock !== undefined) {
        product.stock = Math.max(0, product.stock - Number(item.qty));
      }
    });

    await writeData(data);

    // Fire-and-forget: order is saved regardless of Telegram delivery.
    sendTelegramOrderNotification(order);

    res.status(201).json({ order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to place order.' });
  }
});

// Logged-in customer's own notifications (order accepted/cancelled/shipped), freshest first.
app.get('/api/notifications/mine', authenticateCustomer, (req, res) => {
  const data = readData();
  const mine = data.notifications
    .filter((n) => n.user_id === req.user.id)
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(mine);
});

// Logged-in customer's own order history, freshest first — this is what
// lets "My Orders" reflect real-time status (e.g. admin cancelling an order)
// instead of the stale copy that used to sit in localStorage.
app.get('/api/orders/mine', authenticateCustomer, (req, res) => {
  const data = readData();
  const mine = data.orders
    .filter((o) => o.user_id === req.user.id)
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(mine);
});

// ============================================================
// ADMIN ROUTES (Basic Auth)
// ============================================================

app.get('/api/admin/orders', adminAuth, (req, res) => {
  const data = readData();
  res.json(data.orders);
});

const ORDER_STATUS_MESSAGES = {
  approved: (id) => `✅ သင့်အော်ဒါ ${id} ကို admin က လက်ခံလိုက်ပါပြီ။`,
  shipped: (id) => `🚚 သင့်အော်ဒါ ${id} ကို ပို့ဆောင်နေပါပြီ။`,
  cancelled: (id) => `❌ သင့်အော်ဒါ ${id} ကို ပယ်ချလိုက်ပါသည်။`,
};
const NOTIFICATION_LIMIT_PER_USER = 20;

function pushNotification(data, userId, orderId, status) {
  const build = ORDER_STATUS_MESSAGES[status];
  if (!userId || !build) return;

  data.notifications.push({
    id: `N-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    user_id: userId,
    order_id: orderId,
    status,
    message: build(orderId),
    created_at: new Date().toISOString(),
    read: false,
  });

  // Keep at most the most recent 20 notifications per customer — auto-delete oldest.
  const mine = data.notifications.filter((n) => n.user_id === userId);
  if (mine.length > NOTIFICATION_LIMIT_PER_USER) {
    const excessIds = new Set(
      [...mine]
        .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
        .slice(0, mine.length - NOTIFICATION_LIMIT_PER_USER)
        .map((n) => n.id)
    );
    data.notifications = data.notifications.filter((n) => !excessIds.has(n.id));
  }
}

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

    // If this order is newly cancelled (wasn't cancelled before), give the stock back.
    if (status === 'cancelled' && order.status !== 'cancelled') {
      order.items.forEach((item) => {
        const product = data.products.find((p) => p.id === item.productId);
        if (product && product.stock !== null && product.stock !== undefined) {
          product.stock += Number(item.qty);
        }
      });
    }

    // Notify the customer only when the status actually changes.
    if (status !== order.status) {
      pushNotification(data, order.user_id, order.order_id, status);
    }

    order.status = status;
    await writeData(data);

    // Fire-and-forget: response doesn't wait on Telegram archival/cleanup.
    archiveOrdersIfNeeded();

    res.json({ order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update order.' });
  }
});

app.post('/api/admin/products', adminAuth, async (req, res) => {
  try {
    const { name, price, oldPrice, category, image, images, desc, sizes, colors, stock, payment_type, estimated_delivery } = req.body;
    if (!name || !price || !category) {
      return res.status(400).json({ error: 'name, price, and category are required.' });
    }
    const data = readData();
    const finalSizes = Array.isArray(sizes) ? sizes : [];
    const finalColors = Array.isArray(colors) ? colors : [];
    const productNumber = nextProductNumber(data.products);
    const product = {
      id: nextId(data.products),
      product_number: productNumber,
      item_id: `ITM-${String(productNumber).padStart(3, '0')}`,
      letter_code: letterCode(productNumber - 1),
      name,
      price: Number(price),
      oldPrice: oldPrice ? Number(oldPrice) : null,
      category,
      image: image || 'https://picsum.photos/400/400',
      images: images && typeof images === 'object' ? images : {},
      desc: desc || '',
      sizes: finalSizes,
      colors: finalColors,
      variant_codes: buildVariantCodes(finalSizes, finalColors),
      stock: stock !== undefined && stock !== '' ? Number(stock) : null, // null = unlimited/untracked
      payment_type: payment_type === 'cod' ? 'cod' : 'prepay',
      estimated_delivery: estimated_delivery || '',
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
    const { name, price, oldPrice, category, image, images, desc, sizes, colors, stock, payment_type, estimated_delivery } = req.body;

    const data = readData();
    const product = data.products.find((p) => p.id === id);
    if (!product) return res.status(404).json({ error: 'Product not found.' });

    if (name !== undefined) product.name = name;
    if (price !== undefined) product.price = Number(price);
    if (oldPrice !== undefined) product.oldPrice = oldPrice ? Number(oldPrice) : null;
    if (category !== undefined) product.category = category;
    if (image !== undefined) product.image = image;
    if (images !== undefined) product.images = images && typeof images === 'object' ? images : {};
    if (desc !== undefined) product.desc = desc;
    if (sizes !== undefined) product.sizes = Array.isArray(sizes) ? sizes : [];
    if (colors !== undefined) product.colors = Array.isArray(colors) ? colors : [];
    if (sizes !== undefined || colors !== undefined) {
      product.variant_codes = buildVariantCodes(product.sizes, product.colors);
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
