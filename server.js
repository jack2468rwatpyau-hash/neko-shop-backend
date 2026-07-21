require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());

// JSON Data File Path
const DATA_FILE = path.join(__dirname, 'data.json');

// Helper: Read Data
const readData = () => {
  const data = fs.readFileSync(DATA_FILE);
  return JSON.parse(data);
};

// Helper: Write Data
const writeData = (data) => {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
};

// =============================================
// AUTH MIDDLEWARE (Admin)
// =============================================
const basicAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const base64Credentials = authHeader.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
  const [username, password] = credentials.split(':');
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    next();
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
};

// =============================================
// TELEGRAM BOT
// =============================================
const sendTelegramMessage = async (message) => {
  try {
    const url = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`;
    await axios.post(url, {
      chat_id: process.env.ADMIN_TELEGRAM_ID,
      text: message,
      parse_mode: 'HTML'
    });
  } catch (error) {
    console.error('Telegram error:', error.message);
  }
};

// =============================================
// PUBLIC ROUTES
// =============================================
app.get('/', (req, res) => {
  res.json({ message: 'Neko Shop Backend is running!' });
});

// Products List
app.get('/api/products', (req, res) => {
  const data = readData();
  res.json({ success: true, products: data.products });
});

// =============================================
// ADMIN ROUTES
// =============================================

// 1. Get All Orders
app.get('/api/orders', (req, res) => {
  const data = readData();
  res.json({ success: true, orders: data.orders });
});

// 2. Update Order Status
app.put('/api/orders/:orderId', (req, res) => {
  const { orderId } = req.params;
  const { status } = req.body;
  const data = readData();
  const orderIndex = data.orders.findIndex(o => o.order_id === orderId);
  if (orderIndex === -1) {
    return res.status(404).json({ success: false, error: 'Order not found' });
  }
  data.orders[orderIndex].status = status;
  writeData(data);
  res.json({ success: true, message: `Order ${orderId} updated to ${status}` });
});

// 3. Add Product (Admin Custom Variants)
app.post('/api/admin/products', basicAuth, (req, res) => {
  const { name, base_price, variants, category } = req.body;
  const data = readData();
  const newProduct = {
    id: data.products.length + 1,
    name,
    base_price: Number(base_price),
    variants: variants || [],
    category: category || 'General',
    created_at: new Date().toISOString()
  };
  data.products.push(newProduct);
  writeData(data);
  res.json({ success: true, product: newProduct });
});

// 4. Delete Product
app.delete('/api/admin/products/:id', basicAuth, (req, res) => {
  const { id } = req.params;
  const data = readData();
  data.products = data.products.filter(p => p.id !== Number(id));
  writeData(data);
  res.json({ success: true, message: 'Product deleted successfully' });
});

// 5. Save Settings (Payment Info)
app.post('/api/admin/settings', basicAuth, (req, res) => {
  const { kbz, aya, wave } = req.body;
  const data = readData();
  data.settings = { kbz, aya, wave };
  writeData(data);
  res.json({ success: true, message: 'Settings saved successfully' });
});

// 6. Get Settings
app.get('/api/admin/settings', basicAuth, (req, res) => {
  const data = readData();
  res.json({ success: true, settings: data.settings || {} });
});

// =============================================
// USER AUTH ROUTES (JSON Mode)
// =============================================

// User Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, phone, password } = req.body;
    if (!email || !phone || !password) {
      return res.status(400).json({ success: false, error: 'Email, phone, and password are required' });
    }

    const data = readData();
    const existingUser = data.users.find(u => u.email === email);
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: data.users.length + 1,
      email,
      phone,
      password: hashedPassword,
      isBlocked: false,
      role: 'customer',
      created_at: new Date().toISOString()
    };

    data.users.push(newUser);
    writeData(data);

    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      user: { id: newUser.id, email: newUser.email, phone: newUser.phone },
      token
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required' });
    }

    const data = readData();
    const user = data.users.find(u => u.email === email);

    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      user: { id: user.id, email: user.email, phone: user.phone },
      token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// =============================================
// PLACE ORDER (Telegram Notification)
// =============================================
app.post('/api/orders', async (req, res) => {
  try {
    const { customerName, phone, address, paymentMethod, items, totalAmount, receiptImageUrl } = req.body;

    const orderId = 'CID-' + Date.now().toString(36).toUpperCase();

    const data = readData();
    const newOrder = {
      order_id: orderId,
      customer_name: customerName,
      phone: phone,
      address: address,
      payment_method: paymentMethod,
      items: items,
      total_amount: Number(totalAmount),
      receipt_image: receiptImageUrl || null,
      status: 'pending',
      created_at: new Date().toISOString()
    };

    data.orders.push(newOrder);
    writeData(data);

    // Send Telegram Notification
    let itemsText = items.map(item => 
      `  • ${item.name} (${item.size || 'N/A'}) x${item.quantity} = ${item.price} ကျပ်`
    ).join('\n');

    const message = `
🆕 အော်ဒါအသစ်ရောက်လာပါပြီ!
━━━━━━━━━━━━━━━━━━━━━━
📦 အော်ဒါအမှတ်: ${orderId}
👤 အမည်: ${customerName}
📞 ဖုန်း: ${phone}
📍 လိပ်စာ: ${address}
💳 ငွေပေးချေမှု: ${paymentMethod}
────────────────────
🛒 ပစ္စည်းများ:
${itemsText}
────────────────────
💰 စုစုပေါင်းကျသင့်ငွေ: ${totalAmount} ကျပ်
📎 ပြေစာပုံ: ${receiptImageUrl || 'မရှိသေးပါ'}
────────────────────
💬 Admin Dashboard မှာ အတည်ပြုပေးပါ။
    `;

    await sendTelegramMessage(message);

    res.status(201).json({ 
      success: true, 
      message: 'Order placed successfully', 
      order: newOrder 
    });

  } catch (error) {
    console.error('Order error:', error);
    res.status(500).json({ success: false, error: 'Failed to place order' });
  }
});

// =============================================
// START SERVER
// =============================================
app.listen(PORT, () => {
  console.log(`🚀 Neko Shop Server running on port ${PORT} (JSON Mode)`);
});