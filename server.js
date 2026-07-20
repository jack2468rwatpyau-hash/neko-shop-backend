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
const webpush = require('web-push');

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
// VAPID KEYS FOR WEB PUSH (Browser Notification)
// =============================================
const vapidKeys = webpush.generateVAPIDKeys();
webpush.setVapidDetails(
  'mailto:admin@nekoshop.com',
  vapidKeys.publicKey,
  vapidKeys.privateKey
);

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
// AUTO CLEANUP: DELETE COMPLETED ORDERS (After 1 Hour)
// =============================================
setInterval(() => {
  const data = readData();
  const now = new Date();
  const ONE_HOUR_MS = 60 * 60 * 1000; // 1 hour

  // Keep only orders that are NOT completed, OR completed less than 1 hour ago
  data.orders = data.orders.filter(o => {
    if (o.is_completed === true) {
      const orderDate = new Date(o.updated_at || o.created_at);
      return (now - orderDate) < ONE_HOUR_MS;
    }
    return true; // Keep pending/active orders
  });
  writeData(data);
}, 60000); // Run every 1 minute

// =============================================
// PUBLIC ROUTES
// =============================================
app.get('/', (req, res) => {
  res.json({ message: 'Neko Shop Backend is running! (JSON Mode)' });
});

// Products List
app.get('/api/products', (req, res) => {
  const data = readData();
  res.json({ success: true, products: data.products });
});

// Top Selling
app.get('/api/products/top-selling', (req, res) => {
  const data = readData();
  res.json({ success: true, products: data.products.slice(0, 5) });
});

// Categories List
app.get('/api/categories', (req, res) => {
  const data = readData();
  res.json({ success: true, categories: data.categories });
});

// =============================================
// ADMIN ROUTES
// =============================================

// 1. Get All Orders
app.get('/api/orders', (req, res) => {
  const data = readData();
  res.json({ success: true, orders: data.orders });
});

// 2. Update Order Status (Approve / Reject / Complete)
app.put('/api/orders/:orderId', async (req, res) => {
  const { orderId } = req.params;
  const { status, is_completed } = req.body;
  const data = readData();
  const orderIndex = data.orders.findIndex(o => o.order_id === orderId);
  if (orderIndex === -1) {
    return res.status(404).json({ success: false, error: 'Order not found' });
  }
  
  data.orders[orderIndex].status = status;
  if (is_completed === true) {
    data.orders[orderIndex].is_completed = true;
    data.orders[orderIndex].updated_at = new Date().toISOString();
  }
  writeData(data);

  // Send Telegram Notification upon status change
  let statusMsg = '';
  if (status === 'approved') statusMsg = '✅ အတည်ပြုပြီးပါပြီ။ ပစ္စည်းများ မကြာမီ ပို့ဆောင်ပေးပါမည်။';
  else if (status === 'rejected') statusMsg = '❌ ငြင်းပယ်ခံရပါသည်။ အကြောင်းအမျိုးမျိုးကြောင့် ဖြစ်နိုင်ပါသည်။';
  else if (status === 'completed') statusMsg = '✅ အော်ဒါ ပြီးဆုံးသွားပါပြီ။ (System မှ ၁ နာရီအတွင်း အလိုအလျောက် ဖျက်သွားပါမည်)';
  
  if (statusMsg) {
    const message = `
📦 အော်ဒါအမှတ်: ${orderId}
အခြေအနေ: ${statusMsg}
    `;
    await sendTelegramMessage(message);
  }

  // === BROWSER NOTIFICATION (Web Push) ===
  // NOTE: User subscription data must be stored in data.json to make this work.
  // This code is ready to run if you capture subscription from frontend.
  if (status === 'approved' || status === 'rejected') {
    const payload = JSON.stringify({
      title: status === 'approved' ? 'အော်ဒါ အတည်ပြုပြီးပါပြီ' : 'အော်ဒါ ငြင်းပယ်ခံရပါသည်',
      body: `အော်ဒါနံပါတ် ${orderId} သည် ${status === 'approved' ? 'အတည်ပြုပြီး ပို့ဆောင်ပေးပါမည်။' : 'အကြောင်းအမျိုးမျိုးကြောင့် ငြင်းပယ်လိုက်ရပါသည်။'}`,
      icon: '/icon.png'
    });
    // To Do: Send to actual user subscription stored in DB
    // await webpush.sendNotification(userSubscription, payload);
  }

  res.json({ success: true, message: `Order ${orderId} updated to ${status}` });
});

// 3. Add Product
app.post('/api/admin/products', basicAuth, (req, res) => {
  const { name, price, category, image_url, description } = req.body;
  const data = readData();
  const newProduct = {
    id: data.products.length + 1,
    name,
    price: Number(price),
    category: category || '',
    image_url: image_url || '',
    description: description || '',
    created_at: new Date().toISOString()
  };
  data.products.push(newProduct);
  writeData(data);
  res.json({ success: true, product: newProduct });
});

// 4. Update Product
app.put('/api/admin/products/:id', basicAuth, (req, res) => {
  const { id } = req.params;
  const { name, price, category, image_url, description } = req.body;
  const data = readData();
  const productIndex = data.products.findIndex(p => p.id === Number(id));
  if (productIndex === -1) {
    return res.status(404).json({ success: false, error: 'Product not found' });
  }
  data.products[productIndex] = {
    ...data.products[productIndex],
    name,
    price: Number(price),
    category,
    image_url,
    description
  };
  writeData(data);
  res.json({ success: true, product: data.products[productIndex] });
});

// 5. Delete Product
app.delete('/api/admin/products/:id', basicAuth, (req, res) => {
  const { id } = req.params;
  const data = readData();
  data.products = data.products.filter(p => p.id !== Number(id));
  writeData(data);
  res.json({ success: true, message: 'Product deleted successfully' });
});

// 6. Add Category
app.post('/api/admin/categories', basicAuth, (req, res) => {
  const { name } = req.body;
  const data = readData();
  const newCategory = {
    id: data.categories.length + 1,
    name
  };
  data.categories.push(newCategory);
  writeData(data);
  res.json({ success: true, category: newCategory });
});

// 7. Save Settings
app.post('/api/admin/settings', basicAuth, (req, res) => {
  const { kbz, aya, wave } = req.body;
  const data = readData();
  data.settings = { kbz, aya, wave };
  writeData(data);
  res.json({ success: true, message: 'Settings saved successfully' });
});

// 8. Get Settings
app.get('/api/admin/settings', basicAuth, (req, res) => {
  const data = readData();
  res.json({ success: true, settings: data.settings || {} });
});

// =============================================
// ADMIN USER MANAGEMENT ROUTES
// =============================================

// 9. Get All Users (Admin Only)
app.get('/api/admin/users', basicAuth, (req, res) => {
  const data = readData();
  // Remove password field for security
  const safeUsers = data.users.map(u => {
    const { password, ...rest } = u;
    return rest;
  });
  res.json({ success: true, users: safeUsers });
});

// 10. Block / Unblock User
app.put('/api/admin/users/:userId/block', basicAuth, (req, res) => {
  const { userId } = req.params;
  const { is_blocked } = req.body;
  const data = readData();
  const userIndex = data.users.findIndex(u => u.id === Number(userId));
  if (userIndex === -1) {
    return res.status(404).json({ success: false, error: 'User not found' });
  }
  data.users[userIndex].is_blocked = is_blocked;
  writeData(data);
  res.json({ success: true, message: `User ${is_blocked ? 'blocked' : 'unblocked'} successfully` });
});

// 11. Delete User (Adds Phone/Email to Blocked Credentials List)
app.delete('/api/admin/users/:userId', basicAuth, (req, res) => {
  const { userId } = req.params;
  const data = readData();
  const userIndex = data.users.findIndex(u => u.id === Number(userId));
  if (userIndex === -1) {
    return res.status(404).json({ success: false, error: 'User not found' });
  }

  const userToDelete = data.users[userIndex];

  // Add to blocked credentials list
  if (!data.blocked_credentials) data.blocked_credentials = [];
  data.blocked_credentials.push({
    phone: userToDelete.phone,
    email: userToDelete.email,
    blocked_at: new Date().toISOString()
  });

  // Remove user
  data.users.splice(userIndex, 1);
  writeData(data);
  res.json({ success: true, message: 'User deleted and credentials blocked' });
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

    // Check if phone or email is in blocked credentials list
    if (data.blocked_credentials) {
      const isBlocked = data.blocked_credentials.some(b => b.phone === phone || b.email === email);
      if (isBlocked) {
        return res.status(403).json({ success: false, error: 'This phone number or email has been blocked by Admin.' });
      }
    }

    const existingUser = data.users.find(u => u.email === email);
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: data.users.length + 1,
      email: email,
      phone: phone,
      password: hashedPassword,
      is_blocked: false,
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
      user: {
        id: newUser.id,
        email: newUser.email,
        phone: newUser.phone,
        created_at: newUser.created_at
      },
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

    // Check if user is blocked
    if (user.is_blocked === true) {
      return res.status(403).json({ success: false, error: 'Your account has been blocked by Admin.' });
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
// PLACE ORDER (Auto CID-XXXX + Telegram Notification)
// =============================================
app.post('/api/orders', async (req, res) => {
  try {
    const { customerName, phone, address, paymentMethod, items, totalAmount, receiptImageUrl } = req.body;

    // Auto Generate CID-XXXX Order ID
    const data = readData();
    if (!data.order_counter) data.order_counter = 0;
    data.order_counter += 1;
    const orderId = 'CID-' + String(data.order_counter).padStart(4, '0');

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
      is_completed: false,
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