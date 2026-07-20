require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;

// PostgreSQL Connection (Supabase)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());

// =============================================
// AUTH MIDDLEWARE (Admin & User)
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
app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products ORDER BY created_at DESC');
    res.json({ success: true, products: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// Top Selling (Most Recent 5)
app.get('/api/products/top-selling', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products ORDER BY created_at DESC LIMIT 5');
    res.json({ success: true, products: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// Categories List
app.get('/api/categories', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM categories ORDER BY name ASC');
    res.json({ success: true, categories: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// =============================================
// ADMIN ROUTES
// =============================================

// 1. Get All Orders
app.get('/api/admin/orders', basicAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM orders ORDER BY created_at DESC');
    res.json({ success: true, orders: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// 2. Update Order Status
app.put('/api/admin/orders/:orderId', basicAuth, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status } = req.body;
    await pool.query('UPDATE orders SET status = $1 WHERE order_id = $2', [status, orderId]);
    res.json({ success: true, message: `Order ${orderId} updated to ${status}` });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// 3. Add Product
app.post('/api/admin/products', basicAuth, async (req, res) => {
  try {
    const { name, price, category, image_url, description } = req.body;
    const result = await pool.query(
      'INSERT INTO products (name, price, category, image_url, description) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, price, category, image_url, description]
    );
    res.json({ success: true, product: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// 4. Delete Product
app.delete('/api/admin/products/:id', basicAuth, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM products WHERE id = $1', [id]);
    res.json({ success: true, message: 'Product deleted successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// 5. Add Category
app.post('/api/admin/categories', basicAuth, async (req, res) => {
  try {
    const { name } = req.body;
    const result = await pool.query(
      'INSERT INTO categories (name) VALUES ($1) RETURNING *',
      [name]
    );
    res.json({ success: true, category: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// 6. Delete Category
app.delete('/api/admin/categories/:id', basicAuth, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM categories WHERE id = $1', [id]);
    res.json({ success: true, message: 'Category deleted successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// 7. Save Settings (Payment Info)
app.post('/api/admin/settings', basicAuth, async (req, res) => {
  try {
    const { kbz, aya, wave } = req.body;
    await pool.query('DELETE FROM settings');
    await pool.query(
      'INSERT INTO settings (kbz_account, aya_account, wave_account) VALUES ($1, $2, $3)',
      [kbz, aya, wave]
    );
    res.json({ success: true, message: 'Settings saved successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// 8. Get Settings
app.get('/api/admin/settings', basicAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM settings LIMIT 1');
    res.json({ success: true, settings: result.rows[0] || {} });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// =============================================
// USER AUTH ROUTES (Signup / Login) - ထည့်သွင်းထားသော အပိုင်း
// =============================================

// User Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required' });
    }

    // Check if user already exists
    const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ success: false, error: 'Email already exists' });
    }

    // Hash the password (Encrypt)
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, created_at',
      [email, hashedPassword]
    );

    // Generate JWT Token
    const token = jwt.sign(
      { userId: result.rows[0].id, email: result.rows[0].email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({ 
      success: true, 
      message: 'User created successfully', 
      user: result.rows[0],
      token 
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required' });
    }

    // Find user by email
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Compare password (Decrypt & Check)
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    // Generate JWT Token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ 
      success: true, 
      message: 'Login successful', 
      user: { id: user.id, email: user.email },
      token 
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// =============================================
// START SERVER
// =============================================
app.listen(PORT, () => {
  console.log(`🚀 Neko Shop Server running on port ${PORT}`);
  console.log(`📦 Database connected`);
  console.log(`🤖 Telegram Bot ready`);
});