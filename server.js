require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');
const cors = require('cors');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;

// 1. PostgreSQL Connection (Supabase)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// 2. Supabase Client (Storage & Auth အတွက်)
const supabase = createClient(
  'https://lyxhypadsyshxzendjru.supabase.co',
  'sb_publishable_3UJDyoWL0iQ_MQXcuh3uLg__hos799X'
);

// Middleware
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());

// ============================
// TELEGRAM BOT FUNCTION
// ============================
const sendTelegramMessage = async (message) => {
  try {
    const url = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`;
    await axios.post(url, {
      chat_id: process.env.ADMIN_TELEGRAM_ID,
      text: message,
      parse_mode: 'HTML'
    });
    console.log('✅ Telegram message sent');
  } catch (error) {
    console.error('❌ Telegram error:', error.message);
  }
};

// ============================
// TEST ROUTE
// ============================
app.get('/', (req, res) => {
  res.json({ message: 'Neko Shop Backend is running!' });
});

// ============================
// PRODUCTS API
// ============================
app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products ORDER BY created_at DESC');
    res.json({ success: true, products: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// ============================
// ORDERS API (Checkout + Telegram Notification)
// ============================
app.post('/api/orders', async (req, res) => {
  try {
    const { 
      customerName, 
      phone, 
      address, 
      paymentMethod, 
      items, 
      totalAmount,
      receiptImageUrl 
    } = req.body;

    // Generate Order ID
    const orderId = 'CID-' + Date.now().toString(36).toUpperCase();

    // Save to Database
    const query = `
      INSERT INTO orders (order_id, customer_name, phone, address, payment_method, items, total_amount, receipt_image, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `;
    const values = [
      orderId, 
      customerName, 
      phone, 
      address, 
      paymentMethod, 
      JSON.stringify(items), 
      totalAmount, 
      receiptImageUrl || null, 
      'pending'
    ];

    const result = await pool.query(query, values);
    const newOrder = result.rows[0];

    // Send Telegram Notification to Admin
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

// ============================
// ADMIN LOGIN (JWT)
// ============================
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    const token = jwt.sign(
      { username, role: 'admin' }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
});

// ============================
// START SERVER
// ============================
app.listen(PORT, () => {
  console.log(`🚀 Neko Shop Server running on port ${PORT}`);
  console.log(`📦 Supabase Database connected`);
  console.log(`🤖 Telegram Bot ready`);
});