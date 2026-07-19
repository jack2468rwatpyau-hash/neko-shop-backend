require('dotenv').config();
const express = require('express');
const Parse = require('parse/node');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const cron = require('node-cron');

// Initialize Parse
Parse.initialize(
  process.env.PARSE_APP_ID,
  process.env.PARSE_JS_KEY,
  process.env.PARSE_CLIENT_KEY
);
Parse.serverURL = process.env.PARSE_SERVER_URL;

const app = express();
const PORT = process.env.PORT || 3000;

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https://parseapi.back4app.com"],
      connectSrc: ["'self'", "https://parseapi.back4app.com"]
    }
  }
}));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Serve static files
app.use(express.static('public'));

// ============================================
// EMAIL TRANSPORTER (Gmail)
// ============================================

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, 
    pass: process.env.EMAIL_PASS   // ✅ ဒါကို .env နဲ့ ကိုက်အောင် ပြင်ထားပါတယ်
  }
});

// ============================================
// HELPER FUNCTIONS
// ============================================

// Generate unique Order ID
const generateOrderId = () => {
  const timestamp = Date.now().toString(36).toUpperCase();
  const random = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `NEKO-${timestamp}-${random}`;
};

// Format currency
const formatPrice = (price) => {
  return Number(price).toLocaleString('my-MM');
};

// ============================================
// API ROUTES - Products
// ============================================

app.get('/api/products', async (req, res) => {
  try {
    const Product = Parse.Object.extend('Products');
    const query = new Parse.Query(Product);
    query.descending('createdAt');
    
    const results = await query.find();
    const products = results.map(product => ({
      id: product.id,
      name: product.get('name'),
      price: product.get('price'),
      imageUrl: product.get('imageUrl'),
      description: product.get('description'),
      createdAt: product.get('createdAt')
    }));
    
    res.json({ success: true, products });
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch products' });
  }
});

// ============================================
// API ROUTES - Orders
// ============================================

app.post('/api/orders', async (req, res) => {
  try {
    const { 
      customerName, 
      phone, 
      email,  
      address, 
      note, 
      paymentMethod,
      items, 
      totalAmount 
    } = req.body;

    if (!customerName || !phone || !email || !address || !items || !totalAmount) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields' 
      });
    }

    const Order = Parse.Object.extend('Orders');
    const order = new Order();
    
    const orderId = generateOrderId();
    
    order.set('orderId', orderId);
    order.set('customerName', customerName);
    order.set('phone', phone);
    order.set('email', email);
    order.set('address', address);
    order.set('note', note || '');
    order.set('paymentMethod', paymentMethod || '');
    order.set('items', items);
    order.set('totalAmount', parseFloat(totalAmount));
    order.set('status', 'pending');
    order.set('receiptImage', null);

    await order.save();

    res.status(201).json({
      success: true,
      order: {
        orderId,
        customerName,
        phone,
        email,
        address,
        note,
        paymentMethod,
        items,
        totalAmount,
        status: 'pending',
        createdAt: order.get('createdAt')
      }
    });

  } catch (error) {
    console.error('Create order error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create order. Please try again.' 
    });
  }
});

// Admin: Get orders (with date filter)
app.get('/api/admin/orders', async (req, res) => {
  try {
    // Admin auth check
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Basic ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');
    
    if (username !== process.env.ADMIN_USERNAME || password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { date } = req.query; // YYYY-MM-DD
    
    const Order = Parse.Object.extend('Orders');
    const query = new Parse.Query(Order);
    
    if (date) {
      const startDate = new Date(date);
      startDate.setHours(0, 0, 0, 0);
      const endDate = new Date(date);
      endDate.setHours(23, 59, 59, 999);
      
      query.greaterThanOrEqualTo('createdAt', startDate);
      query.lessThanOrEqualTo('createdAt', endDate);
    }
    
    query.descending('createdAt');
    
    const results = await query.find();
    const orders = results.map(order => ({
      id: order.id,
      orderId: order.get('orderId'),
      customerName: order.get('customerName'),
      phone: order.get('phone'),
      email: order.get('email'),
      address: order.get('address'),
      note: order.get('note'),
      paymentMethod: order.get('paymentMethod'),
      items: order.get('items'),
      totalAmount: order.get('totalAmount'),
      status: order.get('status'),
      receiptImage: order.get('receiptImage') ? {
        url: order.get('receiptImage').url(),
        name: order.get('receiptImage')._name
      } : null,
      createdAt: order.get('createdAt')
    }));
    
    res.json({ success: true, orders });
  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch orders' });
  }
});

// Admin: Update order status
app.put('/api/admin/orders/:orderId', async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status } = req.body;

    // Admin auth check
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Basic ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');
    
    if (username !== process.env.ADMIN_USERNAME || password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const Order = Parse.Object.extend('Orders');
    const query = new Parse.Query(Order);
    query.equalTo('orderId', orderId);
    
    const order = await query.first();
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    order.set('status', status);
    await order.save();

    // If approved, send approval email to customer
    if (status === 'approved') {
      const customerEmail = order.get('email');
      if (customerEmail) {
        await sendApprovalEmail(order, customerEmail);
      }
    }

    res.json({ 
      success: true, 
      message: `Order ${orderId} status updated to ${status}` 
    });
  } catch (error) {
    console.error('Update order error:', error);
    res.status(500).json({ success: false, error: 'Failed to update order' });
  }
});

// ============================================
// API ROUTES - Receipt Upload
// ============================================

const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

app.post('/api/upload-receipt', upload.single('receipt'), async (req, res) => {
  try {
    const { orderId } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    if (!orderId) {
      return res.status(400).json({ error: 'Order ID is required' });
    }

    const Order = Parse.Object.extend('Orders');
    const query = new Parse.Query(Order);
    query.equalTo('orderId', orderId);
    
    const order = await query.first();
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const parseFile = new Parse.File(
      `receipt_${orderId}_${Date.now()}.${req.file.originalname.split('.').pop()}`,
      req.file.buffer,
      req.file.mimetype
    );
    
    await parseFile.save();
    
    order.set('receiptImage', parseFile);
    await order.save();

    res.json({ 
      success: true, 
      message: 'Receipt uploaded successfully',
      fileUrl: parseFile.url()
    });

  } catch (error) {
    console.error('Upload receipt error:', error);
    res.status(500).json({ success: false, error: 'Failed to upload receipt' });
  }
});

// ============================================
// EMAIL FUNCTIONS
// ============================================

// Send approval email to customer
async function sendApprovalEmail(order, customerEmail) {
  try {
    const items = order.get('items') || [];
    const totalItems = items.reduce((sum, item) => sum + item.quantity, 0);
    
    const mailOptions = {
      from: `"Neko Anime Shop" <${process.env.EMAIL_USER}>`,
      to: customerEmail,
      subject: `သင့်အော်ဒါ အတည်ပြုပြီးပါပြီ - ${order.get('orderId')}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <h2 style="color: #2D7D9A; text-align: center;">Neko Anime Shop</h2>
          <h3 style="text-align: center; color: #27ae60;">အော်ဒါ အတည်ပြုပြီးပါပြီ! ✅</h3>
          
          <p><strong>အော်ဒါအမှတ်:</strong> ${order.get('orderId')}</p>
          <p><strong>အခြေအနေ:</strong> <span style="color: #27ae60; font-weight: bold;">Approved</span></p>
          
          <hr style="border: 1px solid #e0e0e0; margin: 20px 0;">
          
          <p style="font-size: 16px;">သင့်အော်ဒါကို အတည်ပြုပြီးပါပြီ။ ပစ္စည်းများကို စတင်ပို့ဆောင်ပါမည်။</p>
          <p style="font-size: 16px;">ပစ္စည်းရောက်ရှိပါက ထပ်မံအကြောင်းကြားပါမည်။</p>
          
          <hr style="border: 1px solid #e0e0e0; margin: 20px 0;">
          
          <h4>အော်ဒါအကျဉ်းချုပ်</h4>
          <p><strong>ပစ္စည်းစုစုပေါင်း:</strong> ${totalItems} ခု</p>
          <p><strong>စုစုပေါင်းဈေး:</strong> ${formatPrice(order.get('totalAmount'))} ကျပ်</p>
          
          <hr style="border: 1px solid #e0e0e0; margin: 20px 0;">
          
          <div style="background: #f9f9f9; padding: 15px; border-radius: 6px; text-align: center;">
            <p style="margin: 0;">အကူအညီလိုအပ်ပါက ကျွန်ုပ်တို့ကို ဆက်သွယ်ပါ။</p>
            <p style="margin: 5px 0; color: #2D7D9A;">📞 09-123456789</p>
          </div>
          
          <p style="text-align: center; color: #777; font-size: 14px; margin-top: 20px;">
            Neko Anime Shop မှ ကျေးဇူးတင်ပါတယ်။
          </p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Approval email sent to ${customerEmail}`);
    return true;
  } catch (error) {
    console.error('Send approval email error:', error);
    return false;
  }
}

// ============================================
// DAILY REPORT & ARCHIVE SYSTEM (Cron Job)
// ============================================

// Run at 11:59 PM every day
cron.schedule(process.env.DAILY_REPORT_CRON || '59 23 * * *', async () => {
  console.log('🔄 Running daily order summary and cleanup...');
  
  try {
    // 1. Get today's orders
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    const Order = Parse.Object.extend('Orders');
    const query = new Parse.Query(Order);
    query.greaterThanOrEqualTo('createdAt', today);
    query.lessThan('createdAt', tomorrow);
    query.ascending('createdAt');
    
    const orders = await query.find();
    
    if (orders.length === 0) {
      console.log('📭 No orders today. Skipping email.');
      return;
    }
    
    // 2. Prepare summary data
    const totalOrders = orders.length;
    const totalAmount = orders.reduce((sum, order) => sum + order.get('totalAmount'), 0);
    const pendingOrders = orders.filter(o => o.get('status') === 'pending').length;
    const approvedOrders = orders.filter(o => o.get('status') === 'approved').length;
    const rejectedOrders = orders.filter(o => o.get('status') === 'rejected').length;
    
    // 3. Build email HTML
    let ordersHtml = '';
    orders.forEach((order, index) => {
      const items = order.get('items') || [];
      const itemsHtml = items.map(item => 
        `${item.name} (x${item.quantity}) - ${formatPrice(item.price)} ကျပ်`
      ).join('<br>');
      
      const receiptUrl = order.get('receiptImage') 
        ? order.get('receiptImage').url() 
        : 'မရှိသေးပါ';
      
      ordersHtml += `
        <div style="border: 1px solid #ddd; border-radius: 8px; padding: 15px; margin-bottom: 20px; background: #f9f9f9;">
          <h4 style="color: #2D7D9A; margin: 0 0 10px 0;">#${index + 1}. ${order.get('orderId')}</h4>
          <table style="width: 100%; border-collapse: collapse;">
            <tr><td style="padding: 4px 0; width: 120px; font-weight: bold;">အမည်:</td><td style="padding: 4px 0;">${order.get('customerName')}</td></tr>
            <tr><td style="padding: 4px 0; font-weight: bold;">ဖုန်း:</td><td style="padding: 4px 0;">${order.get('phone')}</td></tr>
            <tr><td style="padding: 4px 0; font-weight: bold;">အီးမေးလ်:</td><td style="padding: 4px 0;">${order.get('email') || 'မရှိပါ'}</td></tr>
            <tr><td style="padding: 4px 0; font-weight: bold;">လိပ်စာ:</td><td style="padding: 4px 0;">${order.get('address')}</td></tr>
            <tr><td style="padding: 4px 0; font-weight: bold;">ငွေပေးချေမှု:</td><td style="padding: 4px 0;">${order.get('paymentMethod') || 'မရွေးရသေးပါ'}</td></tr>
            <tr><td style="padding: 4px 0; font-weight: bold;">အခြေအနေ:</td><td style="padding: 4px 0;">
              <span style="color: ${order.get('status') === 'approved' ? '#27ae60' : order.get('status') === 'rejected' ? '#e74c3c' : '#f39c12'}; font-weight: bold;">
                ${order.get('status')}
              </span>
            </td></tr>
            <tr><td style="padding: 4px 0; font-weight: bold;">ပစ္စည်းများ:</td><td style="padding: 4px 0;">${itemsHtml}</td></tr>
            <tr><td style="padding: 4px 0; font-weight: bold;">စုစုပေါင်း:</td><td style="padding: 4px 0; font-size: 16px; font-weight: bold; color: #2D7D9A;">${formatPrice(order.get('totalAmount'))} ကျပ်</td></tr>
            ${order.get('receiptImage') ? `
              <tr><td style="padding: 4px 0; font-weight: bold;">ပြေစာပုံ:</td><td style="padding: 4px 0;"><a href="${receiptUrl}" target="_blank" style="color: #2D7D9A;">ကြည့်ရန်</a></td></tr>
            ` : ''}
          </table>
        </div>
      `;
    });
    
    // 4. Send daily report email
    const dateStr = today.toLocaleDateString('my-MM', { 
      year: 'numeric', 
      month: 'long', 
      day: 'numeric' 
    });
    
    const mailOptions = {
      from: `"Neko Anime Shop Daily Report" <${process.env.EMAIL_USER}>`,
      to: process.env.ADMIN_EMAIL,
      subject: `📊 နေ့စဉ် အော်ဒါအစီရင်ခံစာ - ${dateStr}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <div style="text-align: center; margin-bottom: 30px;">
            <h2 style="color: #2D7D9A; margin: 0;">Neko Anime Shop</h2>
            <h3 style="color: #555; margin: 5px 0;">နေ့စဉ် အော်ဒါအစီရင်ခံစာ</h3>
            <p style="color: #777; font-size: 14px;">${dateStr}</p>
          </div>
          
          <div style="display: flex; justify-content: space-between; background: #2D7D9A; color: white; padding: 15px; border-radius: 8px; margin-bottom: 30px;">
            <div style="text-align: center; flex: 1;">
              <div style="font-size: 24px; font-weight: bold;">${totalOrders}</div>
              <div style="font-size: 12px;">စုစုပေါင်းအော်ဒါ</div>
            </div>
            <div style="text-align: center; flex: 1; border-left: 1px solid rgba(255,255,255,0.3); border-right: 1px solid rgba(255,255,255,0.3);">
              <div style="font-size: 24px; font-weight: bold;">${pendingOrders}</div>
              <div style="font-size: 12px;">Pending</div>
            </div>
            <div style="text-align: center; flex: 1;">
              <div style="font-size: 24px; font-weight: bold;">${approvedOrders}</div>
              <div style="font-size: 12px;">Approved</div>
            </div>
            <div style="text-align: center; flex: 1; border-left: 1px solid rgba(255,255,255,0.3);">
              <div style="font-size: 24px; font-weight: bold;">${rejectedOrders}</div>
              <div style="font-size: 12px;">Rejected</div>
            </div>
          </div>
          
          <div style="background: #f0f8ff; padding: 15px; border-radius: 8px; margin-bottom: 30px; text-align: center;">
            <h4 style="margin: 0; color: #2D7D9A;">စုစုပေါင်းဝင်ငွေ</h4>
            <h2 style="margin: 10px 0; font-size: 32px; color: #27ae60;">${formatPrice(totalAmount)} ကျပ်</h2>
          </div>
          
          <h4 style="border-bottom: 2px solid #2D7D9A; padding-bottom: 10px;">အော်ဒါစာရင်းအသေးစိတ်</h4>
          ${ordersHtml}
          
          <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #777; font-size: 13px;">
            <p>ဒီနေ့အတွက် အော်ဒါစာရင်း အကုန်အစုံကို ပို့ပေးလိုက်ပါတယ်။</p>
            <p>Website မှ အော်ဒါအားလုံးကို Archive သိမ်းပြီးပါပြီ။ နေ့သစ်အတွက် အဆင်သင့်ဖြစ်ပါပြီ။</p>
            <p style="font-size: 12px; color: #aaa;">Neko Anime Shop System</p>
          </div>
        </div>
      `
    };
    
    await transporter.sendMail(mailOptions);
    console.log(`✅ Daily report email sent! ${totalOrders} orders summarized.`);
    
    // 5. Archive orders (move to ArchiveOrders table, then delete from Orders)
    await archiveOrders(orders);
    
  } catch (error) {
    console.error('❌ Daily report error:', error);
  }
});

// ============================================
// ARCHIVE FUNCTION
// ============================================

async function archiveOrders(orders) {
  try {
    // Create ArchiveOrders class if not exists
    const ArchiveOrder = Parse.Object.extend('ArchiveOrders');
    
    const archivePromises = orders.map(async (order) => {
      const archive = new ArchiveOrder();
      archive.set('orderId', order.get('orderId'));
      archive.set('customerName', order.get('customerName'));
      archive.set('phone', order.get('phone'));
      archive.set('email', order.get('email'));
     archive.set('address', order.get('address'));
      archive.set('note', order.get('note'));
      archive.set('paymentMethod', order.get('paymentMethod'));
      archive.set('items', order.get('items'));
      archive.set('totalAmount', order.get('totalAmount'));
      archive.set('status', order.get('status'));
      archive.set('receiptImage', order.get('receiptImage'));
      archive.set('originalCreatedAt', order.get('createdAt'));
      archive.set('archivedAt', new Date());
      return archive.save();
    });
    
    await Promise.all(archivePromises);
    
    // Delete from Orders table
    await Parse.Object.destroyAll(orders);
    
    console.log(`📦 ${orders.length} orders archived and cleared from Orders table.`);
  } catch (error) {
    console.error('Archive error:', error);
    throw error;
  }
}

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`🚀 Neko Anime Shop server running on port ${PORT}`);
  console.log(`📧 Daily report will run at 11:59 PM every day`);
  console.log(`📍 http://localhost:${PORT}`);
});