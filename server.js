/**
 * NaijaEarn Hub - Backend Server (Node.js / Express)
 * 
 * Run: node server.js
 * Deploy: Vercel, Render, Railway, or any Node.js host
 * 
 * In production: replace localStorage (frontend) with this API
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ===== MIDDLEWARE =====
app.use(express.json());
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.use(express.static(path.join(__dirname)));

// ===== RATE LIMITING =====
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many attempts. Please try again later.' }
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 60,
  message: { error: 'Rate limit exceeded.' }
});

app.use('/api/auth', authLimiter);
app.use('/api/', apiLimiter);

// ===== DATABASE (JSON FILE — swap for MongoDB in production) =====
const DB_PATH = path.join(__dirname, 'data', 'users.json');
const WITHDRAWALS_PATH = path.join(__dirname, 'data', 'withdrawals.json');

// Ensure data directory exists
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'));
}

function readDB(filePath, fallback = []) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeDB(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

// ===== JWT AUTH =====
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_SECRET_IN_PRODUCTION';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'; // CHANGE IN PRODUCTION

function generateToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function adminMiddleware(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_PASSWORD) return res.status(403).json({ error: 'Admin access denied' });
  next();
}

// ===== HELPERS =====
function generateRefCode(name) {
  return name.split(' ')[0].toLowerCase().replace(/[^a-z]/g, '') +
    Math.floor(1000 + Math.random() * 9000);
}

function isSameDay(date1, date2) {
  return date1.getFullYear() === date2.getFullYear() &&
    date1.getMonth() === date2.getMonth() &&
    date1.getDate() === date2.getDate();
}

// ===== AUTH ROUTES =====

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, phone, password, refCode } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const users = readDB(DB_PATH);

    // Check email exists
    if (users.find(u => u.email === email.toLowerCase())) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Anti-fraud: check IP
    const userIP = req.ip || req.connection.remoteAddress;
    const ipCount = users.filter(u => u.registrationIP === userIP).length;
    if (ipCount >= 3) {
      return res.status(429).json({ error: 'Too many accounts from this network' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const myRefCode = generateRefCode(name);

    const user = {
      id: Date.now().toString() + Math.random().toString(36).substr(2, 5),
      name: name.trim(),
      email: email.toLowerCase().trim(),
      phone: phone || '',
      password: hashedPassword,
      refCode: myRefCode,
      referredBy: refCode || null,
      balance: 200, // Signup bonus
      referralCount: 0,
      dailyBonusClaimed: false,
      lastLoginDate: new Date().toISOString(),
      joinedAt: new Date().toISOString(),
      completedTasks: [],
      history: [{ type: 'signup', desc: 'Welcome Bonus', amount: 200, date: new Date().toISOString() }],
      withdrawals: [],
      registrationIP: userIP,
      status: 'active'
    };

    users.push(user);

    // Credit referrer
    if (refCode) {
      const refIdx = users.findIndex(u => u.refCode === refCode && u.email !== user.email);
      if (refIdx !== -1) {
        users[refIdx].balance += 200;
        users[refIdx].referralCount += 1;
        users[refIdx].history.unshift({
          type: 'referral',
          desc: `Referral: ${user.name}`,
          amount: 200,
          date: new Date().toISOString()
        });
      }
    }

    writeDB(DB_PATH, users);

    const token = generateToken(user.id);

    // Return user without sensitive fields
    const { password: _, registrationIP: __, ...safeUser } = user;
    res.status(201).json({ token, user: safeUser });

  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const users = readDB(DB_PATH);
    const userIdx = users.findIndex(u => u.email === email.toLowerCase());

    if (userIdx === -1 || !(await bcrypt.compare(password, users[userIdx].password))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (users[userIdx].status === 'suspended') {
      return res.status(403).json({ error: 'Account suspended. Contact support.' });
    }

    // Daily bonus
    const lastLogin = new Date(users[userIdx].lastLoginDate || 0);
    const today = new Date();
    const dailyBonusEarned = !isSameDay(lastLogin, today);

    if (dailyBonusEarned) {
      users[userIdx].balance += 20;
      users[userIdx].history.unshift({ type: 'bonus', desc: 'Daily Login Bonus', amount: 20, date: today.toISOString() });
    }

    users[userIdx].lastLoginDate = today.toISOString();
    users[userIdx].dailyBonusClaimed = dailyBonusEarned;
    writeDB(DB_PATH, users);

    const token = generateToken(users[userIdx].id);
    const { password: _, registrationIP: __, ...safeUser } = users[userIdx];

    res.json({ token, user: safeUser, dailyBonusEarned, dailyBonusAmount: 20 });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ===== USER ROUTES =====

// GET /api/user/profile
app.get('/api/user/profile', authMiddleware, (req, res) => {
  const users = readDB(DB_PATH);
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password: _, registrationIP: __, ...safeUser } = user;
  res.json(safeUser);
});

// POST /api/user/complete-task
app.post('/api/user/complete-task', authMiddleware, (req, res) => {
  const { taskId, reward } = req.body;
  if (!taskId || !reward) return res.status(400).json({ error: 'Task ID and reward required' });

  const VALID_TASKS = { task_view1: 50, task_view2: 50, task_view3: 50, task_view4: 50 };
  if (!VALID_TASKS[taskId]) return res.status(400).json({ error: 'Invalid task' });

  const users = readDB(DB_PATH);
  const idx = users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });

  if (users[idx].completedTasks.includes(taskId)) {
    return res.status(409).json({ error: 'Task already completed' });
  }

  const taskReward = VALID_TASKS[taskId];
  users[idx].completedTasks.push(taskId);
  users[idx].balance += taskReward;
  users[idx].history.unshift({ type: 'task', desc: 'Sponsored Content Task', amount: taskReward, date: new Date().toISOString() });
  writeDB(DB_PATH, users);

  res.json({ success: true, earned: taskReward, newBalance: users[idx].balance });
});

// POST /api/user/withdraw
app.post('/api/user/withdraw', authMiddleware, (req, res) => {
  const { bank, accountNumber, accountName, amount } = req.body;

  if (!bank || !accountNumber || !accountName || !amount) {
    return res.status(400).json({ error: 'All withdrawal fields are required' });
  }

  if (accountNumber.length !== 10) {
    return res.status(400).json({ error: 'Account number must be 10 digits' });
  }

  if (amount < 2000) {
    return res.status(400).json({ error: 'Minimum withdrawal is ₦2,000' });
  }

  const users = readDB(DB_PATH);
  const idx = users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });

  if (users[idx].balance < amount) {
    return res.status(400).json({ error: 'Insufficient balance' });
  }

  const withdrawalId = Date.now().toString();
  const withdrawal = {
    id: withdrawalId,
    userId: users[idx].id,
    userName: users[idx].name,
    bank, accountNumber, accountName, amount,
    status: 'pending',
    requestedAt: new Date().toISOString()
  };

  users[idx].balance -= amount;
  users[idx].withdrawals.push(withdrawal);
  users[idx].history.unshift({ type: 'withdrawal', desc: `Withdrawal - ${bank}`, amount: -amount, date: new Date().toISOString() });

  // Also store in withdrawals DB
  const withdrawals = readDB(WITHDRAWALS_PATH);
  withdrawals.push(withdrawal);
  writeDB(WITHDRAWALS_PATH, withdrawals);
  writeDB(DB_PATH, users);

  res.json({ success: true, withdrawalId, newBalance: users[idx].balance });
});

// ===== ADMIN ROUTES =====

// GET /api/admin/users
app.get('/api/admin/users', adminMiddleware, (req, res) => {
  const users = readDB(DB_PATH).map(({ password: _, registrationIP: __, ...u }) => u);
  res.json(users);
});

// GET /api/admin/withdrawals
app.get('/api/admin/withdrawals', adminMiddleware, (req, res) => {
  res.json(readDB(WITHDRAWALS_PATH));
});

// POST /api/admin/withdrawal/action
app.post('/api/admin/withdrawal/action', adminMiddleware, (req, res) => {
  const { userId, withdrawalId, action } = req.body;
  if (!['approved', 'rejected'].includes(action)) return res.status(400).json({ error: 'Invalid action' });

  const users = readDB(DB_PATH);
  const withdrawals = readDB(WITHDRAWALS_PATH);

  const userIdx = users.findIndex(u => u.id === userId);
  if (userIdx === -1) return res.status(404).json({ error: 'User not found' });

  const wIdx = users[userIdx].withdrawals.findIndex(w => w.id === withdrawalId);
  if (wIdx === -1) return res.status(404).json({ error: 'Withdrawal not found' });

  if (action === 'rejected') {
    // Refund
    users[userIdx].balance += users[userIdx].withdrawals[wIdx].amount;
    users[userIdx].history.unshift({
      type: 'refund', desc: 'Withdrawal Rejected - Refunded',
      amount: users[userIdx].withdrawals[wIdx].amount, date: new Date().toISOString()
    });
  }

  users[userIdx].withdrawals[wIdx].status = action;
  users[userIdx].withdrawals[wIdx].processedAt = new Date().toISOString();

  // Update global withdrawals
  const gwIdx = withdrawals.findIndex(w => w.id === withdrawalId);
  if (gwIdx !== -1) { withdrawals[gwIdx].status = action; }

  writeDB(DB_PATH, users);
  writeDB(WITHDRAWALS_PATH, withdrawals);

  res.json({ success: true });
});

// POST /api/admin/adjust-balance
app.post('/api/admin/adjust-balance', adminMiddleware, (req, res) => {
  const { userId, action, amount, reason } = req.body;
  const users = readDB(DB_PATH);
  const idx = users.findIndex(u => u.id === userId);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });

  const before = users[idx].balance;
  if (action === 'add') users[idx].balance += amount;
  else if (action === 'deduct') users[idx].balance = Math.max(0, users[idx].balance - amount);
  else if (action === 'set') users[idx].balance = amount;

  users[idx].history.unshift({ type: 'admin', desc: `Admin: ${reason || 'Manual adjustment'}`, amount: users[idx].balance - before, date: new Date().toISOString() });
  writeDB(DB_PATH, users);

  res.json({ success: true, oldBalance: before, newBalance: users[idx].balance });
});

// ===== SERVE FRONTEND =====
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ===== START SERVER =====
app.listen(PORT, () => {
  console.log(`\n🚀 NaijaEarn Hub server running on port ${PORT}`);
  console.log(`📱 Visit: http://localhost:${PORT}`);
  console.log(`🛡️  Admin: http://localhost:${PORT}/admin.html`);
  console.log(`\n⚠️  Remember to:`);
  console.log(`   1. Change ADMIN_PASSWORD in .env`);
  console.log(`   2. Set a strong JWT_SECRET in .env`);
  console.log(`   3. Replace JSON DB with MongoDB in production`);
});
