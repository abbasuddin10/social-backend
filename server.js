const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();

// মিডলওয়্যার
app.use(express.json());
app.use(cors());

// রেন্ডার ড্যাশবোর্ডের Environment Variable থেকে স্বয়ংক্রিয়ভাবে Neon ডাটাবেজ কানেকশন নেবে
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// সার্ভার ঠিকঠাক চলছে কি না তা টেস্ট করার টেস্ট রুট
app.get('/', (req, res) => {
  res.send('Node.js Backend Server with Neon DB is running!');
});

// ১. রেজিস্ট্রেশন এপিআই (Register Endpoint)
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'ইমেইল এবং পাসওয়ার্ড আবশ্যক!' });
  }

  try {
    // পাসওয়ার্ড সিকিউর বা হ্যাশ (Hash) করা
    const hashedPassword = await bcrypt.hash(password, 10);

    // Neon ডাটাবেজে ডাটা ইনসার্ট করা
    const query = 'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, created_at';
    const values = [email, hashedPassword];
    
    const result = await pool.query(query, values);
    
    res.status(201).json({
      success: true,
      message: 'অ্যাকাউন্ট সফলভাবে তৈরি এবং Neon ডাটাবেজে সেভ হয়েছে!',
      user: result.rows[0]
    });
  } catch (err) {
    // ডুপ্লিকেট ইমেল দিলে এরর হ্যান্ডলিং (PostgreSQL code 23505)
    if (err.code === '23505') {
      return res.status(400).json({ success: false, message: 'এই ইমেইল দিয়ে ইতোমধ্যে অ্যাকাউন্ট খোলা হয়েছে!' });
    }
    console.error('Register Error:', err);
    res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
  }
});

// ২. লগইন এপিআই (Login Endpoint)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'ইমেইল এবং পাসওয়ার্ড আবশ্যক!' });
  }

  try {
    // ডাটাবেজ থেকে ইউজার চেক করা
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'ইউজার পাওয়া যায়নি!' });
    }

    const user = result.rows[0];

    // পাসওয়ার্ড ভেরিফাই করা
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'পাসওয়ার্ড ভুল হয়েছে!' });
    }

    res.status(200).json({
      success: true,
      message: 'সফলভাবে লগইন হয়েছে!',
      user: { id: user.id, email: user.email }
    });
  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
  }
});

// সার্ভার পোর্ট কনফিগারেশন (রেন্ডার এবং লোকাল উভয় জায়গার জন্য)
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`=================================`);
  console.log(`সার্ভার সফলভাবে পোর্ট ${PORT}-এ রান হচ্ছে!`);
  console.log(`=================================`);
});