const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
const axios = require('axios'); // ফেসবুক এপিআই কল করার জন্য এটি দরকার হবে

const app = express();

// মিডলওয়্যার
app.use(express.json());
app.use(cors());

// রেন্ডার ড্যাশবোর্ডের Environment Variable থেকে স্বয়ংক্রিয়ভাবে Neon ডাটাবেজ কানেকশন নেবে
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

// ৩. ফেসবুক লগইন রিডাইরেক্ট রাউট (Facebook Auth Route)
app.get('/auth/facebook', (req, res) => {
    const appId = process.env.FACEBOOK_APP_ID;
    const redirectUri = `${process.env.BACKEND_URL}/auth/facebook/callback`;
    const fbLoginUrl = `https://www.facebook.com/v18.0/dialog/oauth?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=pages_show_list,pages_manage_posts,pages_read_engagement`;
    res.redirect(fbLoginUrl);
});

// ৪. ফেসবুক কলব্যাক রাউট (Facebook Callback Route)
app.get('/auth/facebook/callback', async (req, res) => {
    const code = req.query.code;
    if (!code) {
        return res.status(400).send('Authorization code not found!');
    }

    try {
        const appId = process.env.FACEBOOK_APP_ID;
        const appSecret = process.env.FACEBOOK_APP_SECRET;
        const redirectUri = `${process.env.BACKEND_URL}/auth/facebook/callback`;

        // অ্যাক্সেস টোকেন পাওয়ার জন্য ফেসবুক গ্রাফ এপিআই কল
        const tokenUrl = `https://graph.facebook.com/v18.0/oauth/access_token?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&client_secret=${appSecret}&code=${code}`;
        
        const tokenResponse = await axios.get(tokenUrl);
        const accessToken = tokenResponse.data.access_token;

        // ইউজারের পেজগুলোর লিস্ট এবং পেজ টোকেন ফেচ করা
        const pagesUrl = `https://graph.facebook.com/v18.0/me/accounts?access_token=${accessToken}`;
        const pagesResponse = await axios.get(pagesUrl);
        const pages = pagesResponse.data.data;

        // সাময়িকভাবে রেসপন্স দেখছি (পরে এগুলো ডাটাবেজে সেভ করব)
        res.json({
            success: true,
            message: "Facebook Connected Successfully!",
            accessToken: accessToken,
            pages: pages
        });

    } catch (error) {
        console.error("Facebook Auth Error:", error.response?.data || error.message);
        res.status(500).send('Authentication failed!');
    }
});

// সার্ভার পোর্ট কনফিগারেশন (রেন্ডার এবং লোকাল উভয় জায়গার জন্য)
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`=================================`);
  console.log(`সার্ভার সফলভাবে পোর্ট ${PORT}-এ রান হচ্ছে!`);
  console.log(`=================================`);
});