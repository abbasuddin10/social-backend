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
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = 'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, created_at';
    const values = [email, hashedPassword];
    
    const result = await pool.query(query, values);
    
    res.status(201).json({
      success: true,
      message: 'অ্যাকাউন্ট সফলভাবে তৈরি এবং Neon ডাটাবেজে সেভ হয়েছে!',
      user: result.rows[0]
    });
  } catch (err) {
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
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'ইউজার পাওয়া যায়নি!' });
    }

    const user = result.rows[0];

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

// ৪. ফেসবুক কলব্যাক রাউট (Long-lived Token এবং Neon DB তে সেভ করার লজিক সহ)
app.get('/auth/facebook/callback', async (req, res) => {
    const code = req.query.code;
    if (!code) {
        return res.status(400).send('Authorization code not found!');
    }

    try {
        const appId = process.env.FACEBOOK_APP_ID;
        const appSecret = process.env.FACEBOOK_APP_SECRET;
        const redirectUri = `${process.env.BACKEND_URL}/auth/facebook/callback`;

        // ক. শর্ট-লাইভ অ্যাক্সেস টোকেন পাওয়ার জন্য গ্রাফ এপিআই কল
        const tokenUrl = `https://graph.facebook.com/v18.0/oauth/access_token?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&client_secret=${appSecret}&code=${code}`;
        const tokenResponse = await axios.get(tokenUrl);
        const shortLivedToken = tokenResponse.data.access_token;

        // খ. শর্ট-লাইভ টোকেনকে লং-লাইভ টোকেনে (৬০ দিন মেয়াদী) কনভার্ট করা
        const longLivedUrl = `https://graph.facebook.com/v18.0/oauth/access_token?grant_type=fb_exchange_token&client_id=${appId}&client_secret=${appSecret}&fb_exchange_token=${shortLivedToken}`;
        const longLivedResponse = await axios.get(longLivedUrl);
        const longLivedAccessToken = longLivedResponse.data.access_token;

        // গ. লং-লাইভ টোকেন ব্যবহার করে পেজগুলোর লিস্ট ফেচ করা
        const pagesUrl = `https://graph.facebook.com/v18.0/me/accounts?access_token=${longLivedAccessToken}`;
        const pagesResponse = await axios.get(pagesUrl);
        const pages = pagesResponse.data.data;

        // ঘ. (ঐচ্ছিক/প্রয়োজনীয়) Neon ডাটাবেজে পেজ ও টোকেন সেভ করার কোড
        // নোট: আপনার ডাটাবেজে facebook_pages টেবিল থাকতে হবে (page_id, page_name, access_token)
        for (const page of pages) {
            const dbQuery = `
                INSERT INTO facebook_pages (page_id, page_name, access_token) 
                VALUES ($1, $2, $3) 
                ON CONFLICT (page_id) 
                DO UPDATE SET page_name = $2, access_token = $3
            `;
            await pool.query(dbQuery, [page.id, page.name, page.access_token]);
        }

        res.json({
            success: true,
            message: "Successfully upgraded to Long-lived Token, fetched pages, and saved to Neon DB!",
            longLivedAccessToken: longLivedAccessToken,
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