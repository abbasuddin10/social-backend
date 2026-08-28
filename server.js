const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const axios = require('axios');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const { createClient } = require('@supabase/supabase-js');
const { OAuth2Client } = require('google-auth-library');
const { GoogleGenAI } = require('@google/genai');

// 🚀 Initialize Gemini Client
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

const app = express();

app.use(express.json());
app.use(cors());
app.use('/uploads', express.static('uploads'));

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// 🚀 Supabase Client
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = (SUPABASE_URL && SUPABASE_KEY) ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;

// 🗄️ Neon Postgres Pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secure_secret_key_123';

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'অথেন্টিকেশন টোকেন পাওয়া যায়নি!' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'ইনভ্যালিড বা এক্সপায়ার্ড টোকেন!' });
        }
        req.user = user;
        next();
    });
};

app.get('/', (req, res) => {
    res.send('Node.js Backend Server with Neon DB is running!');
});

// ==========================================
// 🔑 AUTHENTICATION ROUTES
// ==========================================

// ১. রেজিস্ট্রেশন এপিআই
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

        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '365d' });

        res.status(201).json({
            success: true,
            message: 'অ্যাকাউন্ট সফলভাবে তৈরি হয়েছে!',
            token: token,
            user: { id: user.id, email: user.email }
        });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ success: false, message: 'এই ইমেইল দিয়ে ইতোমধ্যে অ্যাকাউন্ট খোলা হয়েছে!' });
        }
        console.error('Register Error:', err);
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// ২. লগইন এপিআই
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

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '365d' });

        res.status(200).json({
            success: true,
            message: 'সফলভাবে লগইন হয়েছে!',
            token: token,
            user: { id: user.id, email: user.email }
        });
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// 🌐 ৩. গুগল লগইন এপিআই
app.post('/api/google-login', async (req, res) => {
    const { id_token } = req.body;

    if (!id_token) {
        return res.status(400).json({ success: false, message: 'Google Token আবশ্যক!' });
    }

    try {
        const ticket = await googleClient.verifyIdToken({
            idToken: id_token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const email = payload.email;

        let query = 'SELECT * FROM users WHERE email = $1';
        let result = await pool.query(query, [email]);
        let user;

        if (result.rows.length === 0) {
            const insertQuery = 'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email';
            const randomPassword = await bcrypt.hash(Math.random().toString(36), 10);
            const insertResult = await pool.query(insertQuery, [email, randomPassword]);
            user = insertResult.rows[0];
        } else {
            user = result.rows[0];
        }

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '365d' });

        res.status(200).json({
            success: true,
            message: 'Google দিয়ে লগইন সফল হয়েছে!',
            token: token,
            user: { id: user.id, email: user.email }
        });
    } catch (err) {
        console.error('Google Login Error:', err);
        res.status(500).json({ success: false, message: 'গুগল ভেরিফিকেশন ব্যর্থ হয়েছে: ' + err.message });
    }
});

// 📩 ৪. পাসওয়ার্ড রিসেটের জন্য OTP তৈরি এপিআই
app.post('/api/send-otp', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'ইমেইল আবশ্যক!' });
    }

    try {
        const userQuery = 'SELECT * FROM users WHERE email = $1';
        const userRes = await pool.query(userQuery, [email]);

        if (userRes.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'এই ইমেইলে কোনো অ্যাকাউন্ট পাওয়া যায়নি!' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        await pool.query('DELETE FROM email_otps WHERE email = $1', [email]);
        
        const insertOtpQuery = `
            INSERT INTO email_otps (email, otp, expires_at, created_at) 
            VALUES ($1, $2, $3, NOW())
        `;
        await pool.query(insertOtpQuery, [email, otp, expiresAt]);

        res.status(200).json({
            success: true,
            message: 'OTP সফলভাবে তৈরি হয়েছে! ইমেইল পাঠানো হচ্ছে...'
        });
    } catch (err) {
        console.error('Send OTP Error:', err);
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// 🔓 ৫. পাসওয়ার্ড রিসেট ভেরিফাই ও আপডেট
app.post('/api/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.status(400).json({ success: false, message: 'সবগুলো ঘর পূরণ করুন!' });
    }

    try {
        const query = 'SELECT * FROM email_otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()';
        const result = await pool.query(query, [email, otp]);

        if (result.rows.length === 0) {
            return res.status(400).json({ success: false, message: 'ভুল বা মেয়াদোত্তীর্ণ OTP কোড!' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);

        await pool.query('DELETE FROM email_otps WHERE email = $1', [email]);

        res.status(200).json({
            success: true,
            message: 'পাসওয়ার্ড সফলভাবে পরিবর্তন করা হয়েছে!'
        });
    } catch (err) {
        console.error('Reset Password Error:', err);
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// ==========================================
// 📘 FACEBOOK & INSTAGRAM AUTH ROUTES
// ==========================================
app.get('/auth/facebook', (req, res) => {
    const userId = req.query.user_id;

    if (!userId) {
        return res.status(400).send('❌ ত্রুটি: ফেসবুক কানেক্ট করার জন্য user_id পাঠানো বাধ্যতামূলক!');
    }

    const appId = process.env.FACEBOOK_APP_ID;
    const redirectUri = `${process.env.BACKEND_URL}/auth/facebook/callback`;
    const state = JSON.stringify({ user_id: userId });

    const scope = [
        'pages_show_list',
        'pages_manage_posts',
        'pages_read_engagement',
        'pages_read_user_content',
        'instagram_basic',
        'instagram_content_publish',
        'instagram_manage_comments'
    ].join(',');

    const fbLoginUrl = `https://www.facebook.com/v18.0/dialog/oauth?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&scope=${scope}`;
    res.redirect(fbLoginUrl);
});

// Facebook OAuth Callback Route
app.get('/auth/facebook/callback', async (req, res) => {
  const { code, state: userId } = req.query;

  try {
    // ১. OAuth Code দিয়ে User Access Token নেওয়া
    const tokenResponse = await axios.get('https://graph.facebook.com/v18.0/oauth/access_token', {
      params: {
        client_id: process.env.FB_CLIENT_ID,
        client_secret: process.env.FB_CLIENT_SECRET,
        redirect_uri: process.env.FB_REDIRECT_URI,
        code: code,
      },
    });

    const userAccessToken = tokenResponse.data.access_token;

    // ২. യൂজার সাথে সম্পর্কিত ফেসবুক পেজ এবং লিঙ্কড ইনস্টাগ্রাম একাউন্ট ফেচ করা
    const pagesResponse = await axios.get('https://graph.facebook.com/v18.0/me/accounts', {
      params: {
        fields: 'id,name,access_token,instagram_business_account',
        access_token: userAccessToken,
      },
    });

    const pages = pagesResponse.data.data;

    if (!pages || pages.length === 0) {
      return res.send(renderResponseHtml({
        title: '⚠️ কোনো ফেসবুক পেজ পাওয়া যায়নি!',
        message: 'আপনার ফেসবুক অ্যাকাউন্টে কোনো পাবলিক/বিজনেস পেজ নেই। অনুগ্রহ করে প্রথমে একটি পেজ তৈরি করুন।',
        status: 'warning'
      }));
    }

    // ৩. প্রথম পেজটির ডাটা নিয়ে প্রসেস করা (অথবা একাধিক পেজ থাকলে লুপ করা যায়)
    const primaryPage = pages[0];
    let isInstagramConnected = false;
    let instagramData = null;

    // 🎯 ফেসবুক পেজ সেভ/আপডেট (আপনার MongoDB/Database Logic)
    await Database.saveFacebookPage({
      userId: userId,
      pageId: primaryPage.id,
      pageName: primaryPage.name,
      accessToken: primaryPage.access_token,
      isConnected: true,
    });

    // 🎯 চেক করা এই পেজের সাথে Instagram Business Account লিঙ্ক করা আছে কিনা
    if (primaryPage.instagram_business_account) {
      const instagramAccountId = primaryPage.instagram_business_account.id;

      // ইনস্টাগ্রাম অ্যাকাউন্ট ফেচ করা
      const igResponse = await axios.get(`https://graph.facebook.com/v18.0/${instagramAccountId}`, {
        params: {
          fields: 'id,username,name,profile_picture_url',
          access_token: primaryPage.access_token,
        },
      });

      instagramData = igResponse.data;

      // ইনস্টাগ্রাম অ্যাকাউন্ট ডাটাবেজে সেভ
      await Database.saveInstagramAccount({
        userId: userId,
        instagramId: instagramData.id,
        username: instagramData.username,
        name: instagramData.name || instagramData.username,
        accessToken: primaryPage.access_token, // পেজ এক্সেস টোকেনই ইনস্টাগ্রামের জন্য ব্যবহৃত হয়
        isConnected: true,
      });

      isInstagramConnected = true;
    } else {
      // যদি ইনস্টাগ্রাম না থাকে, ডাটাবেজে ডিসকানেক্টেড ফ্ল্যাগ রেখে দেওয়া
      await Database.markInstagramDisconnected(userId);
    }

    // ৪. ইউজারের জন্য ডাইনামিক এবং সুন্দর HTML ব্রাউজার রেসপন্স
    const title = isInstagramConnected
      ? '🎉 ফেসবুক ও ইনস্টাগ্রাম সফলভাবে কানেক্ট হয়েছে!'
      : '✅ ফেসবুক পেজ কানেক্ট হয়েছে!';

    const message = isInstagramConnected
      ? `আপনার ফেসবুক পেজ <b>"${primaryPage.name}"</b> এবং ইনস্টাগ্রাম অ্যাকাউন্ট <b>"@${instagramData.username}"</b> সফলভাবে কানেক্ট করা হয়েছে।`
      : `আপনার ফেসবুক পেজ <b>"${primaryPage.name}"</b> কানেক্ট হয়েছে। তবে এই পেজের সাথে কোনো <b>Instagram Business Account</b> যুক্ত পাওয়া যায়নি।`;

    return res.send(renderResponseHtml({
      title,
      message,
      isInstagramConnected,
      status: 'success'
    }));

  } catch (error) {
    console.error('Facebook OAuth Error:', error.response?.data || error.message);
    return res.send(renderResponseHtml({
      title: '❌ সংযোগ ব্যর্থ হয়েছে!',
      message: 'ফেসবুক বা ইনস্টাগ্রাম অ্যাকাউন্ট কানেক্ট করার সময় কোনো সমস্যা হয়েছে। অনুগ্রহ করে আবার চেষ্টা করুন।',
      status: 'error'
    }));
  }
});


// 🎨 ব্রাউজারে দেখানোর জন্য ক্লিন UI থিম তৈরি করার হেল্পার ফাংশন
// 🎨 ব্রাউজারে দেখানোর জন্য ক্লিন UI থিম
function renderResponseHtml({ title, message, isInstagramConnected = false, status = 'success' }) {
  const isWarning = status === 'warning' || (status === 'success' && !isInstagramConnected);
  const badgeColor = isWarning ? '#FF9800' : status === 'error' ? '#F44336' : '#4CAF50';

  return `
    <!DOCTYPE html>
    <html lang="bn">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>PostPilot - Account Status</title>
      <style>
        body {
          font-family: 'Segoe UI', Roboto, sans-serif;
          background-color: #F4F6F8;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          margin: 0;
          padding: 20px 0;
        }
        .card {
          background: #ffffff;
          padding: 28px 24px;
          border-radius: 20px;
          box-shadow: 0 10px 25px rgba(0,0,0,0.08);
          text-align: center;
          max-width: 420px;
          width: 90%;
        }
        .icon {
          font-size: 45px;
          margin-bottom: 12px;
        }
        h2 {
          color: #1A1D1E;
          font-size: 19px;
          margin-bottom: 10px;
          line-height: 1.4;
        }
        p {
          color: #555;
          font-size: 13.5px;
          line-height: 1.5;
          margin-bottom: 16px;
        }
        .notice-box {
          background-color: #FFF8E7;
          border-left: 4px solid ${badgeColor};
          padding: 14px;
          border-radius: 10px;
          font-size: 13px;
          color: #333;
          text-align: left;
          margin-bottom: 20px;
        }
        .notice-title {
          font-weight: bold;
          color: #D97706;
          font-size: 14px;
          margin-bottom: 10px;
          display: flex;
          align-items: center;
          gap: 5px;
        }
        .steps-list {
          margin: 0;
          padding-left: 18px;
          line-height: 1.7;
        }
        .steps-list li {
          margin-bottom: 6px;
        }
        .footer-text {
          font-size: 13px;
          font-weight: 600;
          color: #6200EE;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="icon">${status === 'error' ? '❌' : isInstagramConnected ? '🎉' : '⚠️'}</div>
        <h2>${title}</h2>
        <p>${message}</p>
        
        ${!isInstagramConnected && status === 'success' ? `
          <div class="notice-box">
            <div class="notice-title">💡 সহজ ৪টি ধাপে ইনস্টাগ্রাম কানেক্ট করুন:</div>
            <ol class="steps-list">
              <li><strong>Instagram-এ প্রফেশনাল সুইচ করুন:</strong> Profile > Menu > Settings & Privacy > Account type-এ গিয়ে Professional করুন।</li>
              <li><strong>Facebook Page লিঙ্ক করুন:</strong> প্রসেসের সময় বা Edit Profile > Page থেকে আপনার পেজটি কানেক্ট করুন।</li>
              <li><strong>অনবোর্ডিং স্কিপ করুন:</strong> কোনো এক্সট্রা ৮টি স্টেপ পুরন করার দরকার নেই, সরাসরি ✕ কেটে দিন।</li>
              <li><strong>পুনরায় কানেক্ট দিন:</strong> অ্যাপে ফিরে এসে আবার Connect চাপুন।</li>
            </ol>
          </div>
        ` : ''}

        <div class="footer-text">এখন এই ব্রাউজার ট্যাবটি বন্ধ করে অ্যাপে ফিরে যান।</div>
      </div>
    </body>
    </html>
  `;
}

// ==========================================
// 💼 LINKEDIN AUTO REFRESH HELPER FUNCTION
// ==========================================
async function getValidLinkedinToken(userId) {
    try {
        const res = await pool.query(
            "SELECT access_token, refresh_token, expires_at FROM social_accounts WHERE user_id = $1 AND platform = 'linkedin' AND is_active = TRUE",
            [userId]
        );

        if (res.rows.length === 0) return null;
        const account = res.rows[0];

        // টোকেনের মেয়াদ শেষ হতে ৫ দিন বা তার কম বাকি থাকলে রিফ্রেশ করবে
        const isExpiringSoon = account.expires_at && (new Date(account.expires_at) - new Date() < 5 * 24 * 60 * 60 * 1000);

        if (isExpiringSoon && account.refresh_token) {
            try {
                const refreshRes = await axios.post('https://www.linkedin.com/oauth/v2/accessToken', null, {
                    params: {
                        grant_type: 'refresh_token',
                        refresh_token: account.refresh_token,
                        client_id: process.env.LINKEDIN_CLIENT_ID,
                        client_secret: process.env.LINKEDIN_CLIENT_SECRET,
                    },
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                });

                const newAccessToken = refreshRes.data.access_token;
                const newRefreshToken = refreshRes.data.refresh_token || account.refresh_token;
                const newExpiresAt = new Date(Date.now() + refreshRes.data.expires_in * 1000);

                await pool.query(
                    "UPDATE social_accounts SET access_token = $1, refresh_token = $2, expires_at = $3, updated_at = NOW() WHERE user_id = $4 AND platform = 'linkedin'",
                    [newAccessToken, newRefreshToken, newExpiresAt, userId]
                );

                return newAccessToken;
            } catch (e) {
                console.error('LinkedIn Refresh Failed:', e.response?.data || e.message);

                // ৪০১ বা ৪০৩ এরর দিলে পারমিশন বাতিলের কারণে ইজ এক্টিভ ফলস করে দেওয়া হবে
                if (e.response && (e.response.status === 401 || e.response.status === 403)) {
                    await pool.query(
                        "UPDATE social_accounts SET is_active = FALSE WHERE user_id = $1 AND platform = 'linkedin'",
                        [userId]
                    );
                }
                return account.access_token;
            }
        }

        return account.access_token;
    } catch (err) {
        console.error("Helper getValidLinkedinToken Error:", err);
        return null;
    }
}

// ==========================================
// 💼 LINKEDIN AUTH ROUTES (আপডেট করা হয়েছে)
// ==========================================
app.get('/auth/linkedin', (req, res) => {
    const userId = req.query.user_id;
    if (!userId) return res.status(400).send('❌ ত্রুটি: user_id প্রয়োজন!');

    const clientId = process.env.LINKEDIN_CLIENT_ID;
    const backendUrl = process.env.BACKEND_URL || 'https://social-backend-1hwz.onrender.com';

    if (!clientId) {
        return res.status(500).send('❌ ত্রুটি: সার্ভারে LINKEDIN_CLIENT_ID সেট করা নেই!');
    }

    const redirectUri = `${backendUrl}/auth/linkedin/callback`;
    const state = JSON.stringify({ user_id: userId });
    const scope = 'openid profile w_member_social email';

    const linkedinLoginUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&scope=${encodeURIComponent(scope)}`;
    res.redirect(linkedinLoginUrl);
});

app.get('/auth/linkedin/callback', async (req, res) => {
    const { code, state: stateStr } = req.query;
    let userId = null;

    try {
        if (stateStr) userId = JSON.parse(stateStr).user_id;
    } catch (e) { console.error("State parse error:", e); }

    if (!code || !userId) return res.status(400).send('❌ অথেন্টিকেশন কোড বা ইউজার আইডি পাওয়া যায়নি।');

    try {
        const clientId = process.env.LINKEDIN_CLIENT_ID;
        const clientSecret = process.env.LINKEDIN_CLIENT_SECRET;
        const backendUrl = process.env.BACKEND_URL || 'https://social-backend-1hwz.onrender.com';
        const redirectUri = `${backendUrl}/auth/linkedin/callback`;

        const tokenResponse = await axios.post(
            'https://www.linkedin.com/oauth/v2/accessToken',
            new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                client_id: clientId,
                client_secret: clientSecret,
                redirect_uri: redirectUri
            }).toString(),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        const accessToken = tokenResponse.data.access_token;
        const refreshToken = tokenResponse.data.refresh_token || null;
        const expiresIn = tokenResponse.data.expires_in || 5184000; // ৬০ দিনের ডিফল্ট হিসাব
        const expiresAt = new Date(Date.now() + expiresIn * 1000);

        const profileResponse = await axios.get('https://api.linkedin.com/v2/userinfo', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });

        const linkedinSub = profileResponse.data.sub;
        const profileName = profileResponse.data.name || 'LinkedIn User';

        const checkQuery = 'SELECT * FROM social_accounts WHERE page_id = $1 AND user_id = $2 AND platform = $3';
        const existing = await pool.query(checkQuery, [linkedinSub, userId, 'linkedin']);

        if (existing.rows.length > 0) {
            const updateQuery = 'UPDATE social_accounts SET access_token = $1, refresh_token = $2, expires_at = $3, page_name = $4, is_active = TRUE, updated_at = NOW() WHERE page_id = $5 AND user_id = $6 AND platform = $7';
            await pool.query(updateQuery, [accessToken, refreshToken, expiresAt, profileName, linkedinSub, userId, 'linkedin']);
        } else {
            const insertQuery = 'INSERT INTO social_accounts (user_id, page_id, page_name, access_token, refresh_token, expires_at, is_active, platform) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)';
            await pool.query(insertQuery, [userId, linkedinSub, profileName, accessToken, refreshToken, expiresAt, true, 'linkedin']);
        }

        res.send(`<html><body style="font-family: Arial; text-align: center; padding: 50px;"><h2>🎉 LinkedIn অ্যাকাউন্ট সফলভাবে কানেক্ট হয়েছে!</h2><p>ট্যাবটি বন্ধ করে অ্যাপে ফিরে যান।</p></body></html>`);
    } catch (error) {
        console.error("LinkedIn Auth Error:", error.response?.data || error.message);
        res.status(500).send('LinkedIn Authentication failed!');
    }
});

app.post('/api/post-to-facebook', authenticateToken, async (req, res) => {
    const { page_id, message } = req.body;
    const userId = req.user.id;

    try {
        const result = await pool.query('SELECT access_token FROM social_accounts WHERE page_id = $1 AND user_id = $2', [page_id, userId]);
        if (result.rows.length === 0) return res.status(404).send('Page not found or unauthorized!');

        const token = result.rows[0].access_token;
        const postUrl = `https://graph.facebook.com/v18.0/${page_id}/feed`;
        const response = await axios.post(postUrl, {
            message: message,
            access_token: token
        });

        res.json({ success: true, postId: response.data.id });
    } catch (error) {
        console.error("Post Error:", error.response?.data || error.message);
        res.status(500).json({ error: error.response?.data || error.message });
    }
});

// ==========================================
// 🚀 POST SAVING & SCHEDULING (WITH SUPABASE)
// ==========================================

const uploadSingleFile = async (file, userId, reqHost) => {
    try {
        if (supabase) {
            const fileStream = fs.readFileSync(file.path);
            const uniqueSuffix = Date.now() + '-' + Math.floor(Math.random() * 1E9);
            const fileName = `user-${userId}-${uniqueSuffix}.jpg`;

            const { data, error } = await supabase.storage
                .from('postimages')
                .upload(fileName, fileStream, {
                    contentType: file.mimetype,
                    upsert: true
                });

            if (error) {
                console.error('Supabase Upload Error:', error.message);
                return `https://${reqHost}/uploads/${file.filename}`;
            } else {
                const { data: publicUrlData } = supabase.storage
                    .from('postimages')
                    .getPublicUrl(fileName);
                return publicUrlData.publicUrl;
            }
        } else {
            return `https://${reqHost}/uploads/${file.filename}`;
        }
    } catch (uploadErr) {
        console.error('File Upload Error:', uploadErr.message);
        return `https://${reqHost}/uploads/${file.filename}`;
    } finally {
        try {
            if (fs.existsSync(file.path)) {
                fs.unlinkSync(file.path);
            }
        } catch (unlinkErr) {
            console.error('Unlink Error:', unlinkErr.message);
        }
    }
};

app.post('/api/save-post', authenticateToken, upload.array('images'), async (req, res) => {
    const userId = req.user.id;
    const { mode, content, facebook, instagram, pinterest, schedule_time } = req.body;
    const files = req.files || [];

    const platforms = {
        facebook: facebook === 'true',
        instagram: instagram === 'true',
        pinterest: pinterest === 'true',
        linkedin: linkedin === 'true' || linkedin === true
    };

    try {
        if (mode === 'schedule') {
            const baseDate = schedule_time ? new Date(schedule_time) : new Date();
            const savedPosts = [];

            if (files.length > 0) {
                for (let i = 0; i < files.length; i++) {
                    const imageUrl = await uploadSingleFile(files[i], userId, req.get('host'));
                    const postScheduleDate = new Date(baseDate.getTime() + (i * 24 * 60 * 60 * 1000));

                    const query = `
                        INSERT INTO user_posts (user_id, mode, content, platforms, schedule_time, images) 
                        VALUES ($1, $2, $3, $4, $5, $6) 
                        RETURNING *;
                    `;
                    const values = [
                        userId,
                        'schedule',
                        content,
                        JSON.stringify(platforms),
                        postScheduleDate.toISOString(),
                        [imageUrl]
                    ];

                    const result = await pool.query(query, values);
                    savedPosts.push(result.rows[0]);
                }
            } else {
                const query = `
                    INSERT INTO user_posts (user_id, mode, content, platforms, schedule_time, images) 
                    VALUES ($1, $2, $3, $4, $5, $6) 
                    RETURNING *;
                `;
                const values = [
                    userId,
                    'schedule',
                    content,
                    JSON.stringify(platforms),
                    baseDate.toISOString(),
                    []
                ];
                const result = await pool.query(query, values);
                savedPosts.push(result.rows[0]);
            }

            return res.status(201).json({
                success: true,
                message: `${savedPosts.length} days of scheduled posts saved successfully!`,
                posts: savedPosts
            });
        } else {
            const imagePaths = [];
            for (const file of files) {
                const url = await uploadSingleFile(file, userId, req.get('host'));
                imagePaths.push(url);
            }

            const query = `
                INSERT INTO user_posts (user_id, mode, content, platforms, schedule_time, images) 
                VALUES ($1, $2, $3, $4, $5, $6) 
                RETURNING *;
            `;
            const values = [
                userId,
                mode,
                content,
                JSON.stringify(platforms),
                null,
                imagePaths
            ];

            const result = await pool.query(query, values);
            const savedPost = result.rows[0];

            if (process.env.N8N_WEBHOOK_URL) {
                try {
                    await axios.post(process.env.N8N_WEBHOOK_URL, savedPost);
                } catch (n8nError) {
                    console.error('Forwarding to n8n failed:', n8nError.message);
                }
            }

            return res.status(201).json({
                success: true,
                message: 'Post created successfully!',
                post: savedPost
            });
        }
    } catch (error) {
        console.error('Save Post Error:', error.message);
        res.status(500).json({ success: false, message: 'Server error: ' + error.message });
    }
});

// ==========================================
// 🛠️ ACCOUNT MANAGEMENTS
// ==========================================

app.get('/user/accounts', async (req, res) => {
    const userId = req.query.user_id;

    if (!userId) {
        return res.status(400).json({ success: false, message: 'user_id আবশ্যক!' });
    }

    try {
        const query = 'SELECT platform, page_id, page_name, is_active FROM social_accounts WHERE user_id = $1::INTEGER';
        const result = await pool.query(query, [userId]);

        res.status(200).json({
            success: true,
            accounts: result.rows
        });
    } catch (err) {
        console.error('Fetch Accounts Error:', err);
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

app.post('/auth/disconnect', async (req, res) => {
    const { user_id, platform, page_id } = req.body;

    if (!user_id || !platform) {
        return res.status(400).json({ success: false, message: 'user_id এবং platform আবশ্যক!' });
    }

    try {
        let query = '';
        let values = [];

        if (page_id) {
            query = 'DELETE FROM social_accounts WHERE user_id = $1::INTEGER AND platform = $2 AND page_id = $3';
            values = [user_id, platform.toLowerCase().trim(), page_id];
        } else {
            query = 'DELETE FROM social_accounts WHERE user_id = $1::INTEGER AND platform = $2';
            values = [user_id, platform.toLowerCase().trim()];
        }

        await pool.query(query, values);

        res.status(200).json({ 
            success: true, 
            message: `${platform} সফলভাবে নিয়ন ডাটাবেজ থেকে মুছে ফেলা হয়েছে।` 
        });
    } catch (err) {
        console.error('Disconnect Error:', err);
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// 🎯 AI Caption Generator Endpoint
app.post('/api/generate-caption', authenticateToken, async (req, res) => {
    try {
        const { prompt } = req.body;
        if (!prompt) return res.status(400).json({ success: false, message: 'Prompt is required' });

        const response = await ai.models.generateContent({
            model: 'gemini-3.6-flash',
            contents: `Act as a professional social media manager. Based on this topic/description: "${prompt}", write ONLY ONE single, ready-to-publish, engaging social media post with hashtags and emojis. Do not add intro/outro text.`,
        });

        const generatedText = typeof response.text === 'function' ? await response.text() : response.text;

        return res.status(200).json({
            success: true,
            caption: generatedText.trim()
        });
    } catch (error) {
        console.error("Gemini Error:", error);
        return res.status(500).json({ success: false, error: error.message });
    }
});

// 👤 ১. ইউজার প্রোফাইল ডাটা পাওয়া
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const userQuery = 'SELECT id, email, name, profile_pic, created_at FROM users WHERE id = $1';
        const userResult = await pool.query(userQuery, [userId]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'ইউজার পাওয়া যায়নি!' });
        }

        const accountsQuery = 'SELECT platform, page_id, page_name, is_active FROM social_accounts WHERE user_id = $1';
        const accountsResult = await pool.query(accountsQuery, [userId]);

        res.status(200).json({
            success: true,
            user: userResult.rows[0],
            connected_accounts: accountsResult.rows
        });
    } catch (err) {
        console.error("Get Profile Error:", err);
        res.status(500).json({ success: false, message: 'সার্ভার এরর: ' + err.message });
    }
});

// 📝 ২. ইউজার প্রোফাইল আপডেট করা
app.put('/api/user/profile', authenticateToken, async (req, res) => {
    const { name, profile_pic } = req.body;
    const userId = req.user.id;

    try {
        const updateQuery = `
            UPDATE users 
            SET name = COALESCE($1, name), 
                profile_pic = COALESCE($2, profile_pic)
            WHERE id = $3 
            RETURNING id, email, name, profile_pic;
        `;
        const result = await pool.query(updateQuery, [name, profile_pic, userId]);

        res.status(200).json({
            success: true,
            message: 'প্রোফাইল সফলভাবে আপডেট হয়েছে!',
            user: result.rows[0]
        });
    } catch (err) {
        console.error("Update Profile Error:", err);
        res.status(500).json({ success: false, message: 'আপডেট করতে ব্যর্থ হয়েছে: ' + err.message });
    }
});

// ==========================================
// 🤖 AUTOMATION RULE SAVING ROUTE
// ==========================================
app.post('/api/generate-user-plan', async (req, res) => {
  try {
    const { user_prompt } = req.body;

    const systemPrompt = `
You are an expert AI Social Media Assistant Agent. Your role is to understand user commands and transform them into precise, structured JSON actions for the backend system and Neon PostgreSQL Database.

CURRENT TIME REFERENCE: ${new Date().toISOString()}

--- CORE BUSINESS RULES ---

1. INTENT DETECTION & CATEGORIZATION:
   Analyze the user request and determine the primary "intent":
   - "CREATE_POSTS": User wants to create instant, single, or multiple scheduled posts.
   - "DELETE_POSTS": User wants to cancel, clear, or delete pending/scheduled posts.
   - "UPDATE_POSTS": User wants to reschedule or edit existing scheduled posts.
   - "PAUSE_AUTOMATION": User wants to pause all automated posting temporarily.

2. DURATION & POST COUNT LIMITS:
   - Default Schedule Rule: If the user requests recurring or multi-day posts BUT DOES NOT specify the number of days or post count (e.g., "আমার জন্য নিয়মিত পোস্ট বানাও"), DEFAULT TO 7 DAYS (7 posts, 1 post per day).
   - Instant Request Rule: If the user requests an instant post (e.g., "এখনই পোস্ট বানাও"), set scheduled_at to current time and total posts to 1.
   - Absolute Maximum Limit: ABSOLUTELY MAXIMUM 30 DAYS / 30 POSTS. If the user asks for more than 30 days (e.g., "আগামী ৬০ দিনের জন্য" or "১ মাসের বেশি"), STRICTLY TRUNCATE / LIMIT OUTPUT TO 30 POSTS ONLY.

3. SMART TIMING (BEST TIME ALGORITHM):
   - If the user specifies a time (e.g., "প্রতিদিন সকাল ৯টায়"), use that exact time.
   - If the user DOES NOT specify a time, Gemini MUST act as a social media strategist and set optimal daily posting times (e.g., Peak Engagement Hours like 10:00 AM, 02:00 PM, or 08:00 PM local time) spread across consecutive days.

4. PLATFORM SELECTION RULE:
   - If the user specifies target platforms (e.g., "শুধু ফেসবুকে দাও"), set "platforms": ["facebook"].
   - If the user DOES NOT specify platforms, DEFAULT TO ALL ACCOUNTS: ["facebook", "instagram", "pinterest", "linkedin"].

5. DELETION RULES:
   - If user asks to clear/delete all posts (e.g., "আগের সব পোস্ট কেটে দাও"), set "intent": "DELETE_POSTS", "is_delete": true, and "delete_scope": "ALL_PENDING".
   - If user asks to delete specific posts (e.g., "গতকালের পোস্টটা কেটে দাও"), set "intent": "DELETE_POSTS", "is_delete": true, with "delete_scope": "SPECIFIC_DATE" and target date.

--- OUTPUT FORMAT REQUIREMENTS ---
You MUST return ONLY raw valid JSON (no markdown formatting, no \`\`\`json wrappers).

EXAMPLE JSON FOR "CREATE_POSTS":
{
  "intent": "CREATE_POSTS",
  "is_delete": false,
  "intent_summary": "Generated 7 daily tech posts starting from tomorrow at optimal engagement times.",
  "posts": [
    {
      "day_number": 1,
      "scheduled_at": "2026-08-27T10:00:00.000Z",
      "platforms": ["facebook", "instagram", "pinterest", "linkedin"],
      "content": "🚀 Tech Update Day 1: Engaging caption with emojis and relevant hashtags..."
    }
  ]
}

EXAMPLE JSON FOR "DELETE_POSTS":
{
  "intent": "DELETE_POSTS",
  "is_delete": true,
  "intent_summary": "Clearing all pending scheduled posts from the database per user request.",
  "delete_scope": "ALL_PENDING"
}

USER COMMAND TO PROCESS: "${user_prompt}"
`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.6-flash',
      contents: systemPrompt,
    });

    const cleanJsonText = response.text.replace(/```json|```/g, '').trim();
    const parsedPlan = JSON.parse(cleanJsonText);

    res.json({
      success: true,
      plan: parsedPlan
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 🎯 Confirm & Save All Posts API
app.post('/api/confirm-save-plan', authenticateToken, async (req, res) => {
  try {
    const { posts } = req.body;
    const userId = req.user.id;

    if (!posts || !Array.isArray(posts) || posts.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: "সেভ করার জন্য কোনো পোস্ট পাওয়া যায়নি!" 
      });
    }

    for (let post of posts) {
      await pool.query(
        `INSERT INTO user_posts 
         (user_id, mode, content, platforms, schedule_time, images) 
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          userId, 
          'ai_agent',
          post.content, 
          JSON.stringify(post.platforms || { facebook: true, instagram: true, pinterest: true, linkedin: true }),
          post.scheduled_at,
          post.images || []
        ]
      );
    }

    res.json({
      success: true,
      message: `সফলভাবে ${posts.length}টি পোস্ট ডাটাবেসে শিডিউল করা হয়েছে!`
    });

  } catch (error) {
    console.error("Save Plan Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 🎯 ডাটাবেস থেকে ইউজারের পোস্ট ফেচ API
app.get('/api/get-scheduled-posts', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const requestedMode = req.query.mode;

    let query = `
      SELECT id, content, mode, schedule_time AS scheduled_at, platforms AS target_platforms, images, is_posted 
      FROM user_posts 
      WHERE user_id = $1 AND is_posted = FALSE
    `;
    
    const queryParams = [userId];

    if (requestedMode) {
      queryParams.push(requestedMode);
      query += ` AND mode = $${queryParams.length}`;
    }

    query += ` ORDER BY schedule_time ASC;`;

    const result = await pool.query(query, queryParams);

    res.status(200).json({
      success: true,
      posts: result.rows
    });
  } catch (error) {
    console.error("Fetch Posts Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 🎯 ১. Single Post Delete API
app.delete('/api/delete-post/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const postId = req.params.id;

    const result = await pool.query(
      'DELETE FROM user_posts WHERE id = $1 AND user_id = $2 RETURNING *',
      [postId, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'পোস্টটি পাওয়া যায়নি বা অ্যাক্সেস নেই!' });
    }

    res.status(200).json({ success: true, message: 'পোস্টটি সফলতার সাথে মুছে ফেলা হয়েছে!' });
  } catch (error) {
    console.error("Delete Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 🎯 ২. Single Post Edit/Update API
app.put('/api/update-post/:id', authenticateToken, upload.array('images'), async (req, res) => {
  try {
    const userId = req.user.id;
    const postId = req.params.id;
    const { content, target_platforms, scheduled_at } = req.body;
    const files = req.files || [];

    let updatedImages = null;
    if (files.length > 0) {
      updatedImages = [];
      for (const file of files) {
        const url = await uploadSingleFile(file, userId, req.get('host'));
        updatedImages.push(url);
      }
    }

    const query = `
      UPDATE user_posts 
      SET content = COALESCE($1, content), 
          platforms = COALESCE($2, platforms), 
          schedule_time = COALESCE($3, schedule_time),
          images = COALESCE($4, images)
      WHERE id = $5 AND user_id = $6 
      RETURNING *;
    `;

    const values = [
      content || null,
      target_platforms ? JSON.stringify(target_platforms) : null,
      scheduled_at || null,
      updatedImages ? updatedImages : null,
      postId,
      userId
    ];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'পোস্টটি পাওয়া যায়নি বা আপনার অ্যাক্সেস নেই!' });
    }

    res.status(200).json({
      success: true,
      message: 'পোস্টটি সফলতার সাথে আপডেট হয়েছে!',
      post: result.rows[0]
    });
  } catch (error) {
    console.error("Update Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 🎯 Delete All Scheduled Posts for current user
app.delete('/api/delete-all-posts', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    await pool.query('DELETE FROM user_posts WHERE user_id = $1 AND is_posted = FALSE', [userId]);
    res.status(200).json({ success: true, message: 'All scheduled posts deleted successfully!' });
  } catch (error) {
    console.error("Delete All Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`সার্ভার সফলভাবে পোর্ট ${PORT}-এ রান হচ্ছে!`);
});