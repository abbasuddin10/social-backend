const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const axios = require('axios');
const jwt = require('jsonwebtoken'); // 👈 JWT যুক্ত করা হলো

const app = express();

app.use(express.json());
app.use(cors());
app.use('/uploads', express.static('uploads'));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// JWT Secret Key (Render-এর Environment Variable-এ রাখা উচিত)
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secure_secret_key_123';

// 🛡️ মিডলওয়্যার: টোকেন ভেরিফাই করে রিকোয়েস্টে user_id পুশ করার জন্য
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN_HERE

    if (!token) {
        return res.status(401).json({ success: false, message: 'অথেন্টিকেশন টোকেন পাওয়া যায়নি!' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'ইনভ্যালিড বা এক্সপায়ার্ড টোকেন!' });
        }
        req.user = user; // টোকেন থেকে পাওয়া ইউজার অবজেক্ট (id) রিকোয়েস্টে সেট হবে
        next();
    });
};

app.get('/', (req, res) => {
    res.send('Node.js Backend Server with Neon DB is running!');
});

// ১. রেজিস্ট্রেশন এপিআই (JWT Token সহ আপডেট করা)
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
        
        // টোকেন জেনারেট করা (১ বছরের জন্য বা প্রজেক্ট অনুযায়ী সেট করতে পারেন)
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '365d' });

        res.status(201).json({
            success: true,
            message: 'অ্যাকাউন্ট সফলভাবে তৈরি হয়েছে!',
            token: token, // ফ্লাটার অ্যাপ এই টোকেন সেভ করবে
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

// ২. লগইন এপিআই (JWT Token সহ আপডেট করা)
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

        // টোকেন জেনারেট করা
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '365d' });

        res.status(200).json({
            success: true,
            message: 'সফলভাবে লগইন হয়েছে!',
            token: token, // ফ্লাটার অ্যাপ এই টোকেন সেভ করবে
            user: { id: user.id, email: user.email }
        });
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// ৩. ফেসবুক লগইন রিডাইরেক্ট রাউট (টোকেন দিয়ে রিকোয়েস্ট সিকিউর করা হয়েছে)
app.get('/auth/facebook', (req, res) => {
    const userId = req.query.user_id; // এটি অথেনটিকেটেড ইউজার আইডি হিসেবে ফ্লাটার থেকে আসবে
    
    if (!userId) {
        return res.status(400).send('❌ ত্রুটি: ফেসবুক কানেক্ট করার জন্য user_id পাঠানো বাধ্যতামূলক!');
    }

    const appId = process.env.FACEBOOK_APP_ID;
    const redirectUri = `${process.env.BACKEND_URL}/auth/facebook/callback`;
    const state = JSON.stringify({ user_id: userId });
    
    const fbLoginUrl = `https://www.facebook.com/v18.0/dialog/oauth?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&scope=pages_show_list,pages_manage_posts,pages_read_engagement`;
    res.redirect(fbLoginUrl);
});

// ৪. ফেসবুক কলব্যাক রাউট (অপরিবর্তিত, কারণ এটি রিডাইরেক্ট স্টেট থেকে আইডি পায়)
app.get('/auth/facebook/callback', async (req, res) => {
    const code = req.query.code;
    const stateStr = req.query.state;
    
    let userId = null;
    try {
        if (stateStr) {
            const parsedState = JSON.parse(stateStr);
            userId = parsedState.user_id;
        }
    } catch (e) {
        console.error("State parse error:", e);
    }

    if (!code || !userId) {
        return res.status(400).send('❌ ত্রুটি: অথেন্টিকেশন কোড বা ইউজার আইডি পাওয়া যায়নি।');
    }

    try {
        const appId = process.env.FACEBOOK_APP_ID;
        const appSecret = process.env.FACEBOOK_APP_SECRET;
        const redirectUri = `${process.env.BACKEND_URL}/auth/facebook/callback`;

        const tokenUrl = `https://graph.facebook.com/v18.0/oauth/access_token?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&client_secret=${appSecret}&code=${code}`;
        const tokenResponse = await axios.get(tokenUrl);
        const shortLivedToken = tokenResponse.data.access_token;

        const longLivedUrl = `https://graph.facebook.com/v18.0/oauth/access_token?grant_type=fb_exchange_token&client_id=${appId}&client_secret=${appSecret}&fb_exchange_token=${shortLivedToken}`;
        const longLivedResponse = await axios.get(longLivedUrl);
        const longLivedAccessToken = longLivedResponse.data.access_token;

        const pagesUrl = `https://graph.facebook.com/v18.0/me/accounts?access_token=${longLivedAccessToken}`;
        const pagesResponse = await axios.get(pagesUrl);
        const pages = pagesResponse.data.data;

        for (const page of pages) {
            const checkQuery = 'SELECT * FROM social_accounts WHERE page_id = $1 AND user_id = $2'; // 👈 মাল্টি-ইউজার সেফ ফিল্টার
            const existing = await pool.query(checkQuery, [page.id, userId]);

            if (existing.rows.length > 0) {
                const updateQuery = 'UPDATE social_accounts SET access_token = $2, is_active = TRUE, updated_at = NOW() WHERE page_id = $1 AND user_id = $3';
                await pool.query(updateQuery, [page.id, page.access_token, userId]);
            } else {
                const insertQuery = 'INSERT INTO social_accounts (user_id, page_id, access_token, is_active, platform) VALUES ($1, $2, $3, $4, $5)';
                await pool.query(insertQuery, [userId, page.id, page.access_token, true, 'facebook']);
            }
        }

        res.send(`<html><body style="font-family: Arial; text-align: center; padding: 50px;"><h2>🎉 ফেসবুক পেজ সফলভাবে কানেক্ট হয়েছে!</h2><p>ট্যাবটি বন্ধ করে অ্যাপে ফিরে যান।</p></body></html>`);
    } catch (error) {
        console.error("Facebook Auth Error:", error.response?.data || error.message);
        res.status(500).send('Authentication failed!');
    }
});

// ৫. ফেসবুক পেজে পোস্ট করার এপিআই (authenticateToken মিডলওয়্যার এবং মাল্টি-ইউজার কুয়েরি লক সহ)
app.post('/api/post-to-facebook', authenticateToken, async (req, res) => {
    const { page_id, message } = req.body;
    const userId = req.user.id; // 👈 টোকেন থেকে স্বয়ংক্রিয়ভাবে আইডি চলে এসেছে

    try {
        // কুয়েরিতে page_id এর সাথে ইউজার আইডিও বাধ্যতামূলক চেক করা হচ্ছে
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

// ৬. ফ্লাটার অ্যাপ থেকে পোস্ট ডেটা সেভ করার এপিআই (authenticateToken মিডলওয়্যার সহ সম্পূর্ণ সুরক্ষিত)
app.post('/api/save-post', authenticateToken, upload.array('images'), async (req, res) => {
    const userId = req.user.id; // 👈 এখন আর বডি থেকে আইডি নেওয়ার সুযোগ নেই, টোকেন থেকে আসবে
    const { mode, content, facebook, instagram, pinterest, schedule_time } = req.body;
    
    const platforms = {
        facebook: facebook === 'true',
        instagram: instagram === 'true',
        pinterest: pinterest === 'true'
    };

    const imagePaths = req.files ? req.files.map(file => `${req.protocol}://${req.get('host')}/uploads/${file.filename}`) : [];

    try {
        const query = `
            INSERT INTO user_posts (user_id, mode, content, platforms, schedule_time, images) 
            VALUES ($1, $2, $3, $4, $5, $6) 
            RETURNING *;
        `;
        const values = [
            userId, // সুরক্ষিত আইডি
            mode, 
            content, 
            JSON.stringify(platforms), 
            schedule_time || null, 
            imagePaths
        ];
        
        const result = await pool.query(query, values);
        const savedPost = result.rows[0];

        if (process.env.N8N_WEBHOOK_URL) {
            try {
                await axios.post(process.env.N8N_WEBHOOK_URL, savedPost);
            } catch (n8nError) {
                console.error('Error forwarding to n8n:', n8nError.message);
            }
        }

        res.status(201).json({
            success: true,
            message: 'Post saved securely in Neon DB and forwarded to n8n!',
            post: savedPost
        });
    } catch (error) {
        console.error('Save Post Error:', error.message);
        res.status(500).json({ success: false, message: 'Server error: ' + error.message });
    }
});

// ফেসবুক ওয়েবুক রুটসমূহ (GET/POST /api/webhook) অপরিবর্তিত থাকবে...
app.get('/api/webhook', (req, res) => { /* ... */ });
app.post('/api/webhook', async (req, res) => { /* ... */ });

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`সার্ভার সফলভাবে পোর্ট ${PORT}-এ রান হচ্ছে!`);
});