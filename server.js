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

const app = express();

app.use(express.json());
app.use(cors());
app.use('/uploads', express.static('uploads'));

// 🚀 Supabase Client সেটআপ
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = (SUPABASE_URL && SUPABASE_KEY) ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;

// 🗄️ Neon Postgres Pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secure_secret_key_123';

// 🛡️ মিডলওয়্যার: টোকেন ভেরিফাই করা
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

// ==========================================
// 📘 FACEBOOK AUTH ROUTES
// ==========================================

// ৩. ফেসবুক লগইন রিডাইরেক্ট
app.get('/auth/facebook', (req, res) => {
    const userId = req.query.user_id;

    if (!userId) {
        return res.status(400).send('❌ ত্রুটি: ফেসবুক কানেক্ট করার জন্য user_id পাঠানো বাধ্যতামূলক!');
    }

    const appId = process.env.FACEBOOK_APP_ID;
    const redirectUri = `${process.env.BACKEND_URL}/auth/facebook/callback`;
    const state = JSON.stringify({ user_id: userId });

    const fbLoginUrl = `https://www.facebook.com/v18.0/dialog/oauth?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&scope=pages_show_list,pages_manage_posts,pages_read_engagement`;
    res.redirect(fbLoginUrl);
});

// ৪. ফেসবুক কলব্যাক (Page Name সহ সেভ করার জন্য আপডেট করা হয়েছে)
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
        return res.status(400).send('❌ ত্রুটি: অথেন্টিকেশন কোড বা ইউজার আইডি পাওয়া যায়নি।');
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
            const checkQuery = 'SELECT * FROM social_accounts WHERE page_id = $1 AND user_id = $2';
            const existing = await pool.query(checkQuery, [page.id, userId]);

            if (existing.rows.length > 0) {
                const updateQuery = 'UPDATE social_accounts SET access_token = $2, page_name = $3, is_active = TRUE, updated_at = NOW() WHERE page_id = $1 AND user_id = $4';
                await pool.query(updateQuery, [page.id, page.access_token, page.name, userId]);
            } else {
                const insertQuery = 'INSERT INTO social_accounts (user_id, page_id, page_name, access_token, is_active, platform) VALUES ($1, $2, $3, $4, $5, $6)';
                await pool.query(insertQuery, [userId, page.id, page.name, page.access_token, true, 'facebook']);
            }
        }

        res.send(`<html><body style="font-family: Arial; text-align: center; padding: 50px;"><h2>🎉 ফেসবুক পেজ সফলভাবে কানেক্ট হয়েছে!</h2><p>ট্যাবটি বন্ধ করে অ্যাপে ফিরে যান।</p></body></html>`);
    } catch (error) {
        console.error("Facebook Auth Error:", error.response?.data || error.message);
        res.status(500).send('Authentication failed!');
    }
});

// ৫. সরাসরি ফেসবুক পেজে পোস্ট করার এপিআই
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

// ৬. পোস্ট সেভ / শিডিউল এপিআই
app.post('/api/save-post', authenticateToken, upload.array('images'), async (req, res) => {
    const userId = req.user.id;
    const { mode, content, facebook, instagram, pinterest, schedule_time } = req.body;
    const files = req.files || [];

    const platforms = {
        facebook: facebook === 'true',
        instagram: instagram === 'true',
        pinterest: pinterest === 'true'
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

// ৭. ইউজার অ্যাকাউন্টস ও কানেক্টেড পেইজ লিস্ট (পেজের নাম সহ পাঠাবে)
app.get('/user/accounts', async (req, res) => {
    const userId = req.query.user_id;

    if (!userId) {
        return res.status(400).json({ success: false, message: 'user_id আবশ্যক!' });
    }

    try {
        const query = 'SELECT platform, page_id, page_name FROM social_accounts WHERE user_id = $1';
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

// ৮. সোশ্যাল অ্যাকাউন্ট ডিসকানেক্ট (DELETE Query - ডাটা সরাসরি নিয়ন ডাটাবেজ থেকে মুছে ফেলবে)
app.post('/auth/disconnect', async (req, res) => {
    const { user_id, platform, page_id } = req.body;

    if (!user_id || !platform) {
        return res.status(400).json({ success: false, message: 'user_id এবং platform আবশ্যক!' });
    }

    try {
        let query = '';
        let values = [];

        if (page_id) {
            query = 'DELETE FROM social_accounts WHERE user_id = $1 AND platform = $2 AND page_id = $3';
            values = [user_id, platform.toLowerCase().trim(), page_id];
        } else {
            query = 'DELETE FROM social_accounts WHERE user_id = $1 AND platform = $2';
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`সার্ভার সফলভাবে পোর্ট ${PORT}-এ রান হচ্ছে!`);
});