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
const { GoogleGenAI } = require('@google/genai'); // 🎯 Fixed Require

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
// 📘 FACEBOOK AUTH ROUTES
// ==========================================
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

app.get('/user/accounts', async (req, res) => {
    const userId = req.query.user_id;

    if (!userId) {
        return res.status(400).json({ success: false, message: 'user_id আবশ্যক!' });
    }

    try {
        const query = 'SELECT platform, page_id, page_name FROM social_accounts WHERE user_id = $1::INTEGER';
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

// 🎯 AI Caption Generator Endpoint (Secured with authenticateToken)
app.post('/api/generate-caption', authenticateToken, async (req, res) => {
    try {
        const { prompt } = req.body;
        if (!prompt) return res.status(400).json({ success: false, message: 'Prompt is required' });

        const response = await ai.models.generateContent({
            model: 'gemini-3.6-flash',
            contents: `Act as a professional social media manager. Based on this topic/description: "${prompt}", write ONLY ONE single, ready-to-publish, engaging social media post with hashtags and emojis. Do not add intro/outro text.`,
        });

        // Ensure text extraction is safe
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
// ইউজার প্রোফাইল ডাটা গেট করা
// 👤 ১. ইউজার প্রোফাইল ডাটা পাওয়া
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // ইউজার ইনফরমেশন আনা
        const userQuery = 'SELECT id, email, name, profile_pic, created_at FROM users WHERE id = $1';
        const userResult = await pool.query(userQuery, [userId]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'ইউজার পাওয়া যায়নি!' });
        }

        // কানেক্ট করা সোশ্যাল একাউন্ট লিস্ট আনা
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

// 📝 ২. ইউজার প্রোফাইল (নাম ও প্রফাইল পিকচার) আপডেট করা
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
            message: 'প্রোফাইল সফলভাবে আপডেট হয়েছে!',
            user: result.rows[0]
        });
    } catch (err) {
        console.error("Update Profile Error:", err);
        res.status(500).json({ success: false, message: 'আপডেট করতে ব্যর্থ হয়েছে: ' + err.message });
    }
});

// ==========================================
// 🤖 AUTOMATION RULE SAVING ROUTE
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
   - If the user DOES NOT specify platforms, DEFAULT TO ALL ACCOUNTS: ["facebook", "instagram", "pinterest"].

5. DELETION RULES:
   - If user asks to clear/delete all posts (e.g., "আগের সব পোস্ট কেটে দাও"), set "intent": "DELETE_POSTS" and "delete_scope": "ALL_PENDING".
   - If user asks to delete specific posts (e.g., "গতকালের পোস্টটা কেটে দাও"), set "delete_scope": "SPECIFIC_DATE" with the target date.

--- OUTPUT FORMAT REQUIREMENTS ---
You MUST return ONLY raw valid JSON (no markdown formatting, no \`\`\`json wrappers).

EXAMPLE JSON FOR "CREATE_POSTS":
{
  "intent": "CREATE_POSTS",
  "intent_summary": "Generated 7 daily tech posts starting from tomorrow at optimal engagement times.",
  "posts": [
    {
      "day_number": 1,
      "scheduled_at": "2026-08-27T10:00:00.000Z",
      "platforms": ["facebook", "instagram", "pinterest"],
      "content": "🚀 Tech Update Day 1: Engaging caption with emojis and relevant hashtags..."
    }
  ]
}

EXAMPLE JSON FOR "DELETE_POSTS":
{
  "intent": "DELETE_POSTS",
  "intent_summary": "Clearing all pending scheduled posts from the database per user request.",
  "delete_scope": "ALL_PENDING"
}

USER COMMAND TO PROCESS: "${user_prompt}"
`;

    // Calling Gemini 3.6 Flash
    const response = await ai.models.generateContent({
      model: 'gemini-3.6-flash',
      contents: systemPrompt,
    });

    // Cleaning JSON response
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
    const { posts } = req.body; // Flutter থেকে আসা array of generated/edited posts
    const userId = req.user.id;  // JWT Auth Middleware থেকে পাওয়া ইউনিক ইউজার আইডি

    if (!posts || !Array.isArray(posts) || posts.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: "সেভ করার জন্য কোনো পোস্ট পাওয়া যায়নি!" 
      });
    }

    // মাল্টি-ইউজার সেফটি: pool.query ব্যবহার করে লুপ চালানো
    for (let post of posts) {
      await pool.query(
        `INSERT INTO scheduled_posts 
         (user_id, content, scheduled_at, target_platforms, images, status) 
         VALUES ($1, $2, $3, $4, $5, 'PENDING')`,
        [
          userId, 
          post.content, 
          post.scheduled_at, 
          JSON.stringify(post.platforms || ["facebook", "instagram", "pinterest"]),
          JSON.stringify(post.images || [])
        ]
      );
    }

    res.json({
      success: true,
      message: `সফলভাবে ${posts.length}টি পোস্ট ডাটাবেসে শিডিউল করা হয়েছে!`
    });

  } catch (error) {
    console.error("Save Plan Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 🎯 ডাটাবেস থেকে ইউজারের সকল PENDING শিডিউল পোস্ট ফেস (GET) করার API
app.get('/api/get-scheduled-posts', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const query = `
      SELECT id, content, scheduled_at, target_platforms, images, status 
      FROM scheduled_posts 
      WHERE user_id = $1 AND status = 'PENDING' 
      ORDER BY scheduled_at ASC;
    `;

    const result = await pool.query(query, [userId]);

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
      'DELETE FROM scheduled_posts WHERE id = $1 AND user_id = $2 RETURNING *',
      [postId, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'পোস্টটি পাওয়া যায়নি বা অ্যাক্সেস নেই!' });
    }

    res.status(200).json({ success: true, message: 'পোস্টটি সফলতা সাথে মুছে ফেলা হয়েছে!' });
  } catch (error) {
    console.error("Delete Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 🎯 ২. Single Post Edit/Update API
app.put('/api/update-post/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const postId = req.params.id;
    const { content, target_platforms, scheduled_at } = req.body;

    const result = await pool.query(
      `UPDATE scheduled_posts 
       SET content = COALESCE($1, content), 
           target_platforms = COALESCE($2, target_platforms), 
           scheduled_at = COALESCE($3, scheduled_at) 
       WHERE id = $4 AND user_id = $5 
       RETURNING *`,
      [
        content,
        target_platforms ? JSON.stringify(target_platforms) : null,
        scheduled_at,
        postId,
        userId
      ]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'পোস্টটি আপডেট করা সম্ভব হয়নি!' });
    }

    res.status(200).json({ success: true, message: 'পোস্ট আপডেট হয়েছে!', post: result.rows[0] });
  } catch (error) {
    console.error("Update Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});
// 🎯 Post Update API (নিয়নে ডাটাবেস আপডেট করার জন্য)
app.put('/api/update-post/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const postId = req.params.id;
    const { content, target_platforms, scheduled_at } = req.body;

    const query = `
      UPDATE scheduled_posts 
      SET content = COALESCE($1, content), 
          target_platforms = COALESCE($2, target_platforms), 
          scheduled_at = COALESCE($3, scheduled_at) 
      WHERE id = $4 AND user_id = $5 
      RETURNING *;
    `;

    const values = [
      content || null,
      target_platforms ? JSON.stringify(target_platforms) : null,
      scheduled_at || null,
      postId,
      userId
    ];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'পোস্টটি পাওয়া যায়নি বা আপনার অ্যাক্সেস নেই!' });
    }

    res.status(200).json({
      success: true,
      message: 'পোস্টটি সফলতা সাথে আপডেট হয়েছে!',
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
    await pool.query('DELETE FROM scheduled_posts WHERE user_id = $1 AND status = $2', [userId, 'PENDING']);
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