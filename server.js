const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const axios = require('axios');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const cron = require('node-cron');
const crypto = require('crypto'); // 🔑 Twitter PKCE-এর জন্য যুক্ত করা হলো
const { createClient } = require('@supabase/supabase-js');
const { OAuth2Client } = require('google-auth-library');
const { GoogleGenAI } = require('@google/genai');
const twitterVerifiers = {};
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
// 💬 WHATSAPP HELPER & SERVICES
// ==========================================

// 📩 হোয়াটসঅ্যাপে টেক্সট মেসেজ পাঠানোর গ্লোবাল ফাংশন
async function sendWhatsAppMessage(toPhoneNumber, messageBody) {
    try {
        const phoneId = process.env.WHATSAPP_PHONE_NUMBER_ID;
        const token = process.env.WHATSAPP_ACCESS_TOKEN;

        if (!phoneId || !token) {
            console.error("❌ WHATSAPP_PHONE_NUMBER_ID or WHATSAPP_ACCESS_TOKEN is missing in environment variables!");
            return { success: false, error: "Environment variables missing" };
        }

        const url = `https://graph.facebook.com/v19.0/${phoneId}/messages`;

        const payload = {
            messaging_product: "whatsapp",
            to: toPhoneNumber,
            type: "text",
            text: { body: messageBody }
        };

        const response = await axios.post(url, payload, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        console.log(`✅ WhatsApp Sent to ${toPhoneNumber}:`, response.data.messages[0].id);
        return { success: true, data: response.data };
    } catch (error) {
        console.error("❌ WhatsApp Error:", error.response?.data || error.message);
        return { success: false, error: error.response?.data || error.message };
    }
}

// 📱 ইউজারের হোয়াটসঅ্যাপ নম্বর আপডেট ও ভেরিফাই করার API (Flutter APP/Postman-এর জন্য)
app.post('/api/user/update-whatsapp', authenticateToken, async (req, res) => {
    const { whatsappNumber } = req.body;
    const userId = req.user.id;

    if (!whatsappNumber) {
        return res.status(400).json({ success: false, message: 'WhatsApp Number is required!' });
    }

    try {
        await pool.query(
            'UPDATE users SET whatsapp_number = $1 WHERE id = $2',
            [whatsappNumber, userId]
        );

        // কানেক্ট হওয়ার সাথে সাথে একটি টেস্ট নোটিফিকেশন মেসেজ সেন্ড
        await sendWhatsAppMessage(
            whatsappNumber, 
            "🎉 আপনার AFARZ Automation-এ WhatsApp অ্যাকাউন্ট সফলভাবে যুক্ত হয়েছে! এখন থেকে আপনি যেকোনো সময় বিজনেসের আপডেট জানতে মেসেজ দিতে পারেন।"
        );

        res.json({ success: true, message: 'WhatsApp connected successfully!' });
    } catch (err) {
        console.error("Update WhatsApp Error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ==========================================
// 📊 AI BUSINESS ANALYTICS & WEBHOOK LOGIC
// ==========================================

// ১. সোশ্যাল মিডিয়া পারফরম্যান্স ডাটা ফেচিং (Meta Graph API)
async function getSocialAnalytics(pageId, pageAccessToken) {
    try {
        const url = `https://graph.facebook.com/v18.0/${pageId}/posts?fields=id,message,created_time,likes.summary(true),comments.summary(true),permalink_url&limit=10&access_token=${pageAccessToken}`;
        const response = await axios.get(url);
        const posts = response.data.data;

        if (!posts || posts.length === 0) return null;

        let totalLikes = 0;
        let totalComments = 0;
        let topLikedPost = posts[0];
        let topCommentedPost = posts[0];

        posts.forEach(post => {
            const likes = post.likes?.summary?.total_count || 0;
            const comments = post.comments?.summary?.total_count || 0;

            totalLikes += likes;
            totalComments += comments;

            if (likes > (topLikedPost.likes?.summary?.total_count || 0)) {
                topLikedPost = post;
            }
            if (comments > (topCommentedPost.comments?.summary?.total_count || 0)) {
                topCommentedPost = post;
            }
        });

        return {
            totalPostsAnalyzed: posts.length,
            totalLikes,
            totalComments,
            topLikedPost: {
                caption: topLikedPost.message || "No Caption",
                likes: topLikedPost.likes?.summary?.total_count || 0,
                comments: topLikedPost.comments?.summary?.total_count || 0,
                link: topLikedPost.permalink_url,
                createdTime: topLikedPost.created_time
            },
            topCommentedPost: {
                caption: topCommentedPost.message || "No Caption",
                likes: topCommentedPost.likes?.summary?.total_count || 0,
                comments: topCommentedPost.comments?.summary?.total_count || 0,
                link: topCommentedPost.permalink_url
            }
        };
    } catch (err) {
        console.error("Meta API Fetch Error:", err.response?.data || err.message);
        return null;
    }
}

// ২. ডাটাবেস থেকে সেলস ও অর্ডারের আপডেট ডাটা ফেচিং (Neon Postgres)
async function getDatabaseAnalytics(userId) {
    try {
        const today = new Date().toISOString().split('T')[0];

        // আজকের মোট অর্ডার ও সেলস অ্যামাউন্ট
        const orderQuery = `
            SELECT COUNT(*) as total_orders, COALESCE(SUM(amount), 0) as total_revenue 
            FROM orders_leads 
            WHERE user_id = $1 AND DATE(created_at) = $2
        `;
        const orderRes = await pool.query(orderQuery, [userId, today]);

        // অল-টাইম টপ সেলিং প্রোডাক্ট
        const bestSellerQuery = `
            SELECT product_name, COUNT(*) as total_sales 
            FROM orders_leads 
            WHERE user_id = $1 
            GROUP BY product_name 
            ORDER BY total_sales DESC 
            LIMIT 1
        `;
        const bestSellerRes = await pool.query(bestSellerQuery, [userId]);

        return {
            todayOrders: parseInt(orderRes.rows[0].total_orders || 0),
            todayRevenue: parseFloat(orderRes.rows[0].total_revenue || 0),
            bestSeller: bestSellerRes.rows[0] ? bestSellerRes.rows[0].product_name : "N/A",
            bestSellerCount: bestSellerRes.rows[0] ? parseInt(bestSellerRes.rows[0].total_sales) : 0
        };
    } catch (err) {
        console.error("DB Query Error:", err);
        return null;
    }
}

// ৩. Gemini AI দ্বারা ইউজারের প্রশ্ন বিশ্লেষণ ও রেসপন্স তৈরি
async function processUserQueryWithGemini(userMessage, socialData, dbData) {
    try {
        const contextData = {
            social: socialData || "Social media data not available",
            sales: dbData || "Sales database data not available"
        };

        const systemPrompt = `
You are an intelligent business assistant responding to a shop owner via WhatsApp.
Here is the current live data of the user's business:
${JSON.stringify(contextData, null, 2)}

User's incoming WhatsApp message: "${userMessage}"

Tasks:
1. Understand what the user is asking about (e.g., top post, total likes, total comments, best views/reach, total orders, best-selling product, overall business summary).
2. Answer the user's question clearly, concisely, and accurately in standard Bengali (with relevant emojis).
3. Use bullet points and clean formatting suitable for WhatsApp (e.g., bold with *text*).
4. Do NOT invent numbers; rely strictly on the provided JSON data.

Generate ONLY the final WhatsApp message text response:
`;

        const response = await ai.models.generateContent({
            model: 'gemini-3.6-flash',
            contents: systemPrompt
        });

        const generatedText = typeof response.text === 'function' ? await response.text() : response.text;
        return generatedText.trim();
    } catch (err) {
        console.error("Gemini AI Processing Error:", err);
        return "🤖 দুঃখিত, ডাটা প্রসেস করতে একটি সাময়িক সমস্যা হয়েছে। কিছুক্ষণ পর আবার চেষ্টা করুন।";
    }
}

// 📩 ৪. WHATSAPP WEBHOOK ROUTES (রিয়েল-টাইম ইন্টারেক্টিভ রিপ্লাইয়ের জন্য)

// Webhook Verification (Meta-র জন্য)
app.get('/webhook/whatsapp', (req, res) => {
    const verifyToken = process.env.WHATSAPP_VERIFY_TOKEN || 'my_secret_token';
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode && token === verifyToken) {
        res.status(200).send(challenge);
    } else {
        res.sendStatus(403);
    }
});

// Incoming WhatsApp Message Receiver & Auto-Responder
app.post('/webhook/whatsapp', async (req, res) => {
    try {
        const message = req.body.entry?.[0]?.changes?.[0]?.value?.messages?.[0];

        if (message && message.type === 'text') {
            const userPhone = message.from; // ইউজারের মোবাইল নম্বর
            const userText = message.text.body; // ইউজারের পাঠানো মেসেজ

            // ১. ডাটাবেস থেকে ইউজার ও ফেসবুক পেজ এক্সেস টোকেন বের করা
            const cleanPhone = userPhone.replace(/^\+/, '');
            const userRes = await pool.query(
                `SELECT u.id, s.page_id, s.access_token 
                 FROM users u 
                 LEFT JOIN social_accounts s ON u.id = s.user_id AND s.platform = 'facebook'
                 WHERE u.whatsapp_number = $1 OR u.whatsapp_number = $2 OR u.whatsapp_number = $3
                 LIMIT 1`,
                [userPhone, `+${userPhone}`, cleanPhone]
            );

            if (userRes.rows.length === 0) {
                console.log("Registered user not found for phone:", userPhone);
                return res.sendStatus(200);
            }

            const { id: userId, page_id: pageId, access_token: pageToken } = userRes.rows[0];

            // ২. সোশ্যাল স্ট্যাটস ও ডাটাবেস স্ট্যাটস একসাথে ফেচ করা
            const [socialStats, dbStats] = await Promise.all([
                pageId && pageToken ? getSocialAnalytics(pageId, pageToken) : null,
                getDatabaseAnalytics(userId)
            ]);

            // ৩. Gemini AI দিয়ে ইউজারের প্রশ্নের উত্তর জেনারেট করা
            const finalReply = await processUserQueryWithGemini(userText, socialStats, dbStats);

            // ৪. হোয়াটসঅ্যাপে ব্যাক অ্যান্সার পাঠানো
            await sendWhatsAppMessage(userPhone, finalReply);
        }

        res.sendStatus(200);
    } catch (error) {
        console.error("Webhook Handling Error:", error);
        res.sendStatus(500);
    }
});

// ⏰ অটোমেটিক ডেইলি বিজনেস রিপোর্ট Cron Job (প্রতিদিন রাত ৯:০০ টায় রান হবে)
cron.schedule('0 21 * * *', async () => {
    console.log('📊 Generating & Sending WhatsApp Business Reports...');

    try {
        const usersRes = await pool.query(
            "SELECT id, email, name, whatsapp_number FROM users WHERE whatsapp_number IS NOT NULL AND whatsapp_number != ''"
        );

        for (const user of usersRes.rows) {
            const today = new Date().toISOString().split('T')[0];

            // ১. আজকের দিনে কতগুলো পোস্ট হয়েছে
            const publishedRes = await pool.query(
                "SELECT COUNT(*) FROM user_posts WHERE user_id = $1 AND DATE(schedule_time) = $2 AND is_posted = TRUE",
                [user.id, today]
            );

            // ২. আগামীকালের জন্য পেন্ডিং পোস্ট
            const upcomingRes = await pool.query(
                "SELECT COUNT(*) FROM user_posts WHERE user_id = $1 AND schedule_time > NOW() AND is_posted = FALSE",
                [user.id]
            );

            // 📝 বিজনেস রিপোর্ট মেসেজের ফরম্যাট
            const report = `
📊 *[AFARZ Automation] - Daily Summary*
📅 *তারিখ:* ${today}
👤 *ইউজার:* ${user.name || user.email}

----------------------------------------
✅ *আজকের আপডেট:*
• সফল পোস্ট: *${publishedRes.rows[0].count} টি*

⏳ *আগামী আপডেট:*
• পেন্ডিং/শিডিউল পোস্ট: *${upcomingRes.rows[0].count} টি*

----------------------------------------
_ধন্যবাদ, AFARZ Automation ব্যবহার করার জন্য!_ 🚀
`;

            await sendWhatsAppMessage(user.whatsapp_number, report);
        }
    } catch (err) {
        console.error("Cron Job Error:", err);
    }
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

        let hasConnectedInstagram = false;

        for (const page of pages) {
            // ১. ফেসবুক পেজ সেভ বা আপডেট
            const checkQuery = 'SELECT * FROM social_accounts WHERE page_id = $1 AND user_id = $2';
            const existing = await pool.query(checkQuery, [page.id, userId]);

            if (existing.rows.length > 0) {
                const updateQuery = 'UPDATE social_accounts SET access_token = $2, page_name = $3, is_active = TRUE, updated_at = NOW() WHERE page_id = $1 AND user_id = $4';
                await pool.query(updateQuery, [page.id, page.access_token, page.name, userId]);
            } else {
                const insertQuery = 'INSERT INTO social_accounts (user_id, page_id, page_name, access_token, is_active, platform) VALUES ($1, $2, $3, $4, $5, $6)';
                await pool.query(insertQuery, [userId, page.id, page.name, page.access_token, true, 'facebook']);
            }

            // ২. ইনস্টাগ্রাম অ্যাকাউন্ট ফেচ
            try {
                const igUrl = `https://graph.facebook.com/v18.0/${page.id}?fields=instagram_business_account{id,username,name}&access_token=${page.access_token}`;
                const igResponse = await axios.get(igUrl);
                
                if (igResponse.data && igResponse.data.instagram_business_account) {
                    const igData = igResponse.data.instagram_business_account;
                    const igId = igData.id;
                    const igPageName = igData.name || igData.username || page.name;

                    const checkIg = await pool.query(
                        'SELECT * FROM social_accounts WHERE page_id = $1 AND user_id = $2 AND platform = $3', 
                        [igId, userId, 'instagram']
                    );

                    if (checkIg.rows.length > 0) {
                        const updateIgQuery = 'UPDATE social_accounts SET access_token = $1, page_name = $2, is_active = TRUE, updated_at = NOW() WHERE page_id = $3 AND user_id = $4 AND platform = $5';
                        await pool.query(updateIgQuery, [page.access_token, igPageName, igId, userId, 'instagram']);
                    } else {
                        const insertIgQuery = 'INSERT INTO social_accounts (user_id, page_id, page_name, access_token, is_active, platform) VALUES ($1, $2, $3, $4, $5, $6)';
                        await pool.query(insertIgQuery, [userId, igId, igPageName, page.access_token, true, 'instagram']);
                    }

                    hasConnectedInstagram = true;
                }
            } catch (igErr) {
                console.error(`Instagram fetch error for page ${page.id}:`, igErr.message);
            }
        }

        if (hasConnectedInstagram) {
            res.send(`
                <html>
                <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px; background-color: #f4f6f9;">
                    <div style="max-width: 500px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
                        <h2 style="color: #2e7d32;">🎉 ফেসবুক ও ইনস্টাগ্রাম সফলভাবে কানেক্ট হয়েছে!</h2>
                        <p style="color: #555;">আপনার ফেসবুক পেজ এবং ইনস্টাগ্রাম বিজনেস অ্যাকাউন্ট সফলভাবে সংযুক্ত হয়েছে।</p>
                        <p style="font-weight: bold;">ট্যাবটি বন্ধ করে অ্যাপে ফিরে যান।</p>
                    </div>
                </body>
                </html>
            `);
        } else {
            res.send(`
                <html>
                <body style="font-family: Arial, sans-serif; padding: 30px; background-color: #f4f6f9; color: #333;">
                    <div style="max-width: 600px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
                        <h2 style="color: #d32f2f; text-align: center;">⚠️ আপনার কোনো ইনস্টাগ্রাম পেজ কানেক্ট হয়নি!</h2>
                        <p style="text-align: center; color: #555;">আপনার ফেসবুক পেজটি সফলভাবে কানেক্ট হয়েছে, কিন্তু এর সাথে কোনো <b>Instagram Business/Creator Account</b> যুক্ত ছিল না।</p>
                        
                        <hr style="border: 0; border-top: 1px solid #ddd; margin: 20px 0;">

                        <h3>📌 যেভাবে ইনস্টাগ্রাম কানেক্ট করবেন:</h3>
                        <ol style="line-height: 1.8; color: #444;">
                            <li>আপনার <b>Instagram App</b>-এ যান এবং প্রোফাইলটিকে <b>Professional / Business Account</b>-এ সুইচ করুন।</li>
                            <li>আপনার <b>Facebook Page</b>-এ প্রবেশ করুন।</li>
                            <li><b>Settings</b> &gt; <b>Linked Accounts</b>-এ যান।</li>
                            <li><b>Instagram</b> অপশন সিলেক্ট করে আপনার ইনস্টাগ্রাম অ্যাকাউন্টটি লগইন করে কানেক্ট করুন।</li>
                            <li>কানেক্ট হয়ে গেলে অ্যাপ থেকে পুনরায় <b>Facebook & Instagram Connect</b> বাটনে চাপ দিন।</li>
                        </ol>

                        <div style="text-align: center; margin-top: 30px;">
                            <p style="font-weight: bold; color: #1976d2;">প্রসেস সম্পন্ন হলে এই ট্যাবটি বন্ধ করে অ্যাপে ফিরে যান।</p>
                        </div>
                    </div>
                </body>
                </html>
            `);
        }
    } catch (error) {
        console.error("Facebook/Instagram Auth Error:", error.response?.data || error.message);
        res.status(500).send('Authentication failed!');
    }
});

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
// 💼 LINKEDIN AUTH ROUTES
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
        const expiresIn = tokenResponse.data.expires_in || 5184000;
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

// ==========================================
// 🐦 TWITTER (X) AUTH ROUTES (FIXED SESSION/PKCE)
// ==========================================

// In-Memory store for PKCE Code Verifiers


function base64URLEncode(str) {
    return str.toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

function sha256(buffer) {
    return crypto.createHash('sha256').update(buffer).digest();
}

app.get('/auth/twitter', (req, res) => {
    const userId = req.query.user_id;
    if (!userId) return res.status(400).send('❌ ত্রুটি: user_id প্রয়োজন!');

    const clientId = process.env.TWITTER_CLIENT_ID;
    const backendUrl = process.env.BACKEND_URL || 'https://social-backend-1hwz.onrender.com';

    if (!clientId) {
        return res.status(500).send('❌ ত্রুটি: সার্ভারে TWITTER_CLIENT_ID সেট করা নেই!');
    }

    const redirectUri = `${backendUrl}/auth/twitter/callback`;

    // 🔑 Generate clean PKCE Pair
    const codeVerifier = base64URLEncode(crypto.randomBytes(32));
    const codeChallenge = base64URLEncode(sha256(codeVerifier));

    // Simple single string state to prevent JSON encoding errors
    const state = `usr_${userId}_${Date.now()}`;
    
    // Save verifier in memory with the state key
    twitterVerifiers[state] = {
        userId: userId,
        codeVerifier: codeVerifier
    };

    const scope = 'tweet.read tweet.write users.read offline.access';

    const twitterLoginUrl = `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scope)}&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;

    res.redirect(twitterLoginUrl);
});

app.get('/auth/twitter/callback', async (req, res) => {
    const { code, state } = req.query;

    if (!code || !state || !twitterVerifiers[state]) {
        return res.status(400).send('❌ অথেন্টিকেশন কোড, ইউজার আইডি বা ভেরিফায়ার পাওয়া যায়নি।');
    }

    const { userId, codeVerifier } = twitterVerifiers[state];
    delete twitterVerifiers[state]; // Clean up after use

    try {
        const clientId = process.env.TWITTER_CLIENT_ID;
        const clientSecret = process.env.TWITTER_CLIENT_SECRET;
        const backendUrl = process.env.BACKEND_URL || 'https://social-backend-1hwz.onrender.com';
        const redirectUri = `${backendUrl}/auth/twitter/callback`;

        const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

        const tokenResponse = await axios.post(
            'https://api.twitter.com/2/oauth2/token',
            new URLSearchParams({
                code: code,
                grant_type: 'authorization_code',
                redirect_uri: redirectUri,
                code_verifier: codeVerifier,
                client_id: clientId
            }).toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': `Basic ${basicAuth}`
                }
            }
        );

        const { access_token, refresh_token, expires_in } = tokenResponse.data;
        const expiresAt = new Date(Date.now() + expires_in * 1000);

        const profileResponse = await axios.get('https://api.twitter.com/2/users/me', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        const twitterId = profileResponse.data.data.id;
        const profileName = profileResponse.data.data.name || profileResponse.data.data.username || 'Twitter User';

        const checkQuery = 'SELECT * FROM social_accounts WHERE page_id = $1 AND user_id = $2 AND platform = $3';
        const existing = await pool.query(checkQuery, [twitterId, userId, 'twitter']);

        if (existing.rows.length > 0) {
            const updateQuery = 'UPDATE social_accounts SET access_token = $1, refresh_token = $2, expires_at = $3, page_name = $4, is_active = TRUE, updated_at = NOW() WHERE page_id = $5 AND user_id = $6 AND platform = $7';
            await pool.query(updateQuery, [access_token, refresh_token, expiresAt, profileName, twitterId, userId, 'twitter']);
        } else {
            const insertQuery = 'INSERT INTO social_accounts (user_id, page_id, page_name, access_token, refresh_token, expires_at, is_active, platform) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)';
            await pool.query(insertQuery, [userId, twitterId, profileName, access_token, refresh_token, expiresAt, true, 'twitter']);
        }

        res.send(`
            <html>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px; background-color: #f4f6f9;">
                <div style="max-width: 500px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
                    <h2 style="color: #1DA1F2;">🎉 Twitter (X) অ্যাকাউন্ট সফলভাবে কানেক্ট হয়েছে!</h2>
                    <p style="color: #555;">ইউজার: <b>${profileName}</b></p>
                    <p style="font-weight: bold;">ট্যাবটি বন্ধ করে অ্যাপে ফিরে যান।</p>
                </div>
            </body>
            </html>
        `);
    } catch (error) {
        console.error("Twitter Auth Error:", error.response?.data || error.message);
        res.status(500).send('Twitter Authentication failed!');
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
            
            // 🎯 Extension dynamic করা হলো (video/image উভয়টির জন্য)
            const ext = file.originalname.split('.').pop() || 'file';
            const fileName = `user-${userId}-${uniqueSuffix}.${ext}`;

            const { data, error } = await supabase.storage
                .from('postimages') // Supabase bucket name
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

app.post('/api/save-post', authenticateToken, upload.fields([
    { name: 'images', maxCount: 10 },
    { name: 'thumbnail', maxCount: 1 }
]), async (req, res) => {
    const userId = req.user.id;
    
    // 🎯 ১. req.body থেকে সব ভ্যালু গ্রহণ (Fallback সহ)
    const { 
        mode, 
        content,               
        twitter_caption,     
        twitter_content,      // 👈 ফ্রন্টএন্ড থেকে দুটি নামই সেফটি হিসেবে হ্যান্ডেল করা হলো
        youtube_title,        
        youtube_description,  
        youtube_tags,         
        facebook, 
        instagram, 
        pinterest, 
        twitter, 
        linkedin, 
        youtube, 
        schedule_time 
    } = req.body;
    
    const mediaFiles = req.files?.['images'] || [];
    const thumbnailFiles = req.files?.['thumbnail'] || [];

    const isTrue = (val) => val === 'true' || val === true;
    const postMode = mode || 'manual';

    // মূল কনটেন্ট যদি ফাঁকা থাকে তবে ইউটিউব ডেসক্রিপশন বা টুইটার ক্যাপশন ব্যাকআপ হিসেবে নেবে
    const finalMainContent = content || youtube_description || twitter_caption || twitter_content || '';
    const finalTwitterContent = twitter_caption || twitter_content || content || null;

    const platforms = {
        facebook: isTrue(facebook),
        instagram: isTrue(instagram),
        pinterest: isTrue(pinterest),
        twitter: isTrue(twitter),
        linkedin: isTrue(linkedin),
        youtube: isTrue(youtube)
    };

    try {
        // ফাইল আপলোড...
        const imagePaths = [];
        for (const file of mediaFiles) {
            const url = await uploadSingleFile(file, userId, req.get('host'));
            imagePaths.push(url);
        }

        let thumbnailUrl = null;
        if (thumbnailFiles.length > 0) {
            thumbnailUrl = await uploadSingleFile(thumbnailFiles[0], userId, req.get('host'));
        }

        // 🎯 Neon Database Insert Query
        const query = `
            INSERT INTO user_posts 
            (user_id, mode, content, twitter_content, youtube_title, youtube_description, youtube_tags, thumbnail_url, platforms, schedule_time, images) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) 
            RETURNING *;
        `;
        
        const values = [
            userId,
            postMode,
            finalMainContent,                    // $3: null হবে না
            finalTwitterContent,                 // $4: twitter_content কলামে বসবে
            youtube_title || null,               // $5
            youtube_description || finalMainContent || null, // $6
            youtube_tags || null,                // $7
            thumbnailUrl,                        // $8
            JSON.stringify(platforms),           // $9
            postMode === 'schedule' && schedule_time ? new Date(schedule_time).toISOString() : null, // $10
            imagePaths                           // $11
        ];

        const result = await pool.query(query, values);
        return res.status(201).json({ success: true, post: result.rows[0] });

    } catch (error) {
        console.error('Save Post Error:', error.message);
        res.status(500).json({ success: false, message: error.message });
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
        // ১. সোশ্যাল অ্যাকাউন্টস ফেচ
        const query = 'SELECT platform, page_id, page_name, is_active FROM social_accounts WHERE user_id = $1::INTEGER';
        const result = await pool.query(query, [userId]);
        const accounts = result.rows;

        // ২. users টেবিল থেকে WhatsApp নম্বরটি ফেচ করে যুক্ত করা
        const userQuery = 'SELECT whatsapp_number FROM users WHERE id = $1::INTEGER';
        const userRes = await pool.query(userQuery, [userId]);

        if (userRes.rows.length > 0 && userRes.rows[0].whatsapp_number) {
            accounts.push({
                platform: 'whatsapp',
                page_name: userRes.rows[0].whatsapp_number,
                is_active: true
            });
        }

        res.status(200).json({
            success: true,
            accounts: accounts
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

        const aiPrompt = `
You are an expert social media and YouTube SEO content creator.
Based on this input: "${prompt}", generate JSON data with the following fields:
1. "caption": A detailed, engaging social media caption with emojis and hashtags (for FB/Instagram/LinkedIn).
2. "twitter_caption": A punchy, highly engaging tweet under 260 characters including 2-3 trending hashtags.
3. "youtube_title": A catchy, SEO-friendly YouTube title under 90 characters.
4. "youtube_description": A detailed YouTube description.
5. "youtube_tags": A comma-separated string of relevant YouTube tags.

Return ONLY a valid JSON object without markdown syntax or extra text:
{
  "caption": "...",
  "twitter_caption": "...",
  "youtube_title": "...",
  "youtube_description": "...",
  "youtube_tags": "..."
}
`;

        const response = await ai.models.generateContent({
            model: 'gemini-3.6-flash',
            contents: aiPrompt,
        });

        const rawText = typeof response.text === 'function' ? await response.text() : response.text;
        const cleanedJson = rawText.replace(/```json/g, '').replace(/```/g, '').trim();
        const parsedData = JSON.parse(cleanedJson);

        return res.status(200).json({
            success: true,
            data: parsedData
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
        
        const userQuery = 'SELECT id, email, name, profile_pic, whatsapp_number, created_at FROM users WHERE id = $1';
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
    const { name, profile_pic, whatsapp_number } = req.body;
    const userId = req.user.id;

    try {
        const updateQuery = `
            UPDATE users 
            SET name = COALESCE($1, name), 
                profile_pic = COALESCE($2, profile_pic),
                whatsapp_number = COALESCE($3, whatsapp_number)
            WHERE id = $4 
            RETURNING id, email, name, profile_pic, whatsapp_number;
        `;
        const result = await pool.query(updateQuery, [name, profile_pic, whatsapp_number, userId]);

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
   - If the user DOES NOT specify platforms, DEFAULT TO ALL ACCOUNTS: ["facebook", "instagram", "pinterest", "linkedin", "twitter"].

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
      "platforms": ["facebook", "instagram", "pinterest", "linkedin", "twitter"],
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
          JSON.stringify(post.platforms || { facebook: true, instagram: true, pinterest: true, linkedin: true, twitter: true }),
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

// ==========================================
// 🎥 YOUTUBE AUTH ROUTES
// ==========================================

// ১. ইউটিউব লগইন/কানেক্ট লিঙ্ক
app.get('/auth/youtube', (req, res) => {
    const userId = req.query.user_id;

    if (!userId) {
        return res.status(400).send('❌ ত্রুটি: user_id পাঠানো বাধ্যতামূলক!');
    }

    const clientId = process.env.GOOGLE_CLIENT_ID;
    const backendUrl = process.env.BACKEND_URL || 'https://social-backend-1hwz.onrender.com';
    const redirectUri = `${backendUrl}/auth/youtube/callback`;
    const state = JSON.stringify({ user_id: userId });

    const scopes = [
        'https://www.googleapis.com/auth/youtube.upload',
        'https://www.googleapis.com/auth/youtube.readonly'
    ].join(' ');

    const youtubeLoginUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent(scopes)}&access_type=offline&prompt=consent&state=${encodeURIComponent(state)}`;

    res.redirect(youtubeLoginUrl);
});

// ২. ইউটিউব কলব্যাক এবং ডাটাবেসে সেভ
app.get('/auth/youtube/callback', async (req, res) => {
    const { code, state: stateStr } = req.query;
    let userId = null;

    try {
        if (stateStr) {
            userId = JSON.parse(stateStr).user_id;
        }
    } catch (e) {
        console.error("State parse error:", e);
    }

    if (!code || !userId) {
        return res.status(400).send('❌ ত্রুটি: অথেন্টিকেশন কোড বা ইউজার আইডি পাওয়া যায়নি।');
    }

    try {
        const clientId = process.env.GOOGLE_CLIENT_ID;
        const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
        const backendUrl = process.env.BACKEND_URL || 'https://social-backend-1hwz.onrender.com';
        const redirectUri = `${backendUrl}/auth/youtube/callback`;

        const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', new URLSearchParams({
            code: code,
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code'
        }).toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const { access_token, refresh_token, expires_in } = tokenResponse.data;
        const expiresAt = new Date(Date.now() + expires_in * 1000);

        const channelResponse = await axios.get('https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        const channel = channelResponse.data.items?.[0];

        if (!channel) {
            return res.status(404).send('❌ কোনো ইউটিউব চ্যানেল পাওয়া যায়নি!');
        }

        const channelId = channel.id;
        const channelName = channel.snippet.title;

        const checkQuery = 'SELECT * FROM social_accounts WHERE page_id = $1 AND user_id = $2 AND platform = $3';
        const existing = await pool.query(checkQuery, [channelId, userId, 'youtube']);

        if (existing.rows.length > 0) {
            const updateQuery = `
                UPDATE social_accounts 
                SET access_token = $1, 
                    refresh_token = COALESCE($2, refresh_token), 
                    expires_at = $3, 
                    page_name = $4, 
                    is_active = TRUE, 
                    updated_at = NOW() 
                WHERE page_id = $5 AND user_id = $6 AND platform = 'youtube'
            `;
            await pool.query(updateQuery, [access_token, refresh_token, expiresAt, channelName, channelId, userId]);
        } else {
            const insertQuery = `
                INSERT INTO social_accounts (user_id, page_id, page_name, access_token, refresh_token, expires_at, is_active, platform) 
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            `;
            await pool.query(insertQuery, [userId, channelId, channelName, access_token, refresh_token, expiresAt, true, 'youtube']);
        }

        res.send(`
            <html>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px; background-color: #f4f6f9;">
                <div style="max-width: 500px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
                    <h2 style="color: #cc0000;">🎉 YouTube চ্যানেল সফলভাবে কানেক্ট হয়েছে!</h2>
                    <p style="color: #555;">চ্যানেল: <b>${channelName}</b></p>
                    <p style="font-weight: bold;">ট্যাবটি বন্ধ করে অ্যাপে ফিরে যান।</p>
                </div>
            </body>
            </html>
        `);
    } catch (error) {
        console.error("YouTube Auth Error:", error.response?.data || error.message);
        res.status(500).send('YouTube Authentication failed!');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`সার্ভার সফলভাবে পোর্ট ${PORT}-এ রান হচ্ছে!`);
});