const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
const axios = require('axios');

const app = express();

// মিডলওয়্যার
app.use(express.json());
app.use(cors());

// রেন্ডার ড্যাশবোর্ডের Environment Variable থেকে স্বয়ংক্রিয়ভাবে Neon ডাটাবেজ কানেকশন নেবে
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// সার্ভার ঠিকঠাক চলছে কি না তা টেস্ট করার রুট
app.get('/', (req, res) => {
    res.send('Node.js Backend Server with Neon DB & Supabase Integration is running!');
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

// ৩. ফেসবুক লগইন রিডাইরেক্ট রাউট
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

// ৪. ফেসবুক কলব্যাক রাউট
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
        return res.status(400).send('❌ ত্রুটি: অথোরাইজেশন কোড বা ইউজার আইডি পাওয়া যায়নি!');
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
            const checkQuery = 'SELECT * FROM social_accounts WHERE page_id = $1';
            const existing = await pool.query(checkQuery, [page.id]);

            if (existing.rows.length > 0) {
                const updateQuery = 'UPDATE social_accounts SET user_id = $1, access_token = $2, is_active = TRUE, platform = $3, updated_at = NOW() WHERE page_id = $4';
                await pool.query(updateQuery, [userId, page.access_token, 'facebook', page.id]);
            } else {
                const insertQuery = 'INSERT INTO social_accounts (user_id, page_id, access_token, is_active, platform) VALUES ($1, $2, $3, $4, $5)';
                await pool.query(insertQuery, [userId, page.id, page.access_token, true, 'facebook']);
            }
        }

        res.send(`
            <html>
                <body style="font-family: Arial, text-align: center; padding: 50px;">
                    <h2 style="color: #28a745;">🎉 ফেসবুক পেজ সফলভাবে কানেক্ট হয়েছে!</h2>
                    <p>টোকেন সফলভাবে Neon Database-এ সেভ করা হয়েছে। আপনি এই ট্যাব বন্ধ করে অ্যাপে ফিরে যেতে পারেন।</p>
                </body>
            </html>
        `);
    } catch (error) {
        console.error("Facebook Auth Error:", error.response?.data || error.message);
        res.status(500).send('Authentication failed!');
    }
});

// ৫. ফ্লাটার অ্যাপ থেকে পোস্ট এবং Supabase ইমেজ লিংক সেভ করার আপডেট করা এপিআই
app.post('/api/save-post', async (req, res) => {
    const { user_id, mode, content, facebook, instagram, pinterest, schedule_time, images } = req.body;
    
    // প্ল্যাটফর্ম সিলেকশন বুলিয়ান ফরম্যাটে রূপান্তর
    const platforms = {
        facebook: facebook === true || facebook === 'true',
        instagram: instagram === 'true' || instagram === true,
        pinterest: pinterest === 'true' || pinterest === true
    };

    // Supabase থেকে আসা পাবলিক ইমেজ লিংকের অ্যারে
    const imageLinks = images || [];

    try {
        const query = `
            INSERT INTO user_posts (user_id, mode, content, platforms, schedule_time, images) 
            VALUES ($1, $2, $3, $4, $5, $6) 
            RETURNING *;
        `;
        const values = [
            user_id, 
            mode, 
            content, 
            JSON.stringify(platforms), 
            schedule_time || null, 
            imageLinks // নিয়ন ডাটাবেজে Supabase-এর লিংকগুলো অ্যারে হিসেবে সেভ হচ্ছে
        ];
        
        const result = await pool.query(query, values);
        const savedPost = result.rows[0];

        // n8n-এ ডেটা ফরোয়ার্ড করার লজিক
        if (process.env.N8N_WEBHOOK_URL) {
            try {
                await axios.post(process.env.N8N_WEBHOOK_URL, savedPost);
                console.log('Post data with Supabase image links successfully forwarded to n8n');
            } catch (n8nError) {
                console.error('Error forwarding to n8n:', n8nError.message);
            }
        }

        res.status(201).json({
            success: true,
            message: 'Post and Supabase image links saved successfully in Neon DB and forwarded to n8n!',
            post: savedPost
        });
    } catch (error) {
        console.error('Save Post Error:', error.message);
        res.status(500).json({ success: false, message: 'Server error: ' + error.message });
    }
});

// সার্ভার পোর্ট কনফিগারেশন
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`=================================`);
    console.log(`সার্ভার সফলভাবে পোর্ট ${PORT}-এ রান হচ্ছে!`);
    console.log(`=================================`);
});