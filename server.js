const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const axios = require('axios');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const { OAuth2Client } = require('google-auth-library');
const { Resend } = require('resend'); // 💡 Nodemailer এর বদলে Resend

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(cors());
app.use('/uploads', express.static('uploads'));

// ✉️ Resend API ইনিশিয়ালাইজেশন
const resend = new Resend('re_2YHG1Bmx_K6cXdswhWUAxyYFrXZutJw3L');

// 🛡️ ব্রুট-ফোর্স সিকিউরিটির জন্য Rate Limiter (১ মিনিটে সর্বোচ্চ ৫ রিকোয়েস্ট)
const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 5,
  validate: { xForwardedForHeader: false },
  message: { success: false, message: 'অতিরিক্ত চেষ্টা করা হয়েছে! অনুগ্রহ করে ১ মিনিট পর আবার চেষ্টা করুন।' }
});

// 🎲 Resend দিয়ে OTP ইমেইল পাঠানোর হেলপার ফাংশন
const sendOtpEmail = async (email, otp, title) => {
    try {
        const data = await resend.emails.send({
            from: 'onboarding@resend.dev', // Resend-এর ডিফল্ট টেস্ট সেন্ডার
            to: email,
            subject: title,
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px; max-width: 500px;">
                    <h2 style="color: #6200ee;">${title}</h2>
                    <p style="font-size: 16px;">আপনার সিকিউরিটি OTP কোড হলো:</p>
                    <div style="background-color: #f3f4f6; padding: 12px; text-align: center; border-radius: 6px; margin: 15px 0;">
                        <span style="font-size: 28px; font-weight: bold; letter-spacing: 4px; color: #111827;">${otp}</span>
                    </div>
                    <p style="font-size: 14px; color: #6b7280;">কোডটি আগামী ৫ মিনিটের জন্য কার্যকর থাকবে। এটি কারো সাথে শেয়ার করবেন না।</p>
                </div>
            `
        });
        console.log('Email sent via Resend successfully:', data);
        return data;
    } catch (error) {
        console.error('Resend Send Error:', error);
        throw new Error('ইমেইল পাঠাতে সমস্যা হয়েছে: ' + error.message);
    }
};

// 🌐 Google Auth Client ইনিশিয়ালিজেশন
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '910096214036-4gi7puoqg1edarqub27v7mluqqt6fht6.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// 🚀 Supabase Client সেটআপ
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = (SUPABASE_URL && SUPABASE_KEY) ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;

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

// 📩 ১. OTP সেন্ড করার এপিআই (পাসওয়ার্ড রিসেটের জন্য)
app.post('/api/send-otp', authLimiter, async (req, res) => {
    const { email, type } = req.body; // type: 'reset'

    if (!email) {
        return res.status(400).json({ success: false, message: 'ইমেইল আবশ্যক!' });
    }

    const disposableDomains = ['tempmail.com', '10minutemail.com', 'dispostable.com', 'guerrillamail.com'];
    const emailDomain = email.split('@')[1]?.toLowerCase();
    if (disposableDomains.includes(emailDomain)) {
        return res.status(400).json({ success: false, message: 'ফেক বা টেম্পোরারি ইমেইল গ্রহণযোগ্য নয়!' });
    }

    try {
        if (type === 'reset') {
            const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            if (userCheck.rows.length === 0) {
                return res.status(404).json({ success: false, message: 'এই ইমেইল দিয়ে কোনো অ্যাকাউন্ট পাওয়া যায়নি!' });
            }
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        await pool.query('DELETE FROM email_otps WHERE email = $1', [email]);
        await pool.query('INSERT INTO email_otps (email, otp, expires_at) VALUES ($1, $2, $3)', [email, otp, expiresAt]);

        const mailTitle = type === 'reset' ? 'পাসওয়ার্ড রিসেট OTP' : 'আপনার ইমেইল ভেরিফিকেশন OTP';
        await sendOtpEmail(email, otp, mailTitle);

        res.status(200).json({ success: true, message: 'ইমেইলে OTP সফলভাবে পাঠানো হয়েছে!' });
    } catch (err) {
        console.error('Send OTP Error:', err);
        res.status(500).json({ success: false, message: 'OTP পাঠাতে সমস্যা হয়েছে: ' + err.message });
    }
});

// ২. সরাসরি রেজিস্ট্রেশন এপিআই (OTP ছাড়া)
app.post('/api/register', authLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'ইমেইল এবং পাসওয়ার্ড আবশ্যক!' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, created_at';
        const result = await pool.query(query, [email, hashedPassword]);

        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '365d' });

        res.status(201).json({
            success: true,
            message: 'সফলভাবে অ্যাকাউন্ট তৈরি হয়েছে!',
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

// 🔑 ৩. ফরগেট পাসওয়ার্ড দিয়ে নতুন পাসওয়ার্ড সেট করার এপিআই
app.post('/api/reset-password', authLimiter, async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.status(400).json({ success: false, message: 'সবগুলো ঘর পূরণ করা আবশ্যক!' });
    }

    try {
        const otpResult = await pool.query(
            'SELECT * FROM email_otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()',
            [email, otp]
        );

        if (otpResult.rows.length === 0) {
            return res.status(400).json({ success: false, message: 'ভুল অথবা মেয়াদোত্তীর্ণ OTP!' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);
        await pool.query('DELETE FROM email_otps WHERE email = $1', [email]);

        res.status(200).json({ success: true, message: 'পাসওয়ার্ড সফলভাবে পরিবর্তন করা হয়েছে! এখন নতুন পাসওয়ার্ড দিয়ে লগইন করুন।' });
    } catch (err) {
        console.error('Reset Password Error:', err);
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// ৪. ধাপ ১: ইমেইল ও পাসওয়ার্ড দিয়ে লগইন চেষ্টা এবং ইমেইলে OTP পাঠানো
app.post('/api/login', authLimiter, async (req, res) => {
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

        // পাসওয়ার্ড সঠিক হলে ইমেইলে OTP পাঠাব
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        await pool.query('DELETE FROM email_otps WHERE email = $1', [email]);
        await pool.query('INSERT INTO email_otps (email, otp, expires_at) VALUES ($1, $2, $3)', [email, otp, expiresAt]);

        await sendOtpEmail(email, otp, 'আপনার লগইন ভেরিফিকেশন OTP');

        res.status(200).json({
            success: true,
            requiresOtp: true,
            message: 'পাসওয়ার্ড সঠিক! আপনার ইমেইলে OTP পাঠানো হয়েছে।'
        });
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// ৪. ধাপ ২: লগইন OTP ভেরিফাই করা
app.post('/api/login-verify-otp', authLimiter, async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ success: false, message: 'ইমেইল এবং OTP আবশ্যক!' });
    }

    try {
        const otpResult = await pool.query(
            'SELECT * FROM email_otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()',
            [email, otp]
        );

        if (otpResult.rows.length === 0) {
            return res.status(400).json({ success: false, message: 'ভুল অথবা মেয়াদোত্তীর্ণ OTP!' });
        }

        const userResult = await pool.query('SELECT id, email FROM users WHERE email = $1', [email]);
        const user = userResult.rows[0];

        await pool.query('DELETE FROM email_otps WHERE email = $1', [email]);

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '365d' });

        res.status(200).json({
            success: true,
            message: 'সফলভাবে লগইন হয়েছে!',
            token: token,
            user: { id: user.id, email: user.email }
        });
    } catch (err) {
        console.error('Verify Login OTP Error:', err);
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// 🌐 ৫. গুগল লগইন / রেজিস্ট্রেশন এপিআই
app.post('/api/google-login', async (req, res) => {
    const { id_token } = req.body;

    if (!id_token) {
        return res.status(400).json({ success: false, message: 'Google ID Token আবশ্যক!' });
    }

    try {
        const ticket = await googleClient.verifyIdToken({
            idToken: id_token,
            audience: GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();
        const { email, sub: googleId } = payload;

        if (!email) {
            return res.status(400).json({ success: false, message: 'গুগল অ্যাকাউন্টে কোনো ইমেইল পাওয়া যায়নি!' });
        }

        let query = 'SELECT * FROM users WHERE email = $1';
        let result = await pool.query(query, [email]);

        let user;

        if (result.rows.length === 0) {
            const dummyPasswordHash = await bcrypt.hash(googleId + '_google_secret', 10);
            const insertQuery = 'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, created_at';
            
            const insertResult = await pool.query(insertQuery, [email, dummyPasswordHash]);
            user = insertResult.rows[0];
        } else {
            user = result.rows[0];
        }

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '365d' });

        return res.status(200).json({
            success: true,
            message: 'গুগল দিয়ে সফলভাবে লগইন হয়েছে!',
            token: token,
            user: { id: user.id, email: user.email }
        });

    } catch (err) {
        console.error('Google Auth Error:', err.message);
        return res.status(400).json({ success: false, message: 'গুগল অথেন্টিকেশন ব্যর্থ হয়েছে: ' + err.message });
    }
});

// ৬. ফেসবুক লগইন রিডাইরেক্ট
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

// ৭. ফেসবুক কলব্যাক
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
            await pool.query('DELETE FROM social_accounts WHERE user_id = $1 AND platform = $2', [userId, 'facebook']);

            const insertQuery = 'INSERT INTO social_accounts (user_id, page_id, access_token, is_active, platform, page_name) VALUES ($1, $2, $3, $4, $5, $6)';
            await pool.query(insertQuery, [userId, page.id, page.access_token, true, 'facebook', page.name]);
        }

        res.send(`<html><body style="font-family: Arial; text-align: center; padding: 50px;"><h2>🎉 ফেসবুক পেজ সফলভাবে কানেক্ট হয়েছে!</h2><p>ট্যাবটি বন্ধ করে অ্যাপে ফিরে যান।</p></body></html>`);
    } catch (error) {
        console.error("Facebook Auth Error:", error.response?.data || error.message);
        res.status(500).send('Authentication failed!');
    }
});

// 🚀 ৮. পোস্ট ডেটা সেভ করার এপিআই
app.post('/api/save-post', authenticateToken, upload.array('images'), async (req, res) => {
    const userId = req.user.id;
    const { mode, content, facebook, instagram, pinterest, schedule_time } = req.body;
    
    const platforms = {
        facebook: facebook === 'true',
        instagram: instagram === 'true',
        pinterest: pinterest === 'true'
    };

    const files = req.files || [];

    const uploadSingleFile = async (file) => {
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
                    return `https://${req.get('host')}/uploads/${file.filename}`;
                } else {
                    const { data: publicUrlData } = supabase.storage
                        .from('postimages')
                        .getPublicUrl(fileName);
                    return publicUrlData.publicUrl;
                }
            } else {
                return `https://${req.get('host')}/uploads/${file.filename}`;
            }
        } catch (uploadErr) {
            console.error('File Upload Error:', uploadErr.message);
            return `https://${req.get('host')}/uploads/${file.filename}`;
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

    try {
        if (mode === 'schedule') {
            const baseDate = schedule_time ? new Date(schedule_time) : new Date();
            const savedPosts = [];

            if (files.length > 0) {
                for (let i = 0; i < files.length; i++) {
                    const imageUrl = await uploadSingleFile(files[i]);
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
                const url = await uploadSingleFile(file);
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

// ৯. ইউজার অ্যাকাউন্টস স্ট্যাটাস চেক
app.get('/user/accounts', async (req, res) => {
    const userId = req.query.user_id;
    if (!userId) {
        return res.status(400).json({ success: false, message: 'user_id আবশ্যক!' });
    }

    try {
        const query = 'SELECT platform, page_name FROM social_accounts WHERE user_id = $1 AND is_active = true';
        const result = await pool.query(query, [userId]);
        
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('Fetch Accounts Error:', err);
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// ১০. অ্যাকাউন্ট ডিসকানেক্ট
app.post('/auth/disconnect', async (req, res) => {
    const { user_id, platform } = req.body;
    if (!user_id || !platform) {
        return res.status(400).json({ success: false, message: 'user_id এবং platform আবশ্যক!' });
    }

    try {
        const query = 'DELETE FROM social_accounts WHERE user_id = $1 AND platform = $2';
        await pool.query(query, [user_id, platform.toLowerCase().trim()]);

        res.status(200).json({ 
            success: true, 
            message: `${platform} সফলভাবে ডিসকানেক্ট ও ডাটাবেস থেকে রিমুভ করা হয়েছে।` 
        });
    } catch (err) {
        console.error('Disconnect Error:', err);
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// 🛡️ গ্লোবাল ৪-০-৪ হ্যান্ডলার
app.use((req, res) => {
    res.status(404).json({ success: false, message: 'অনুরোধকৃত এপিআই এন্ডপয়েন্টটি পাওয়া যায়নি (404 Not Found)' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`সার্ভার সফলভাবে পোর্ট ${PORT}-এ রান হচ্ছে!`);
});