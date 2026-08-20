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

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(cors());
app.use('/uploads', express.static('uploads'));

// 🛡️ Rate Limiter (১ মিনিটে সর্বোচ্চ ৫টি রিকোয়েস্ট)
const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 5,
  validate: { xForwardedForHeader: false },
  message: { success: false, message: 'অতিরিক্ত চেষ্টা করা হয়েছে! অনুগ্রহ করে ১ মিনিট পর আবার চেষ্টা করুন।' }
});

// 🔍 ফেক ইমেইল ফিল্টার
const isDisposableEmail = (email) => {
  const disposableDomains = ['tempmail.com', '10minutemail.com', 'dispostable.com', 'guerrillamail.com', 'yopmail.com'];
  const domain = email.split('@')[1]?.toLowerCase();
  return disposableDomains.includes(domain);
};

// 🔐 পাসওয়ার্ড স্ট্রেন্থ চেক (৮ ক্যারেক্টার + ১টি বড় হাতের + ১টি ছোট হাতের অক্ষর)
const validatePassword = (password) => {
  if (!password || password.length < 8) {
    return 'পাসওয়ার্ড কমপক্ষে ৮ অক্ষরের হতে হবে!';
  }
  if (!/[A-Z]/.test(password)) {
    return 'পাসওয়ার্ডে অন্তত একটি বড় হাতের অক্ষর (A-Z) থাকতে হবে!';
  }
  if (!/[a-z]/.test(password)) {
    return 'পাসওয়ার্ডে অন্তত একটি ছোট হাতের অক্ষর (a-z) থাকতে হবে!';
  }
  return null;
};

// 🤖 n8n Webhook দিয়ে OTP পাঠানোর হেলপার
const sendOtpViaN8n = async (email, otp, title) => {
    const n8nWebhookUrl = process.env.N8N_OTP_WEBHOOK_URL;
    
    if (!n8nWebhookUrl) {
        throw new Error('n8n Webhook URL এনভায়রনমেন্ট ভ্যারিয়েবলে যুক্ত করা হয়নি!');
    }

    try {
        await axios.post(n8nWebhookUrl, {
            email: email,
            otp: otp,
            title: title
        });
    } catch (error) {
        console.error('n8n Webhook Error:', error.message);
        throw new Error('n8n অটোমেশনের মাধ্যমে ইমেইল পাঠাতে ব্যর্থ হয়েছে');
    }
};

// 🌐 Google Auth Client
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '910096214036-4gi7puoqg1edarqub27v7mluqqt6fht6.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// 🚀 Supabase Client
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = (SUPABASE_URL && SUPABASE_KEY) ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;

// 🗄️ Neon DB Pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secure_secret_key_123';

// 🛡️ টোকেন ভেরিফিকেশন মিডলওয়্যার
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
    res.send('Server is running smoothly with n8n & Neon DB!');
});

// 📩 ১. OTP সেন্ড করার এপিআই
app.post('/api/send-otp', authLimiter, async (req, res) => {
    const { email, type } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'ইমেইল আবশ্যক!' });
    }

    if (isDisposableEmail(email)) {
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
        await sendOtpViaN8n(email, otp, mailTitle);

        res.status(200).json({ success: true, message: 'ইমেইলে OTP সফলভাবে পাঠানো হয়েছে!' });
    } catch (err) {
        console.error('Send OTP Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// 🔑 ২. রেজিস্ট্রেশন এপিআই
app.post('/api/register', authLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'ইমেইল এবং পাসওয়ার্ড আবশ্যক!' });
    }

    if (isDisposableEmail(email)) {
        return res.status(400).json({ success: false, message: 'ফেক বা টেম্পোরারি ইমেইল দিয়ে অ্যাকাউন্ট খোলা যাবে না!' });
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
        return res.status(400).json({ success: false, message: passwordError });
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
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// 🔄 ৩. পাসওয়ার্ড রিসেট এপিআই
app.post('/api/reset-password', authLimiter, async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.status(400).json({ success: false, message: 'সবগুলো ঘর পূরণ করা আবশ্যক!' });
    }

    const passwordError = validatePassword(newPassword);
    if (passwordError) {
        return res.status(400).json({ success: false, message: passwordError });
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

        res.status(200).json({ success: true, message: 'পাসওয়ার্ড সফলভাবে পরিবর্তন করা হয়েছে! এখন লগইন করুন।' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// 🔓 ৪. লগইন এপিআই (ধাপ ১)
app.post('/api/login', authLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'ইমেইল এবং পাসওয়ার্ড আবশ্যক!' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'ইউজার পাওয়া যায়নি!' });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'পাসওয়ার্ড ভুল হয়েছে!' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        await pool.query('DELETE FROM email_otps WHERE email = $1', [email]);
        await pool.query('INSERT INTO email_otps (email, otp, expires_at) VALUES ($1, $2, $3)', [email, otp, expiresAt]);

        await sendOtpViaN8n(email, otp, 'আপনার লগইন ভেরিফিকেশন OTP');

        res.status(200).json({
            success: true,
            requiresOtp: true,
            message: 'পাসওয়ার্ড সঠিক! আপনার ইমেইলে OTP পাঠানো হয়েছে।'
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 🔓 ৪. লগইন OTP ভেরিফাই (ধাপ ২)
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
        res.status(500).json({ success: false, message: 'সার্ভার সমস্যা: ' + err.message });
    }
});

// 🌐 ৫. গুগল লগইন এপিআই
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

        let result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        let user;

        if (result.rows.length === 0) {
            const dummyPasswordHash = await bcrypt.hash(googleId + '_google_secret', 10);
            const insertResult = await pool.query(
                'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, created_at',
                [email, dummyPasswordHash]
            );
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

// 🚀 ৬. পোস্ট সেভ এবং n8n পোস্ট সোশ্যাল মিডিয়া ট্র্রিগার (সম্পূর্ণ ইমেজ আপলোডসহ)
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
            return `https://${req.get('host')}/uploads/${file.filename}`;
        } finally {
            try {
                if (fs.existsSync(file.path)) {
                    fs.unlinkSync(file.path);
                }
            } catch (unlinkErr) {}
        }
    };

    try {
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
            schedule_time ? new Date(schedule_time).toISOString() : null,
            imagePaths
        ];

        const result = await pool.query(query, values);
        const savedPost = result.rows[0];

        if (process.env.N8N_WEBHOOK_URL) {
            try {
                await axios.post(process.env.N8N_WEBHOOK_URL, savedPost);
            } catch (n8nError) {
                console.error('n8n-এ পোস্ট পাঠাতে সমস্যা:', n8nError.message);
            }
        }

        return res.status(201).json({
            success: true,
            message: 'পোস্ট সফলভাবে সেভ ও n8n-এ ফরওয়ার্ড হয়েছে!',
            post: savedPost
        });

    } catch (error) {
        console.error('Save Post Error:', error.message);
        res.status(500).json({ success: false, message: 'Server error: ' + error.message });
    }
});

// 🛡️ ৪-০-৪ হ্যান্ডলার
app.use((req, res) => {
    res.status(404).json({ success: false, message: 'এপিআই এন্ডপয়েন্ট পাওয়া যায়নি (404 Not Found)' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`সার্ভার পোর্ট ${PORT}-এ রান হচ্ছে!`);
});