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

        // ঘ. Neon ডাটাবেজে সঠিক ডেটা এবং updated_at আপডেট করার লজিক
        for (const page of pages) {
            const checkQuery = 'SELECT * FROM social_accounts WHERE page_id = $1';
            const existing = await pool.query(checkQuery, [page.id]);

            if (existing.rows.length > 0) {
                const updateQuery = 'UPDATE social_accounts SET access_token = $1, is_active = TRUE, updated_at = NOW() WHERE page_id = $2';
                await pool.query(updateQuery, [page.access_token, page.id]);
            } else {
                const insertQuery = 'INSERT INTO social_accounts (page_id, access_token, is_active) VALUES ($1, $2, $3)';
                await pool.query(insertQuery, [page.id, page.access_token, true]);
            }
        }

      // JSON রেসপন্স পাঠানোর বদলে এটি দিন:
res.redirect('socialautomation://success?status=true');

    } catch (error) {
        console.error("Facebook Auth Error:", error.response?.data || error.message);
        res.status(500).send('Authentication failed!');
    }
});

// ফেসবুক পেজে পোস্ট করার এপিআই
app.post('/api/post-to-facebook', async (req, res) => {
    const { page_id, message } = req.body;
    try {
        const result = await pool.query('SELECT access_token FROM social_accounts WHERE page_id = $1', [page_id]);
        if (result.rows.length === 0) return res.status(404).send('Page not found!');
        
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

app.post('/api/reply-to-comment', async (req, res) => {
    const { page_id, comment_id, reply_message } = req.body;
    try {
        const result = await pool.query('SELECT access_token FROM social_accounts WHERE page_id = $1', [page_id]);
        if (result.rows.length === 0) return res.status(404).send('Page not found!');
        
        const token = result.rows[0].access_token;
        const replyUrl = `https://graph.facebook.com/v18.0/${comment_id}/comments`;
        await axios.post(replyUrl, {
            message: reply_message,
            access_token: token
        });

        res.json({ success: true, message: "Reply posted successfully!" });
    } catch (error) {
        console.error("Reply Error:", error.response?.data || error.message);
        res.status(500).json({ error: error.message });
    }
});  
// ফেসবুক ইনবক্স মেসেজে রিপ্লাই পাঠানোর এপিআই
app.post('/api/reply-to-message', async (req, res) => {
    const { page_id, recipient_id, message } = req.body;
    try {
        // ১. ডাটাবেজ থেকে ওই পেজের সঠিক টোকেন বের করা
        const result = await pool.query('SELECT access_token FROM social_accounts WHERE page_id = $1', [page_id]);
        if (result.rows.length === 0) return res.status(404).send('Page not found!');
        
        const token = result.rows[0].access_token;

        // ২. ফেসবুক গ্রাফ এপিআই-এর মাধ্যমে মেসেজ পাঠানো (Send API)
        const messageUrl = `https://graph.facebook.com/v18.0/me/messages?access_token=${token}`;
        const response = await axios.post(messageUrl, {
            recipient: { id: recipient_id },
            message: { text: message }
        });

        res.json({ success: true, messageId: response.data.message_id });
    } catch (error) {
        console.error("Message Reply Error:", error.response?.data || error.message);
        res.status(500).json({ error: error.response?.data || error.message });
    }
});

// ৫. ফেসবুক ওয়েবুক ভেরিফিকেশন (GET Route)
app.get('/api/webhook', (req, res) => {
    const VERIFY_TOKEN = process.env.FB_VERIFY_TOKEN || 'my_secure_verify_token';

    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode && token) {
        if (mode === 'subscribe' && token === VERIFY_TOKEN) {
            console.log('WEBHOOK_VERIFIED');
            res.status(200).send(challenge);
        } else {
            res.sendStatus(403);
        }
    } else {
        res.sendStatus(400);
    }
});

// ৬. ফেসবুক ওয়েবুক ডেটা রিসিভ এবং n8n-এ ফরোয়ার্ড করার জন্য (POST Route)
app.post('/api/webhook', async (req, res) => {
    const body = req.body;

    if (body.object === 'page') {
        try {
            // n8n এ রিকোয়েস্ট পাঠানোর জন্য নিরাপদ লুপ
            for (const entry of body.entry) {
                // সরাসরি পুরো বডি বা এন্ট্রি ডেটা n8n-এর প্রোডাকশন বা টেস্ট ওয়েবুকে পাঠিয়ে দেওয়া হচ্ছে
                if (process.env.N8N_WEBHOOK_URL) {
                    await axios.post(process.env.N8N_WEBHOOK_URL, body);
                    console.log('Webhook data successfully forwarded to n8n');
                } else {
                    console.error('N8N_WEBHOOK_URL is not defined in environment variables!');
                }
            }
        } catch (error) {
            console.error('Error forwarding to n8n:', error.message);
        }

        res.status(200).send('EVENT_RECEIVED');
    } else {
        res.sendStatus(404);
    }
});

// সার্ভার পোর্ট কনফিগারেশন
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`=================================`);
  console.log(`সার্ভার সফলভাবে পোর্ট ${PORT}-এ রান হচ্ছে!`);
  console.log(`=================================`);
});