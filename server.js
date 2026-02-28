const express = require('express');
const cors = require('cors');
const axios = require('axios');
const dotenv = require('dotenv');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { neon } = require('@neondatabase/serverless');

dotenv.config();

// Initialize Stripe AFTER dotenv so env vars are available
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_not_configured');

const app = express();

// ═══════════════════════════════════════════════════════════════════════════════
// ENV SECRETS (set these on Vercel Dashboard → Environment Variables)
//   JWT_SECRET            → any long random string (e.g. openssl rand -hex 32)
//   GOOGLE_CLIENT_ID      → Google OAuth Client ID
//   GOOGLE_CLIENT_SECRET  → Google OAuth Client Secret
//   ENTITLEMENT_SIGN_KEY  → HMAC key for signing entitlement tokens (server-only)
// ═══════════════════════════════════════════════════════════════════════════════

const JWT_SECRET            = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID      = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET  = process.env.GOOGLE_CLIENT_SECRET;
const ENTITLEMENT_SIGN_KEY  = process.env.ENTITLEMENT_SIGN_KEY || JWT_SECRET; // Fallback to JWT_SECRET

// Startup validation
if (!JWT_SECRET) console.error('⚠️  CRITICAL: JWT_SECRET env var is not set! Auth will fail.');
if (!GOOGLE_CLIENT_ID) console.error('⚠️  CRITICAL: GOOGLE_CLIENT_ID env var is not set!');
if (!ENTITLEMENT_SIGN_KEY) console.error('⚠️  CRITICAL: ENTITLEMENT_SIGN_KEY not set! Entitlement signing will fail.');

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 1: CORS — Only allow requests from FocusFlow origins
// ═══════════════════════════════════════════════════════════════════════════════
const allowedOrigins = [
    'http://localhost:5176',
    'http://localhost:5177',
    'app://.',
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (allowedOrigins.some(o => origin.startsWith(o))) return callback(null, true);
        if (origin.startsWith('http://127.0.0.1:')) return callback(null, true);
        return callback(new Error('Blocked by CORS'), false);
    },
    credentials: true,
}));

// ═══════════════════════════════════════════════════════════════════════════════
// DATABASE — Neon Postgres
// ═══════════════════════════════════════════════════════════════════════════════
const sql = neon(process.env.DATABASE_URL);

let tablesReady = false;
async function ensureTablesExist() {
    if (tablesReady) return;
    await sql`
        CREATE TABLE IF NOT EXISTS users (
            email       TEXT PRIMARY KEY,
            trial_start TIMESTAMPTZ DEFAULT NOW(),
            plan        TEXT DEFAULT 'free',
            valid_until TIMESTAMPTZ,
            redeemed_code TEXT,
            redeemed_at   TIMESTAMPTZ
        )
    `;
    await sql`
        CREATE TABLE IF NOT EXISTS redeemed_codes (
            code       TEXT PRIMARY KEY,
            used_by    TEXT NOT NULL,
            used_at    TIMESTAMPTZ DEFAULT NOW(),
            duration   TEXT NOT NULL,
            valid_until TIMESTAMPTZ
        )
    `;
    tablesReady = true;
    console.log('[DB] Postgres tables ready.');
}

// Helper: get or create user
async function getOrCreateUser(email) {
    await ensureTablesExist();
    const rows = await sql`SELECT * FROM users WHERE email = ${email}`;
    if (rows.length > 0) return rows[0];
    const result = await sql`
        INSERT INTO users (email, trial_start, plan)
        VALUES (${email}, NOW(), 'free')
        RETURNING *
    `;
    return result[0];
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRIPE WEBHOOK (Must be raw body for signature verification)
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/paywall/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error('[Stripe Webhook Error]', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    await ensureTablesExist();

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const customerEmail = session.customer_details?.email;
        if (customerEmail) {
            await getOrCreateUser(customerEmail);
            await sql`UPDATE users SET plan = 'pro' WHERE email = ${customerEmail}`;
            console.log(`[Stripe] Upgraded ${customerEmail} to PRO.`);
        }
    }

    res.send({ received: true });
});

app.use(express.json());

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 2: Rate Limiting
// ═══════════════════════════════════════════════════════════════════════════════
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    message: { error: 'Too many requests. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const sessionLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: 'Too many session attempts.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const generalLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 60,
    message: { error: 'Too many requests. Please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use(generalLimiter);

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 3: Google ID Token Verification
// Verifies that a Google ID token is genuine and extracts the user's email.
// This replaces the old APP_KEY/APP_SIGNATURE approach.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Verify Google ID token using Google's tokeninfo endpoint.
 * Returns the token payload (email, sub, etc.) or null if invalid.
 */
async function verifyGoogleIdToken(idToken) {
    try {
        // Use Google's tokeninfo endpoint for robust verification
        const response = await axios.get(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`);
        const payload = response.data;

        // Verify the audience matches OUR client ID
        if (payload.aud !== GOOGLE_CLIENT_ID) {
            console.warn('[Auth] ID token audience mismatch:', payload.aud);
            return null;
        }

        // Verify the token hasn't expired
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && parseInt(payload.exp) < now) {
            console.warn('[Auth] ID token expired');
            return null;
        }

        // Verify email is verified
        if (payload.email_verified !== 'true' && payload.email_verified !== true) {
            console.warn('[Auth] Email not verified');
            return null;
        }

        return {
            email: payload.email,
            name: payload.name,
            picture: payload.picture,
            sub: payload.sub,     // Google's unique user ID
        };
    } catch (err) {
        console.error('[Auth] Google ID token verification failed:', err.response?.data || err.message);
        return null;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 4: User-Level JWT Authentication
// JWTs now contain the verified user email — every request is tied to a user.
// ═══════════════════════════════════════════════════════════════════════════════

function generateUserAccessToken(userPayload) {
    return jwt.sign(
        { email: userPayload.email, sub: userPayload.sub, type: 'access' },
        JWT_SECRET,
        { expiresIn: '15m' }
    );
}

function generateUserRefreshToken(userPayload) {
    return jwt.sign(
        { email: userPayload.email, sub: userPayload.sub, type: 'refresh' },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
}

/**
 * Middleware: Verify user JWT and attach user info to req.user
 * The JWT contains the verified email from Google sign-in.
 */
function verifyUserJWT(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        // Ensure this is an access token, not a refresh token
        if (decoded.type !== 'access') {
            return res.status(403).json({ error: 'Invalid token type' });
        }

        // Ensure the token has a verified email
        if (!decoded.email) {
            return res.status(403).json({ error: 'Token missing user identity' });
        }

        req.user = {
            email: decoded.email,
            sub: decoded.sub,
        };
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
        }
        return res.status(403).json({ error: 'Invalid token' });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// USER SESSION — Replaces the old app-level handshake
// User authenticates with their Google ID token → gets user-level JWT
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/auth/session', sessionLimiter, async (req, res) => {
    try {
        const { id_token } = req.body;

        if (!id_token) {
            return res.status(400).json({ error: 'Missing id_token' });
        }

        if (!JWT_SECRET) {
            console.error('[Session] JWT_SECRET is not configured!');
            return res.status(500).json({ error: 'Server misconfigured' });
        }

        // Verify the Google ID token server-side
        const googleUser = await verifyGoogleIdToken(id_token);
        if (!googleUser) {
            return res.status(401).json({ error: 'Invalid or expired Google ID token' });
        }

        // Generate user-level JWTs (email is baked into the token)
        const access_token  = generateUserAccessToken(googleUser);
        const refresh_token = generateUserRefreshToken(googleUser);

        console.log(`[Session] User session created for ${googleUser.email}`);

        res.json({
            access_token,
            refresh_token,
            expires_in: 900, // 15 minutes
            user: {
                email: googleUser.email,
                name: googleUser.name,
                picture: googleUser.picture,
            },
        });
    } catch (err) {
        console.error('[Session] Error:', err);
        res.status(500).json({ error: 'Session creation failed' });
    }
});

// Refresh expired JWT using refresh token
app.post('/api/auth/token/refresh', async (req, res) => {
    const { refresh_token } = req.body;

    if (!refresh_token) {
        return res.status(400).json({ error: 'Missing refresh_token' });
    }

    try {
        const decoded = jwt.verify(refresh_token, JWT_SECRET);

        // Ensure this is a refresh token
        if (decoded.type !== 'refresh') {
            return res.status(403).json({ error: 'Invalid token type' });
        }

        const new_access_token = generateUserAccessToken({
            email: decoded.email,
            sub: decoded.sub,
        });

        res.json({
            access_token: new_access_token,
            expires_in: 900,
        });
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired refresh token. Re-authenticate required.' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
// LEGACY HANDSHAKE — Keep for backwards compatibility during rollout
// Will be removed in a future version. New clients use /api/auth/session.
// ═══════════════════════════════════════════════════════════════════════════════
const APP_KEY = process.env.APP_KEY;
const APP_SIGNATURE = 'FocusFlow/2.x';

function verifyAppSignature(req, res, next) {
    const sig = req.headers['x-app-signature'];
    if (!sig || sig !== APP_SIGNATURE) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
}

// Legacy handshake for old clients
const handshakeLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Too many handshake attempts.' },
    standardHeaders: true,
    legacyHeaders: false,
});

app.post('/api/auth/handshake', handshakeLimiter, verifyAppSignature, (req, res) => {
    try {
        const { app_key } = req.body;
        if (!app_key || app_key !== APP_KEY) {
            return res.status(403).json({ error: 'Invalid app key' });
        }
        if (!JWT_SECRET) {
            return res.status(500).json({ error: 'Server misconfigured: JWT_SECRET missing' });
        }
        // Legacy tokens don't have user identity — they're app-level
        const payload = { app: 'focusflow', type: 'access', iat: Date.now() };
        const access_token  = jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });
        const refresh_token = jwt.sign({ ...payload, type: 'refresh' }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ access_token, refresh_token, expires_in: 900 });
    } catch (err) {
        console.error('[Handshake] Error:', err);
        res.status(500).json({ error: 'Handshake failed: ' + err.message });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
// DUAL AUTH MIDDLEWARE
// Accepts both user-level JWT (new) and app-level JWT (legacy)
// For endpoints that can work with both during migration
// ═══════════════════════════════════════════════════════════════════════════════

function verifyAnyJWT(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.email) {
            // User-level JWT
            req.user = { email: decoded.email, sub: decoded.sub };
        } else {
            // Legacy app-level JWT — no user identity
            req.user = null;
        }
        req.appSession = decoded;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
        }
        return res.status(403).json({ error: 'Invalid token' });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROTECTED ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── Google OAuth Code Exchange ──
// This endpoint does NOT require JWT — it's used for initial login.
// The Google auth code itself is the proof of identity.
// Rate-limited to prevent abuse.
app.post('/api/auth/google', authLimiter, async (req, res) => {
    const { code, redirect_uri } = req.body;
    if (!code || !redirect_uri) {
        return res.status(400).json({ error: 'Missing code or redirect_uri' });
    }

    try {
        const response = await axios.post('https://oauth2.googleapis.com/token', {
            client_id: GOOGLE_CLIENT_ID,
            client_secret: GOOGLE_CLIENT_SECRET,
            code,
            grant_type: 'authorization_code',
            redirect_uri
        });

        const tokens = response.data;
        tokens.expiry_date = Date.now() + (tokens.expires_in * 1000);
        res.json(tokens);
    } catch (err) {
        console.error('[Token Exchange Error]', err.response?.data || err.message);
        res.status(400).json({ error: 'Failed to exchange token', details: err.response?.data });
    }
});

// ── Google Token Refresh ──
// Public endpoint (rate-limited). Required during session restoration before JWT exists.
// The Google refresh_token is the proof of identity.
app.post('/api/auth/refresh', authLimiter, async (req, res) => {
    const { refresh_token } = req.body;
    if (!refresh_token) {
        return res.status(400).json({ error: 'Missing refresh_token' });
    }

    try {
        const response = await axios.post('https://oauth2.googleapis.com/token', {
            client_id: GOOGLE_CLIENT_ID,
            client_secret: GOOGLE_CLIENT_SECRET,
            refresh_token,
            grant_type: 'refresh_token'
        });

        const credentials = response.data;
        credentials.expiry_date = Date.now() + (credentials.expires_in * 1000);
        res.json(credentials);
    } catch (err) {
        console.error('[Token Refresh Error]', err.response?.data || err.message);
        res.status(400).json({ error: 'Failed to refresh token', details: err.response?.data });
    }
});

// ── Spotify Code Exchange ──
app.post('/api/auth/spotify', authLimiter, verifyAnyJWT, async (req, res) => {
    const { code, redirect_uri } = req.body;
    if (!code || !redirect_uri) {
        return res.status(400).json({ error: 'Missing code or redirect_uri' });
    }

    try {
        const response = await axios.post('https://accounts.spotify.com/api/token',
            new URLSearchParams({
                code,
                redirect_uri,
                grant_type: 'authorization_code'
            }).toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': 'Basic ' + Buffer.from(process.env.SPOTIFY_CLIENT_ID + ':' + process.env.SPOTIFY_CLIENT_SECRET).toString('base64')
                }
            }
        );
        res.json(response.data);
    } catch (err) {
        console.error('[Spotify Token Error]', err.response?.data || err.message);
        res.status(400).json({ error: 'Failed to exchange Spotify token', details: err.response?.data });
    }
});

// ── Spotify Token Refresh ──
app.post('/api/auth/spotify/refresh', authLimiter, verifyAnyJWT, async (req, res) => {
    const { refresh_token } = req.body;
    if (!refresh_token) {
        return res.status(400).json({ error: 'Missing refresh_token' });
    }

    try {
        const response = await axios.post('https://accounts.spotify.com/api/token',
            new URLSearchParams({
                refresh_token,
                grant_type: 'refresh_token'
            }).toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': 'Basic ' + Buffer.from(process.env.SPOTIFY_CLIENT_ID + ':' + process.env.SPOTIFY_CLIENT_SECRET).toString('base64')
                }
            }
        );
        res.json(response.data);
    } catch (err) {
        console.error('[Spotify Refresh Error]', err.response?.data || err.message);
        res.status(400).json({ error: 'Failed to refresh Spotify token', details: err.response?.data });
    }
});

// ── Public Client Identifiers ──
// These are NOT secrets — they're embedded in every OAuth redirect URL.
// Rate-limited but no JWT required (needed for initial login before user has JWT).
app.get('/api/auth/spotify/client-id', authLimiter, (req, res) => {
    res.json({ client_id: process.env.SPOTIFY_CLIENT_ID });
});

app.get('/api/auth/google/client-id', authLimiter, (req, res) => {
    res.json({ client_id: process.env.GOOGLE_CLIENT_ID });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ENTITLEMENT SIGNING — Server-signed entitlement tokens
// These are signed with ENTITLEMENT_SIGN_KEY (server-only, never shipped to client).
// The client can verify the signature using the public verification endpoint.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

function signEntitlement(entitlement, email) {
    const payload = JSON.stringify({ entitlement, email, issuedAt: Date.now() });
    const signature = crypto
        .createHmac('sha256', ENTITLEMENT_SIGN_KEY)
        .update(payload)
        .digest('hex');
    return { payload, signature };
}

// Verification endpoint — client sends payload + signature, server confirms
app.post('/api/paywall/verify-entitlement', verifyUserJWT, async (req, res) => {
    const { payload, signature } = req.body;
    if (!payload || !signature) {
        return res.status(400).json({ valid: false, error: 'Missing payload or signature' });
    }

    try {
        const expectedSig = crypto
            .createHmac('sha256', ENTITLEMENT_SIGN_KEY)
            .update(payload)
            .digest('hex');

        if (expectedSig !== signature) {
            return res.json({ valid: false, error: 'Signature mismatch' });
        }

        const parsed = JSON.parse(payload);

        // Verify the email in the entitlement matches the authenticated user
        if (parsed.email !== req.user.email) {
            return res.json({ valid: false, error: 'Email mismatch' });
        }

        // Check if the signed token is too old (max 7 days offline grace)
        const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
        if (Date.now() - parsed.issuedAt > MAX_AGE_MS) {
            return res.json({ valid: false, error: 'Entitlement token expired' });
        }

        return res.json({ valid: true, entitlement: parsed.entitlement });
    } catch (err) {
        return res.json({ valid: false, error: 'Verification failed' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
// PAYWALL ENDPOINTS — Now require USER-level JWT (email verified via Google)
// ═══════════════════════════════════════════════════════════════════════════════

const FREE_FEATURES = {
    maxTasks: 50, maxNotes: 10, maxReminders: 5, maxProjects: 2, maxHabits: 5,
    maxBooks: 10, maxKpis: 3, kanbanView: false, gmailIntegration: false,
    calendarSync: false, analyticsHistory: 7, ceoCockpitFull: false,
    pdfExport: false, customThemes: false, customShortcuts: false,
    allSidebarTabs: false, cloudBackup: false, ambientSounds: false,
    customFocusDuration: false, dailyReflection: false, commandPalette: false,
    templateBrowser: false, hardReminderOverlay: false, customBreakInterval: false,
    workspaceAnalytics: false, prioritySupport: false, xpMultiplier: 1, maxThemes: 3
};

const PRO_FEATURES = {
    maxTasks: -1, maxNotes: -1, maxReminders: -1, maxProjects: -1, maxHabits: -1,
    maxBooks: -1, maxKpis: -1, kanbanView: true, gmailIntegration: true,
    calendarSync: true, analyticsHistory: -1, ceoCockpitFull: true,
    pdfExport: true, customThemes: true, customShortcuts: true,
    allSidebarTabs: true, cloudBackup: true, ambientSounds: true,
    customFocusDuration: true, dailyReflection: true, commandPalette: true,
    templateBrowser: true, hardReminderOverlay: true, customBreakInterval: true,
    workspaceAnalytics: true, prioritySupport: true, xpMultiplier: 2, maxThemes: -1
};

app.post('/api/paywall/entitlement', authLimiter, verifyUserJWT, async (req, res) => {
    // Email comes from the verified JWT — NOT from the request body
    const email = req.user.email;

    try {
        // ── PRO WHITELIST (env var: comma-separated emails) ──
        const whitelist = (process.env.PRO_WHITELIST || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
        if (whitelist.includes(email.toLowerCase())) {
            const entitlement = {
                plan: 'pro',
                trialActive: false,
                trialEndsAt: null,
                validUntil: null,
                features: PRO_FEATURES
            };
            const signed = signEntitlement(entitlement, email);
            return res.json({ entitlement, signed });
        }

        const user = await getOrCreateUser(email);

        const trialStart = new Date(user.trial_start);
        const TRIAL_DURATION_DAYS = 0;
        const trialEndsAt = new Date(trialStart.getTime() + TRIAL_DURATION_DAYS * 24 * 60 * 60 * 1000);
        const trialActive = TRIAL_DURATION_DAYS > 0 && new Date() < trialEndsAt;

        let isPro = user.plan === 'pro';

        // ── Expiration check for timed promo codes ──
        if (isPro && user.valid_until) {
            const expiresAt = new Date(user.valid_until);
            if (new Date() > expiresAt) {
                await sql`UPDATE users SET plan = 'free', valid_until = NULL WHERE email = ${email}`;
                isPro = false;
                console.log(`[Paywall] Subscription expired for ${email}, downgraded to free.`);
            }
        }

        const planType = isPro ? (user.valid_until ? 'pro' : 'lifetime') : 'free';

        const entitlement = {
            plan: planType,
            trialActive: !isPro && trialActive,
            trialEndsAt: trialEndsAt.toISOString(),
            validUntil: user.valid_until || null,
            features: (isPro || trialActive) ? PRO_FEATURES : FREE_FEATURES
        };

        // Sign the entitlement so the client can cache it securely
        const signed = signEntitlement(entitlement, email);

        res.json({ entitlement, signed });
    } catch (err) {
        console.error('[Entitlement] Error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/paywall/checkout', authLimiter, verifyUserJWT, async (req, res) => {
    const email = req.user.email;
    const { plan, successUrl, cancelUrl } = req.body;

    const PRICE_ID = plan === 'monthly' ? process.env.STRIPE_PRICE_MONTHLY : process.env.STRIPE_PRICE_LIFETIME;

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            customer_email: email,
            line_items: [{ price: PRICE_ID || 'dummy_price_id', quantity: 1 }],
            mode: plan === 'monthly' ? 'subscription' : 'payment',
            success_url: successUrl,
            cancel_url: cancelUrl,
        });

        res.json({ checkoutUrl: session.url });
    } catch (err) {
        console.error('[Stripe Checkout Error]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
// PROMO CODE REDEMPTION — Now email comes from verified JWT
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/paywall/redeem', authLimiter, verifyUserJWT, async (req, res) => {
    const email = req.user.email; // From verified JWT, not request body
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Missing code' });

    const normalizedCode = code.trim().toUpperCase();

    if (!/^[A-Z0-9]{10}$/.test(normalizedCode)) {
        return res.status(400).json({ error: 'Invalid code format. Must be 10 alphanumeric characters.' });
    }

    // Parse promo codes from env var
    const promoCodes = {};
    (process.env.PROMO_CODES || '').split(',').forEach(entry => {
        const [c, duration] = entry.trim().split(':');
        if (c && duration) {
            promoCodes[c.trim().toUpperCase()] = duration.trim().toLowerCase();
        }
    });

    if (!promoCodes[normalizedCode]) {
        return res.status(404).json({ error: 'Invalid or expired promo code.' });
    }

    try {
        await ensureTablesExist();

        // Check if code has already been used
        const existing = await sql`SELECT * FROM redeemed_codes WHERE code = ${normalizedCode}`;
        if (existing.length > 0) {
            return res.status(409).json({
                error: 'This promo code has already been redeemed.',
                usedAt: existing[0].used_at
            });
        }

        // Calculate subscription validity
        const durationStr = promoCodes[normalizedCode];
        let validUntil = null;

        if (durationStr !== 'lifetime') {
            const days = parseInt(durationStr, 10);
            if (isNaN(days) || days <= 0) {
                return res.status(500).json({ error: 'Server misconfiguration: invalid code duration.' });
            }
            validUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
        }

        // Mark code as redeemed
        await sql`
            INSERT INTO redeemed_codes (code, used_by, used_at, duration, valid_until)
            VALUES (${normalizedCode}, ${email}, NOW(), ${durationStr}, ${validUntil})
        `;

        // Upgrade the user
        await getOrCreateUser(email);
        await sql`
            UPDATE users SET plan = 'pro', valid_until = ${validUntil},
                redeemed_code = ${normalizedCode}, redeemed_at = NOW()
            WHERE email = ${email}
        `;

        console.log(`[Promo] Code ${normalizedCode} redeemed by ${email} — ${durationStr === 'lifetime' ? 'Lifetime' : durationStr + ' days'}`);

        // Return signed entitlement
        const entitlement = {
            plan: 'pro',
            trialActive: false,
            trialEndsAt: null,
            validUntil,
            features: PRO_FEATURES,
        };
        const signed = signEntitlement(entitlement, email);

        res.json({
            success: true,
            message: durationStr === 'lifetime'
                ? 'Lifetime Pro access activated! 🎉'
                : `Pro access activated for ${durationStr} days! 🎉`,
            validUntil,
            plan: 'pro',
            entitlement,
            signed,
        });
    } catch (err) {
        console.error('[Redeem] Error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 5000;
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`FocusFlow Backend running on port ${PORT}`);
        console.log('🔒 Protected: CORS + Rate Limit + User JWT + Google ID Token Verification');
    });
}
module.exports = app;
