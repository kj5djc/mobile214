const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { pool } = require('../db');
const logger = require('../logger');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../mailer');
const { BCRYPT_ROUNDS, AUTH_RATE_LIMIT_WINDOW_MS, AUTH_RATE_LIMIT_MAX, EMAIL_VERIFICATION_EXPIRY_MS, PASSWORD_RESET_EXPIRY_MS } = require('../config');

const router = express.Router();

const authLimiter = rateLimit({
  windowMs: AUTH_RATE_LIMIT_WINDOW_MS,
  max: AUTH_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn({ ip: req.ip, url: req.url }, 'Rate limit exceeded');
    res.status(429).render('429');
  },
});

// Basic but reliable email format check
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Ensure APP_BASE_URL always has a scheme so email links are valid https:// URLs.
// If the env var is missing a scheme (e.g. "mobile214.example.com") macOS Mail
// rewrites the href to its internal x-webdoc:// scheme and the link breaks.
function getBaseUrl(req) {
  const raw = (process.env.APP_BASE_URL || '').replace(/\/+$/, '');
  if (raw) {
    return /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  }
  return `${req.protocol}://${req.get('host')}`;
}

// Home
router.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('index');
});

// Register
router.get('/register', authLimiter, (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('register', { error: null });
});

router.post('/register', authLimiter, async (req, res) => {
  const email = (req.body.email || '').toLowerCase();
  const { password, confirm_password } = req.body;

  if (!email || !password) {
    return res.render('register', { error: 'All fields are required.' });
  }
  if (!EMAIL_RE.test(email)) {
    return res.render('register', { error: 'Please enter a valid email address.' });
  }
  if (password !== confirm_password) {
    return res.render('register', { error: 'Passwords do not match.' });
  }
  if (password.length < 6) {
    return res.render('register', { error: 'Password must be at least 6 characters.' });
  }

  try {
    const username = email.split('@')[0];
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + EMAIL_VERIFICATION_EXPIRY_MS);
    await pool.query(
      'INSERT INTO users (username, email, password_hash, verification_token, verification_token_expires_at) VALUES ($1, $2, $3, $4, $5)',
      [username, email, hash, token, expiresAt]
    );
    const baseUrl = getBaseUrl(req);
    const verifyUrl = `${baseUrl}/verify-email?token=${token}`;
    await sendVerificationEmail(email, verifyUrl);
    logger.info({ email }, 'User registered — verification email sent');
    res.render('verify-email-sent', { email });
  } catch (err) {
    if (err.code === '23505') {
      res.render('register', { error: 'Email already registered.' });
    } else {
      logger.error({ err }, 'Registration error');
      res.render('register', { error: 'Something went wrong. Please try again.' });
    }
  }
});

// Login
router.get('/login', authLimiter, (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('login', { error: null, registered: req.query.registered === '1', reset: req.query.reset === '1' });
});

router.post('/login', authLimiter, async (req, res) => {
  const email = (req.body.email || '').toLowerCase();
  const { password } = req.body;

  if (!email || !password) {
    return res.render('login', { error: 'All fields are required.', registered: false, reset: false });
  }
  if (!EMAIL_RE.test(email)) {
    return res.render('login', { error: 'Invalid email or password.', registered: false, reset: false });
  }

  const { rows } = await pool.query(
    'SELECT * FROM users WHERE email = $1',
    [email]
  );
  const user = rows[0];
  if (!user) {
    return res.render('login', { error: 'Invalid email or password.', registered: false, reset: false });
  }

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    return res.render('login', { error: 'Invalid email or password.', registered: false, reset: false });
  }

  if (!user.email_verified) {
    return res.render('login', { error: 'Please verify your email address before signing in. Check your inbox for the verification link.', registered: false, reset: false });
  }

  // Regenerate session ID to prevent session fixation attacks
  req.session.regenerate((err) => {
    if (err) {
      logger.error({ err }, 'Session regeneration error');
      return res.render('login', { error: 'Something went wrong. Please try again.', registered: false, reset: false });
    }
    req.session.userId = user.id;
    req.session.user = { id: user.id, username: user.username, email: user.email };
    req.session.save((saveErr) => {
      if (saveErr) {
        logger.error({ err: saveErr }, 'Session save error');
        return res.render('login', { error: 'Something went wrong. Please try again.', registered: false, reset: false });
      }
      logger.info({ userId: user.id }, 'User logged in');
      res.redirect('/dashboard');
    });
  });
});

// Verify email
router.get('/verify-email', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).render('404');

  try {
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE verification_token = $1',
      [token]
    );
    const user = rows[0];
    if (!user) {
      return res.render('login', { error: 'Verification link is invalid.', registered: false, reset: false });
    }
    if (user.email_verified) {
      return res.redirect('/login?registered=1');
    }
    if (new Date() > new Date(user.verification_token_expires_at)) {
      return res.render('login', { error: 'Verification link has expired. Please register again.', registered: false, reset: false });
    }
    await pool.query(
      'UPDATE users SET email_verified = TRUE, verification_token = NULL, verification_token_expires_at = NULL WHERE id = $1',
      [user.id]
    );
    logger.info({ userId: user.id }, 'Email verified');
    res.redirect('/login?registered=1');
  } catch (err) {
    logger.error({ err }, 'Email verification error');
    res.status(500).render('500');
  }
});

// Forgot password
router.get('/forgot-password', authLimiter, (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('forgot-password', { error: null, success: false });
});

router.post('/forgot-password', authLimiter, async (req, res) => {
  const email = (req.body.email || '').toLowerCase();
  // Always show the same success message to prevent email enumeration
  const successReply = () => res.render('forgot-password', { error: null, success: true });

  if (!email || !EMAIL_RE.test(email)) {
    return res.render('forgot-password', { error: 'Please enter a valid email address.', success: false });
  }
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = rows[0];
    if (!user) return successReply(); // don't reveal whether email exists

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + PASSWORD_RESET_EXPIRY_MS);
    await pool.query(
      'UPDATE users SET reset_token = $1, reset_token_expires_at = $2 WHERE id = $3',
      [token, expiresAt, user.id]
    );
    const baseUrl = getBaseUrl(req);
    const resetUrl = `${baseUrl}/reset-password?token=${token}`;
    await sendPasswordResetEmail(email, resetUrl);
    logger.info({ userId: user.id }, 'Password reset email sent');
    successReply();
  } catch (err) {
    logger.error({ err }, 'Forgot password error');
    res.render('forgot-password', { error: 'Something went wrong. Please try again.', success: false });
  }
});

// Reset password
router.get('/reset-password', authLimiter, async (req, res) => {
  const { token } = req.query;
  if (!token) return res.render('login', { error: 'Invalid reset link.', registered: false });
  try {
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE reset_token = $1',
      [token]
    );
    const user = rows[0];
    if (!user || new Date() > new Date(user.reset_token_expires_at)) {
      return res.render('login', { error: 'This reset link is invalid or has expired. Please request a new one.', registered: false });
    }
    res.render('reset-password', { token, error: null });
  } catch (err) {
    logger.error({ err }, 'Reset password page error');
    res.status(500).render('500');
  }
});

router.post('/reset-password', authLimiter, async (req, res) => {
  const { token, password, confirm_password } = req.body;
  if (!token) return res.render('login', { error: 'Invalid reset link.', registered: false });

  if (!password || password.length < 6) {
    return res.render('reset-password', { token, error: 'Password must be at least 6 characters.' });
  }
  if (password !== confirm_password) {
    return res.render('reset-password', { token, error: 'Passwords do not match.' });
  }
  try {
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE reset_token = $1',
      [token]
    );
    const user = rows[0];
    if (!user || new Date() > new Date(user.reset_token_expires_at)) {
      return res.render('login', { error: 'This reset link is invalid or has expired. Please request a new one.', registered: false });
    }
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    await pool.query(
      'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires_at = NULL WHERE id = $2',
      [hash, user.id]
    );
    logger.info({ userId: user.id }, 'Password reset successfully');
    res.redirect('/login?reset=1');
  } catch (err) {
    logger.error({ err }, 'Reset password error');
    res.status(500).render('500');
  }
});

// Logout
router.get('/logout', (req, res) => {
  const userId = req.session.userId;
  req.session.destroy();
  logger.info({ userId }, 'User logged out');
  res.redirect('/login');
});

module.exports = router;
