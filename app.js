require('dotenv').config();

const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');

const { initialize, pool } = require('./db');
const { SESSION_MAX_AGE } = require('./config');
const { attachCurrentUser } = require('./middleware/auth');
const authRoutes = require('./routes/auth');
const eventRoutes = require('./routes/events');
const pdfRoutes = require('./routes/pdf');
const passkeyRoutes = require('./routes/passkey');
const logger = require('./logger');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const pgSession = require('connect-pg-simple')(session);
const { doubleCsrf } = require('csrf-csrf');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Trust proxy ────────────────────────────────────────────────────────────
// Required when running behind a reverse proxy (nginx, load balancer, etc.)
// so that req.ip and rate limiters see the real client IP from X-Forwarded-For.
app.set('trust proxy', 1);

// ─── View engine ────────────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── CSS asset manifest (written by scripts/fingerprint-css.js) ────────────
const manifestPath = path.join(__dirname, 'public', 'css', 'manifest.json');
let cssManifest = {};
if (fs.existsSync(manifestPath)) {
  cssManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
}

// ─── Static files ───────────────────────────────────────────────────────────
// Fingerprinted CSS files get immutable long-lived cache headers;
// everything else relies on ETag / conditional requests.
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res, filePath) {
    if (/tailwind\.[a-f0-9]{8}\.css$/.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    }
  },
}));

// ─── Security headers ───────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://static.cloudflareinsights.com"],  // inline scripts in EJS views
      scriptSrcAttr: ["'unsafe-inline'"],        // inline event handlers (onclick etc.)
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    },
  },
  hsts: process.env.NODE_ENV === 'production'
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false,
  crossOriginEmbedderPolicy: false, // not needed for a traditional web app
}));
app.use(compression());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Trim all string body fields so routes always receive clean input
app.use((req, res, next) => {
  if (req.body && typeof req.body === 'object') {
    for (const key of Object.keys(req.body)) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = req.body[key].trim();
      }
    }
  }
  next();
});

app.use(session({
  store: new pgSession({ pool, createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'strict', maxAge: SESSION_MAX_AGE }
}));
app.use(attachCurrentUser);

// Expose fingerprinted CSS path to all views
app.use((req, res, next) => {
  res.locals.cssFile = cssManifest['tailwind.css'] || '/css/tailwind.css';
  next();
});

// ─── CSRF protection ────────────────────────────────────────────────────────
const { generateToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.SESSION_SECRET || 'change-this-secret-in-production',
  cookieName: 'x-csrf-token',
  getTokenFromRequest: (req) => req.body?._csrf || req.headers['x-csrf-token'],
  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
  },
});
app.use(doubleCsrfProtection);
app.use((req, res, next) => {
  res.locals.csrfToken = generateToken(req, res, false, false);
  next();
});

// ─── Request logging ────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    logger.info({ method: req.method, url: req.url, status: res.statusCode, ms: Date.now() - start });
  });
  next();
});

// ─── Routes ─────────────────────────────────────────────────────────────────
app.use('/', authRoutes);
app.use('/', eventRoutes);
app.use('/', pdfRoutes);
app.use('/', passkeyRoutes);

// ─── 404 ────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).render('404');
});

// ─── Global error handler ────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const errorId = Math.random().toString(36).slice(2, 9).toUpperCase();
  logger.error({ err, errorId, method: req.method, url: req.url }, 'Unhandled error');
  if (res.headersSent) return next(err);
  res.status(500).render('500', { errorId });
});

process.on('unhandledRejection', (reason) => {
  logger.error({ reason }, 'Unhandled promise rejection');
});

// ─── Server ─────────────────────────────────────────────────────────────────
const certPath = path.join(__dirname, 'server.crt');
const keyPath  = path.join(__dirname, 'server.key');

async function start() {
  await initialize();

  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    const credentials = {
      cert: fs.readFileSync(certPath),
      key:  fs.readFileSync(keyPath)
    };
    https.createServer(credentials, app).listen(PORT, () => {
      logger.info(`Server running at https://localhost:${PORT}`);
    });
  } else {
    http.createServer(app).listen(PORT, () => {
      logger.info(`Server running at http://localhost:${PORT}`);
    });
  }
}

start().catch(err => {
  logger.error({ err }, 'Failed to start server');
  process.exit(1);
});
