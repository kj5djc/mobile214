const express = require('express');
const { pool } = require('../db');
const logger = require('../logger');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// Lazy-load ESM-only @simplewebauthn/server
let _webauthn;
async function loadWebAuthn() {
  if (!_webauthn) _webauthn = await import('@simplewebauthn/server');
  return _webauthn;
}

// WebAuthn Relying Party configuration
const rpName = process.env.WEBAUTHN_RP_NAME || 'mobile214';
const rpID = process.env.WEBAUTHN_RP_ID || 'localhost';
const origin = process.env.WEBAUTHN_ORIGIN || process.env.APP_BASE_URL || 'http://localhost:3000';

// ─── Registration (requires auth) ──────────────────────────────────────────

router.post('/passkey/register/options', requireAuth, async (req, res) => {
  try {
    const { generateRegistrationOptions } = await loadWebAuthn();
    const userId = req.session.userId;
    const user = req.session.user;

    const { rows: existing } = await pool.query(
      'SELECT id, transports FROM passkeys WHERE user_id = $1',
      [userId]
    );

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: new TextEncoder().encode(String(userId)),
      userName: user.email,
      userDisplayName: user.username,
      attestationType: 'none',
      excludeCredentials: existing.map(pk => ({
        id: pk.id,
        transports: pk.transports || [],
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    req.session.passkeyChallenge = options.challenge;
    res.json(options);
  } catch (err) {
    logger.error({ err }, 'Passkey registration options error');
    res.status(500).json({ error: 'Failed to generate registration options.' });
  }
});

router.post('/passkey/register/verify', requireAuth, async (req, res) => {
  try {
    const { verifyRegistrationResponse } = await loadWebAuthn();
    const expectedChallenge = req.session.passkeyChallenge;

    if (!expectedChallenge) {
      return res.status(400).json({ error: 'No challenge found. Please try again.' });
    }

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'Verification failed.' });
    }

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

    await pool.query(
      `INSERT INTO passkeys (id, user_id, public_key, counter, device_type, backed_up, transports, name)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        credential.id,
        req.session.userId,
        Buffer.from(credential.publicKey),
        credential.counter,
        credentialDeviceType,
        credentialBackedUp,
        credential.transports || [],
        'My Passkey',
      ]
    );

    delete req.session.passkeyChallenge;
    logger.info({ userId: req.session.userId }, 'Passkey registered');
    res.json({ verified: true });
  } catch (err) {
    logger.error({ err }, 'Passkey registration verify error');
    res.status(500).json({ error: 'Verification failed.' });
  }
});

// ─── Authentication (no auth required) ─────────────────────────────────────

router.post('/passkey/login/options', async (req, res) => {
  try {
    const { generateAuthenticationOptions } = await loadWebAuthn();

    const options = await generateAuthenticationOptions({
      rpID,
      userVerification: 'preferred',
    });

    req.session.passkeyChallenge = options.challenge;
    res.json(options);
  } catch (err) {
    logger.error({ err }, 'Passkey login options error');
    res.status(500).json({ error: 'Failed to generate authentication options.' });
  }
});

router.post('/passkey/login/verify', async (req, res) => {
  try {
    const { verifyAuthenticationResponse } = await loadWebAuthn();
    const expectedChallenge = req.session.passkeyChallenge;

    if (!expectedChallenge) {
      return res.status(400).json({ error: 'No challenge found.' });
    }

    const credentialId = req.body.id;
    const { rows } = await pool.query(
      `SELECT p.*, u.id AS uid, u.username, u.email, u.email_verified
       FROM passkeys p JOIN users u ON p.user_id = u.id
       WHERE p.id = $1`,
      [credentialId]
    );
    const passkey = rows[0];

    if (!passkey) {
      return res.status(400).json({ error: 'Passkey not found.' });
    }
    if (!passkey.email_verified) {
      return res.status(400).json({ error: 'Email not verified.' });
    }

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: passkey.id,
        publicKey: passkey.public_key,
        counter: Number(passkey.counter),
        transports: passkey.transports || [],
      },
    });

    if (!verification.verified) {
      return res.status(400).json({ error: 'Authentication failed.' });
    }

    // Update signature counter
    await pool.query(
      'UPDATE passkeys SET counter = $1 WHERE id = $2',
      [verification.authenticationInfo.newCounter, passkey.id]
    );

    delete req.session.passkeyChallenge;

    // Log the user in (regenerate session to prevent fixation)
    req.session.regenerate((err) => {
      if (err) {
        logger.error({ err }, 'Session regeneration error');
        return res.status(500).json({ error: 'Login failed.' });
      }
      req.session.userId = passkey.uid;
      req.session.user = { id: passkey.uid, username: passkey.username, email: passkey.email };
      req.session.save((saveErr) => {
        if (saveErr) {
          logger.error({ err: saveErr }, 'Session save error');
          return res.status(500).json({ error: 'Login failed.' });
        }
        logger.info({ userId: passkey.uid }, 'User logged in via passkey');
        res.json({ verified: true });
      });
    });
  } catch (err) {
    logger.error({ err }, 'Passkey login verify error');
    res.status(500).json({ error: 'Authentication failed.' });
  }
});

// ─── Management (requires auth) ────────────────────────────────────────────

router.get('/account', requireAuth, async (req, res) => {
  try {
    const { rows: passkeys } = await pool.query(
      'SELECT id, name, created_at, device_type, backed_up FROM passkeys WHERE user_id = $1 ORDER BY created_at DESC',
      [req.session.userId]
    );
    res.render('account', { passkeys });
  } catch (err) {
    logger.error({ err }, 'Account page error');
    res.status(500).render('500');
  }
});

router.post('/passkey/delete', requireAuth, async (req, res) => {
  try {
    const { passkeyId } = req.body;
    if (!passkeyId || typeof passkeyId !== 'string') {
      return res.status(400).json({ error: 'Missing passkey ID.' });
    }

    const result = await pool.query(
      'DELETE FROM passkeys WHERE id = $1 AND user_id = $2',
      [passkeyId, req.session.userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Passkey not found.' });
    }

    logger.info({ userId: req.session.userId, passkeyId }, 'Passkey deleted');
    res.json({ deleted: true });
  } catch (err) {
    logger.error({ err }, 'Delete passkey error');
    res.status(500).json({ error: 'Failed to delete passkey.' });
  }
});

module.exports = router;
