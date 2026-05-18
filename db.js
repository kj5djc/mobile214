const { Pool } = require('pg');

const pool = new Pool(
  process.env.DATABASE_URL
    ? { connectionString: process.env.DATABASE_URL }
    : {} // falls back to PGHOST / PGPORT / PGDATABASE / PGUSER / PGPASSWORD env vars
);

async function initialize() {
  // Verify database connectivity before running migrations
  let client;
  try {
    client = await pool.connect();
    await client.query('SELECT 1');
  } catch (err) {
    const msg = process.env.DATABASE_URL
      ? `DATABASE_URL=${process.env.DATABASE_URL}`
      : `host=${process.env.PGHOST || 'localhost'} db=${process.env.PGDATABASE || ''}}`;
    throw new Error(`Cannot connect to database (${msg}): ${err.message}`);
  } finally {
    if (client) client.release();
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id          SERIAL PRIMARY KEY,
      username    TEXT UNIQUE NOT NULL,
      email       TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS events (
      id          SERIAL PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES users(id),
      name        TEXT NOT NULL,
      description TEXT,
      deleted_at  TIMESTAMPTZ DEFAULT NULL,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS updates (
      id          SERIAL PRIMARY KEY,
      event_id    INTEGER NOT NULL REFERENCES events(id),
      content     TEXT NOT NULL,
      deleted_at  TIMESTAMPTZ DEFAULT NULL,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_events_user_id        ON events (user_id);
    CREATE INDEX IF NOT EXISTS idx_updates_event_id       ON updates (event_id);
    CREATE INDEX IF NOT EXISTS idx_users_email             ON users (email);

    CREATE TABLE IF NOT EXISTS passkeys (
      id          TEXT PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      public_key  BYTEA NOT NULL,
      counter     BIGINT NOT NULL DEFAULT 0,
      device_type TEXT,
      backed_up   BOOLEAN DEFAULT FALSE,
      transports  TEXT[],
      name        TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys (user_id);
  `);

  // Soft-delete columns – safe to run on an existing DB
  await pool.query(`
    ALTER TABLE events  ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;
    ALTER TABLE updates ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_events_user_deleted     ON events (user_id, deleted_at);
    CREATE INDEX IF NOT EXISTS idx_updates_event_deleted   ON updates (event_id, deleted_at);
  `);
}

module.exports = { pool, initialize };
