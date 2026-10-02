'use strict';

/**
 * ============================================================
 * DORKNET SECURITY — HYBRID PERSISTENCE ENGINE
 * Enterprise Security Data Access Layer / AGATA-AI
 * ============================================================
 *
 * Architecture:
 *   Application Layer
 *       │
 *       ├── In-Memory Thread-Safe Cache
 *       │
 *       ├── PostgreSQL JSONB Store (Primary)
 *       │
 *       └── Atomic Local JSON File (Disaster Recovery Fallback)
 *
 * Features:
 *   - Automatic PostgreSQL schema bootstrap
 *   - Seamless fallback to atomic local JSON storage
 *   - In-process write queue serialization
 *   - Exponential / scheduled reconnect strategy
 *   - Automated backup rotation with mode permissions (0o640)
 *   - Health metrics & status inspection
 * ============================================================
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

// ============================================================
// CONFIGURATION & ENVIRONMENT
// ============================================================

const APP_NAME = 'DorkNet Security';

const DB_PATH =
  process.env.DB_LOCAL_PATH ||
  path.join(__dirname, 'db.json');

const BACKUP_DIR =
  process.env.DB_BACKUP_DIR ||
  path.join(__dirname, 'db-backups');

const DATABASE_URL = process.env.DATABASE_URL;

const NODE_ENV = process.env.NODE_ENV || 'development';

const IS_PRODUCTION = NODE_ENV === 'production';

const PG_CONNECTION_TIMEOUT =
  Number.parseInt(process.env.PG_CONNECTION_TIMEOUT || '5000', 10);

const PG_IDLE_TIMEOUT =
  Number.parseInt(process.env.PG_IDLE_TIMEOUT || '30000', 10);

const PG_MAX_CONNECTIONS =
  Number.parseInt(process.env.PG_MAX_CONNECTIONS || '10', 10);

const PG_RETRY_DELAY =
  Number.parseInt(process.env.PG_RETRY_DELAY || '5000', 10);

const ENABLE_LOCAL_BACKUP =
  process.env.DB_ENABLE_BACKUP !== 'false';

const MAX_BACKUPS =
  Number.parseInt(process.env.DB_MAX_BACKUPS || '10', 10);

// ============================================================
// INTERNAL STATE
// ============================================================

let memoryCache = null;
let pool = null;
let pgConnected = false;
let pgInitializing = false;
let reconnectTimer = null;
let writeQueue = Promise.resolve();
let lastDatabaseError = null;
let lastSuccessfulWrite = null;
let initializedAt = null;

// ============================================================
// UTILITIES
// ============================================================

function cloneDefaultData() {
  return {
    users: [],
    audits: [],
    transactions: []
  };
}

function cloneData(data) {
  return JSON.parse(JSON.stringify(data));
}

function generateBackupId() {
  return `${new Date()
    .toISOString()
    .replace(/[:.]/g, '-')}-${crypto.randomBytes(4).toString('hex')}`;
}

function normalizeData(data) {
  if (!data || typeof data !== 'object') {
    return cloneDefaultData();
  }

  return {
    users: Array.isArray(data.users) ? data.users : [],
    audits: Array.isArray(data.audits) ? data.audits : [],
    transactions: Array.isArray(data.transactions) ? data.transactions : []
  };
}

function getFileSize(filePath) {
  try {
    return fs.statSync(filePath).size;
  } catch (_) {
    return 0;
  }
}

// ============================================================
// LOCAL STORAGE MANAGEMENT
// ============================================================

function ensureLocalDirectories() {
  try {
    const parentDir = path.dirname(DB_PATH);

    if (!fs.existsSync(parentDir)) {
      fs.mkdirSync(parentDir, {
        recursive: true,
        mode: 0o750
      });
    }

    if (ENABLE_LOCAL_BACKUP && !fs.existsSync(BACKUP_DIR)) {
      fs.mkdirSync(BACKUP_DIR, {
        recursive: true,
        mode: 0o750
      });
    }
  } catch (error) {
    console.error(
      '[DB LOCAL ERROR] Preparation des repertoires impossible :',
      error.message
    );
    throw error;
  }
}

function loadInitialLocalData() {
  try {
    if (!fs.existsSync(DB_PATH)) {
      return cloneDefaultData();
    }

    const raw = fs.readFileSync(DB_PATH, 'utf8');

    if (!raw.trim()) {
      console.warn(
        `[DB LOCAL] ${DB_PATH} est vide. Initialisation avec une base vierge.`
      );
      return cloneDefaultData();
    }

    const parsed = JSON.parse(raw);
    return normalizeData(parsed);
  } catch (error) {
    console.error(
      '[DB LOCAL ERROR] Impossible de charger db.json :',
      error.message
    );
    return cloneDefaultData();
  }
}

// ============================================================
// ATOMIC LOCAL WRITE & BACKUP
// ============================================================

function createLocalBackup(serialized) {
  if (!ENABLE_LOCAL_BACKUP) return;

  try {
    ensureLocalDirectories();
    const backupId = generateBackupId();
    const backupPath = path.join(BACKUP_DIR, `db-${backupId}.json`);

    fs.writeFileSync(backupPath, serialized, {
      encoding: 'utf8',
      mode: 0o640
    });

    rotateBackups();
  } catch (error) {
    console.warn('[DB BACKUP WARNING]:', error.message);
  }
}

function rotateBackups() {
  if (!ENABLE_LOCAL_BACKUP) return;

  try {
    if (!fs.existsSync(BACKUP_DIR)) return;

    const files = fs
      .readdirSync(BACKUP_DIR)
      .filter((file) => file.startsWith('db-'))
      .map((file) => {
        const fullPath = path.join(BACKUP_DIR, file);
        try {
          return {
            file,
            fullPath,
            mtime: fs.statSync(fullPath).mtimeMs
          };
        } catch (_) {
          return null;
        }
      })
      .filter(Boolean)
      .sort((a, b) => b.mtime - a.mtime);

    const obsolete = files.slice(MAX_BACKUPS);
    for (const item of obsolete) {
      try {
        fs.unlinkSync(item.fullPath);
      } catch (_) {}
    }
  } catch (error) {
    console.warn('[DB BACKUP ROTATION WARNING]:', error.message);
  }
}

function writeLocalAtomically(data) {
  ensureLocalDirectories();

  const formattedData = normalizeData(data);
  const tempPath = `${DB_PATH}.${process.pid}.${Date.now()}.tmp`;
  const serialized = JSON.stringify(formattedData, null, 2);

  try {
    const fd = fs.openSync(tempPath, 'w', 0o640);

    try {
      fs.writeFileSync(fd, serialized, 'utf8');
      try {
        fs.fsyncSync(fd);
      } catch (_) {
        // Ignoré si le système de fichiers ne supporte pas fsync
      }
    } finally {
      fs.closeSync(fd);
    }

    fs.renameSync(tempPath, DB_PATH);

    if (ENABLE_LOCAL_BACKUP) {
      createLocalBackup(serialized);
    }

    return true;
  } catch (error) {
    console.error('[DB LOCAL WRITE ERROR]:', error.message);
    try {
      if (fs.existsSync(tempPath)) {
        fs.unlinkSync(tempPath);
      }
    } catch (_) {}
    return false;
  }
}

// ============================================================
// INITIAL CACHE LOAD
// ============================================================

memoryCache = loadInitialLocalData();
initializedAt = new Date().toISOString();

// ============================================================
// POSTGRESQL ENGINE
// ============================================================

function createPostgresPool() {
  if (!DATABASE_URL) {
    console.warn(
      '[DB PG] DATABASE_URL non configuree. Mode local uniquement.'
    );
    return null;
  }

  const sslEnabled = process.env.PGSSL === 'true' || IS_PRODUCTION;
  const sslConfig = sslEnabled
    ? {
        rejectUnauthorized: process.env.PGSSL_REJECT_UNAUTHORIZED !== 'false'
      }
    : false;

  const newPool = new Pool({
    connectionString: DATABASE_URL,
    max: PG_MAX_CONNECTIONS,
    idleTimeoutMillis: PG_IDLE_TIMEOUT,
    connectionTimeoutMillis: PG_CONNECTION_TIMEOUT,
    ssl: sslConfig,
    application_name: process.env.PG_APPLICATION_NAME || APP_NAME,
    keepAlive: true
  });

  newPool.on('error', (error) => {
    pgConnected = false;
    lastDatabaseError = {
      message: error.message,
      timestamp: new Date().toISOString()
    };

    console.error('[DB PG POOL ERROR]:', error.message);
    schedulePgReconnect();
  });

  return newPool;
}

async function initPgStore() {
  if (!pool || pgInitializing) {
    return false;
  }

  pgInitializing = true;

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dorknet_store (
        id INTEGER PRIMARY KEY,
        data JSONB NOT NULL,
        version BIGINT NOT NULL DEFAULT 1,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    const result = await pool.query(`
      SELECT data, version, updated_at
      FROM dorknet_store
      WHERE id = 1
      LIMIT 1;
    `);

    if (result.rows.length === 0) {
      await pool.query(
        `
        INSERT INTO dorknet_store (id, data, version, updated_at)
        VALUES (1, $1::jsonb, 1, NOW())
        ON CONFLICT (id) DO NOTHING;
        `,
        [JSON.stringify(memoryCache)]
      );
    } else {
      memoryCache = normalizeData(result.rows[0].data);
    }

    await pool.query('SELECT 1');
    pgConnected = true;
    lastDatabaseError = null;

    console.log('[OK] PostgreSQL connecte et DorkNet Store initialise.');
    return true;
  } catch (error) {
    pgConnected = false;
    lastDatabaseError = {
      message: error.message,
      timestamp: new Date().toISOString()
    };

    console.error(
      '[DB PG INIT ERROR] Mode local de secours actif :',
      error.message
    );
    schedulePgReconnect();
    return false;
  } finally {
    pgInitializing = false;
  }
}

function schedulePgReconnect() {
  if (!pool || pgConnected || reconnectTimer) {
    return;
  }

  reconnectTimer = setTimeout(async () => {
    reconnectTimer = null;
    if (pgConnected) return;
    await initPgStore();
  }, PG_RETRY_DELAY);

  if (typeof reconnectTimer.unref === 'function') {
    reconnectTimer.unref();
  }
}

if (DATABASE_URL) {
  try {
    pool = createPostgresPool();
    initPgStore().catch((error) => {
      console.error('[DB PG FATAL INIT HANDLER]:', error.message);
      schedulePgReconnect();
    });
  } catch (error) {
    console.error('[DB PG CONFIG ERROR]:', error.message);
    pool = null;
    pgConnected = false;
  }
}

// ============================================================
// READ & WRITE PUBLIC API
// ============================================================

function readDB() {
  return cloneData(normalizeData(memoryCache));
}

async function persistPostgres(data) {
  if (!pool || !pgConnected) {
    return false;
  }

  try {
    await pool.query(
      `
      INSERT INTO dorknet_store (id, data, version, updated_at)
      VALUES (1, $1::jsonb, 1, NOW())
      ON CONFLICT (id)
      DO UPDATE SET
        data = EXCLUDED.data,
        version = dorknet_store.version + 1,
        updated_at = NOW();
      `,
      [JSON.stringify(data)]
    );

    lastSuccessfulWrite = new Date().toISOString();
    return true;
  } catch (error) {
    pgConnected = false;
    lastDatabaseError = {
      message: error.message,
      timestamp: new Date().toISOString()
    };

    console.error('[DB PG WRITE ERROR]:', error.message);
    schedulePgReconnect();
    return false;
  }
}

function writeDB(data) {
  const formattedData = normalizeData(data);

  // Synchronisation immédiate en mémoire
  memoryCache = cloneData(formattedData);

  // Enfilement asynchrone des écritures physiques
  writeQueue = writeQueue
    .then(async () => {
      const localSuccess = writeLocalAtomically(formattedData);
      if (!localSuccess) {
        console.error('[DB CRITICAL] Echec de la persistance locale.');
      }

      if (pool && pgConnected) {
        await persistPostgres(formattedData);
      } else if (pool) {
        schedulePgReconnect();
      }
    })
    .catch((error) => {
      console.error('[DB WRITE QUEUE ERROR]:', error.message);
    });

  return writeQueue;
}

// ============================================================
// HEALTH, MONITORING & SHUTDOWN
// ============================================================

function getDatabaseStatus() {
  return {
    engine: pgConnected ? 'postgresql' : 'local-json',
    postgresql: {
      configured: Boolean(DATABASE_URL),
      connected: pgConnected,
      pool: Boolean(pool)
    },
    local: {
      enabled: true,
      path: DB_PATH,
      exists: fs.existsSync(DB_PATH),
      sizeBytes: getFileSize(DB_PATH),
      backupsEnabled: ENABLE_LOCAL_BACKUP
    },
    initializedAt,
    lastSuccessfulWrite,
    lastError: lastDatabaseError
      ? { timestamp: lastDatabaseError.timestamp }
      : null,
    counts: {
      users: Array.isArray(memoryCache.users) ? memoryCache.users.length : 0,
      audits: Array.isArray(memoryCache.audits) ? memoryCache.audits.length : 0,
      transactions: Array.isArray(memoryCache.transactions)
        ? memoryCache.transactions.length
        : 0
    }
  };
}

async function checkDatabaseHealth() {
  const result = {
    healthy: true,
    postgresql: {
      configured: Boolean(DATABASE_URL),
      connected: pgConnected
    },
    local: {
      available: false
    }
  };

  try {
    ensureLocalDirectories();
    fs.accessSync(
      path.dirname(DB_PATH),
      fs.constants.R_OK | fs.constants.W_OK
    );
    result.local.available = true;
  } catch (_) {
    result.local.available = false;
    result.healthy = false;
  }

  if (pool && pgConnected) {
    try {
      await pool.query('SELECT 1');
      result.postgresql.connected = true;
    } catch (error) {
      result.postgresql.connected = false;
      result.healthy = false;
      pgConnected = false;
      lastDatabaseError = {
        message: error.message,
        timestamp: new Date().toISOString()
      };
      schedulePgReconnect();
    }
  } else if (DATABASE_URL) {
    result.healthy = false;
  }

  return result;
}

async function flushDB() {
  try {
    await writeQueue;
    if (pool && pgConnected) {
      await persistPostgres(normalizeData(memoryCache));
    }
  } catch (error) {
    console.error('[DB FLUSH ERROR]:', error.message);
  }
}

async function closeDB() {
  console.log('[DB] Fermeture du moteur de persistance...');
  try {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }

    await flushDB();

    if (pool) {
      await pool.end();
      pool = null;
      pgConnected = false;
    }

    console.log('[DB] Moteur de persistance arrete proprement.');
  } catch (error) {
    console.error('[DB CLOSE ERROR]:', error.message);
  }
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
  readDB,
  writeDB,
  getDatabaseStatus,
  checkDatabaseHealth,
  flushDB,
  closeDB
};
