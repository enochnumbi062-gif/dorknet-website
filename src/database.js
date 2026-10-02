'use strict';

/**
 * DorkNet Security
 * Hybrid Persistence Engine
 *
 * Architecture:
 *   Application
 *       │
 *       ├── Memory Cache
 *       │
 *       ├── PostgreSQL JSONB Store
 *       │
 *       └── Atomic Local JSON Fallback
 *
 * Compatibility:
 *   const { readDB, writeDB } = require('./database');
 *
 * Design goals:
 *   - PostgreSQL primary persistence
 *   - Local JSON disaster fallback
 *   - Atomic local writes
 *   - In-process write serialization
 *   - PostgreSQL reconnect strategy
 *   - Data structure validation
 *   - Safe shutdown
 *   - Health/status inspection
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

// ============================================================
// CONFIGURATION
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
// DEFAULT DATA MODEL
// ============================================================

const DEFAULT_DATA = Object.freeze({
  users: [],
  audits: [],
  transactions: []
});

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
    transactions: Array.isArray(data.transactions)
      ? data.transactions
      : []
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
// LOCAL STORE
// ============================================================

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
      '[DB LOCAL ERROR] Impossible de préparer les répertoires :',
      error.message
    );

    throw error;
  }
}

// ============================================================
// ATOMIC LOCAL WRITE
// ============================================================

function writeLocalAtomically(data) {

  ensureLocalDirectories();

  const formattedData = normalizeData(data);

  const tempPath =
    `${DB_PATH}.${process.pid}.${Date.now()}.tmp`;

  const serialized =
    JSON.stringify(formattedData, null, 2);

  try {

    /*
     * Écriture dans un fichier temporaire.
     */
    const fd = fs.openSync(
      tempPath,
      'w',
      0o640
    );

    try {

      fs.writeFileSync(
        fd,
        serialized,
        'utf8'
      );

      /*
       * Force l'écriture physique avant rename.
       */
      try {
        fs.fsyncSync(fd);
      } catch (_) {
        // Certains FS / environnements ne supportent pas fsync.
      }

    } finally {

      fs.closeSync(fd);
    }

    /*
     * Remplacement atomique.
     */
    fs.renameSync(
      tempPath,
      DB_PATH
    );

    /*
     * Backup optionnel après écriture réussie.
     */
    if (ENABLE_LOCAL_BACKUP) {
      createLocalBackup(serialized);
    }

    return true;

  } catch (error) {

    console.error(
      '[DB LOCAL WRITE ERROR]:',
      error.message
    );

    try {
      if (fs.existsSync(tempPath)) {
        fs.unlinkSync(tempPath);
      }
    } catch (_) {}

    return false;
  }
}

// ============================================================
// LOCAL BACKUP ROTATION
// ============================================================

function createLocalBackup(serialized) {

  if (!ENABLE_LOCAL_BACKUP) {
    return;
  }

  try {

    ensureLocalDirectories();

    const backupId = generateBackupId();

    const backupPath =
      path.join(
        BACKUP_DIR,
        `db-${backupId}.json`
      );

    fs.writeFileSync(
      backupPath,
      serialized,
      {
        encoding: 'utf8',
        mode: 0o640
      }
    );

    rotateBackups();

  } catch (error) {

    console.warn(
      '[DB BACKUP WARNING]:',
      error.message
    );
  }
}

function rotateBackups() {

  if (!ENABLE_LOCAL_BACKUP) {
    return;
  }

  try {

    if (!fs.existsSync(BACKUP_DIR)) {
      return;
    }

    const files = fs.readdirSync(BACKUP_DIR)
      .filter(file => file.startsWith('db-'))
      .map(file => {

        const fullPath =
          path.join(BACKUP_DIR, file);

        let stat;

        try {
          stat = fs.statSync(fullPath);
        } catch (_) {
          return null;
        }

        return {
          file,
          fullPath,
          mtime: stat.mtimeMs
        };
      })
      .filter(Boolean)
      .sort((a, b) => b.mtime - a.mtime);

    const obsolete =
      files.slice(MAX_BACKUPS);

    for (const item of obsolete) {

      try {
        fs.unlinkSync(item.fullPath);
      } catch (_) {}
    }

  } catch (error) {

    console.warn(
      '[DB BACKUP ROTATION WARNING]:',
      error.message
    );
  }
}

// ============================================================
// INITIAL MEMORY CACHE
// ============================================================

memoryCache = loadInitialLocalData();

initializedAt = new Date().toISOString();

// ============================================================
// POSTGRESQL
// ============================================================

function createPostgresPool() {

  if (!DATABASE_URL) {
    console.warn(
      '[DB PG] DATABASE_URL non configurée. Mode local uniquement.'
    );

    return null;
  }

  /*
   * En production, on évite volontairement
   * rejectUnauthorized:false.
   *
   * Pour Render/Supabase/etc., configure correctement
   * le certificat CA si nécessaire via PGSSLROOTCERT.
   */

  const sslEnabled =
    process.env.PGSSL === 'true' ||
    IS_PRODUCTION;

  const sslConfig = sslEnabled
    ? {
        rejectUnauthorized:
          process.env.PGSSL_REJECT_UNAUTHORIZED !== 'false'
      }
    : false;

  const newPool = new Pool({
    connectionString: DATABASE_URL,

    max: PG_MAX_CONNECTIONS,

    idleTimeoutMillis:
      PG_IDLE_TIMEOUT,

    connectionTimeoutMillis:
      PG_CONNECTION_TIMEOUT,

    ssl: sslConfig,

    application_name:
      process.env.PG_APPLICATION_NAME ||
      APP_NAME,

    keepAlive: true
  });

  newPool.on('error', (error) => {

    pgConnected = false;

    lastDatabaseError = {
      message: error.message,
      timestamp: new Date().toISOString()
    };

    console.error(
      '[DB PG POOL ERROR]:',
      error.message
    );

    schedulePgReconnect();
  });

  return newPool;
}

// ============================================================
// POSTGRESQL INITIALIZATION
// ============================================================

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
      SELECT
        data,
        version,
        updated_at
      FROM dorknet_store
      WHERE id = 1
      LIMIT 1;
    `);

    if (result.rows.length === 0) {

      await pool.query(
        `
        INSERT INTO dorknet_store
          (id, data, version, updated_at)
        VALUES
          (1, $1::jsonb, 1, NOW())
        ON CONFLICT (id)
        DO NOTHING;
        `,
        [JSON.stringify(memoryCache)]
      );

    } else {

      const remoteData =
        normalizeData(result.rows[0].data);

      /*
       * PostgreSQL devient la source persistante
       * lorsqu'il contient déjà des données.
       */
      memoryCache = remoteData;
    }

    /*
     * Vérification réelle de la connexion.
     */
    await pool.query('SELECT 1');

    pgConnected = true;

    lastDatabaseError = null;

    console.log(
      '[OK] PostgreSQL connecté et DorkNet Store initialisé.'
    );

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

// ============================================================
// POSTGRESQL RECONNECT
// ============================================================

function schedulePgReconnect() {

  if (!pool || pgConnected || reconnectTimer) {
    return;
  }

  reconnectTimer = setTimeout(async () => {

    reconnectTimer = null;

    if (pgConnected) {
      return;
    }

    await initPgStore();

  }, PG_RETRY_DELAY);

  if (typeof reconnectTimer.unref === 'function') {
    reconnectTimer.unref();
  }
}

// ============================================================
// INITIALIZE POSTGRES
// ============================================================

if (DATABASE_URL) {

  try {

    pool = createPostgresPool();

    /*
     * Ne bloque pas le démarrage du serveur HTTP.
     */
    initPgStore().catch((error) => {

      console.error(
        '[DB PG FATAL INIT HANDLER]:',
        error.message
      );

      schedulePgReconnect();
    });

  } catch (error) {

    console.error(
      '[DB PG CONFIG ERROR]:',
      error.message
    );

    pool = null;
    pgConnected = false;
  }
}

// ============================================================
// READ DATABASE
// ============================================================

function readDB() {

  /*
   * Retourne toujours une copie afin d'éviter
   * qu'un appel externe modifie directement le cache.
   */
  return cloneData(
    normalizeData(memoryCache)
  );
}

// ============================================================
// POSTGRES PERSISTENCE
// ============================================================

async function persistPostgres(data) {

  if (!pool || !pgConnected) {
    return false;
  }

  try {

    await pool.query(
      `
      INSERT INTO dorknet_store
        (id, data, version, updated_at)
      VALUES
        (
          1,
          $1::jsonb,
          1,
          NOW()
        )
      ON CONFLICT (id)
      DO UPDATE SET
        data = EXCLUDED.data,
        version = dorknet_store.version + 1,
        updated_at = NOW();
      `,
      [JSON.stringify(data)]
    );

    lastSuccessfulWrite =
      new Date().toISOString();

    return true;

  } catch (error) {

    pgConnected = false;

    lastDatabaseError = {
      message: error.message,
      timestamp: new Date().toISOString()
    };

    console.error(
      '[DB PG WRITE ERROR]:',
      error.message
    );

    schedulePgReconnect();

    return false;
  }
}

// ============================================================
// WRITE DATABASE
// ============================================================

function writeDB(data) {

  const formattedData =
    normalizeData(data);

  /*
   * Mise à jour mémoire immédiate.
   */
  memoryCache =
    cloneData(formattedData);

  /*
   * Sérialisation des écritures.
   *
   * Cela évite deux writeDB() simultanés
   * qui pourraient écraser les modifications
   * l'une de l'autre au niveau du stockage.
   */
  writeQueue =
    writeQueue
      .then(async () => {

        /*
         * 1. Persistance locale atomique.
         *
         * Le fichier local constitue notre point
         * de récupération immédiat.
         */
        const localSuccess =
          writeLocalAtomically(
            formattedData
          );

        if (!localSuccess) {

          console.error(
            '[DB CRITICAL] Échec de la persistance locale.'
          );
        }

        /*
         * 2. PostgreSQL.
         *
         * On tente la persistance distante
         * sans bloquer l'API.
         */
        if (pool && pgConnected) {
          await persistPostgres(
            formattedData
          );
        } else if (pool) {
          schedulePgReconnect();
        }

      })
      .catch((error) => {

        console.error(
          '[DB WRITE QUEUE ERROR]:',
          error.message
        );

      });

  /*
   * On retourne la Promise pour permettre
   * au code appelant de l'attendre s'il le souhaite.
   */
  return writeQueue;
}

// ============================================================
// DATABASE STATUS
// ============================================================

function getDatabaseStatus() {

  return {

    engine:
      pgConnected
        ? 'postgresql'
        : 'local-json',

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
      backupsEnabled:
        ENABLE_LOCAL_BACKUP
    },

    initializedAt,

    lastSuccessfulWrite,

    lastError:
      lastDatabaseError
        ? {
            timestamp:
              lastDatabaseError.timestamp
          }
        : null,

    counts: {
      users:
        Array.isArray(memoryCache.users)
          ? memoryCache.users.length
          : 0,

      audits:
        Array.isArray(memoryCache.audits)
          ? memoryCache.audits.length
          : 0,

      transactions:
        Array.isArray(memoryCache.transactions)
          ? memoryCache.transactions.length
          : 0
    }
  };
}

// ============================================================
// DATABASE HEALTH
// ============================================================

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

  /*
   * Vérification locale.
   */
  try {

    ensureLocalDirectories();

    fs.accessSync(
      path.dirname(DB_PATH),
      fs.constants.R_OK |
      fs.constants.W_OK
    );

    result.local.available = true;

  } catch (_) {

    result.local.available = false;
    result.healthy = false;
  }

  /*
   * Vérification PostgreSQL.
   */
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

    /*
     * PostgreSQL est configuré mais indisponible.
     *
     * Le système reste utilisable grâce au fallback
     * local, mais la santé globale n'est pas parfaite.
     */
    result.healthy = false;
  }

  return result;
}

// ============================================================
// FLUSH
// ============================================================

async function flushDB() {

  try {

    await writeQueue;

    /*
     * Dernière synchronisation PostgreSQL.
     */
    if (pool && pgConnected) {
      await persistPostgres(
        normalizeData(memoryCache)
      );
    }

  } catch (error) {

    console.error(
      '[DB FLUSH ERROR]:',
      error.message
    );
  }
}

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

async function closeDB() {

  console.log(
    '[DB] Fermeture du moteur de persistance...'
  );

  try {

    if (reconnectTimer) {

      clearTimeout(
        reconnectTimer
      );

      reconnectTimer = null;
    }

    await flushDB();

    if (pool) {

      await pool.end();

      pool = null;
      pgConnected = false;
    }

    console.log(
      '[DB] Moteur de persistance arrêté proprement.'
    );

  } catch (error) {

    console.error(
      '[DB CLOSE ERROR]:',
      error.message
    );
  }
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {

  /*
   * API compatible avec server.js
   */
  readDB,
  writeDB,

  /*
   * Fonctions supplémentaires pour
   * health / observabilité / shutdown.
   */
  getDatabaseStatus,
  checkDatabaseHealth,
  flushDB,
  closeDB
};

Ce que cette version corrige

1. Le stockage local est réellement atomique.
Le fichier temporaire est écrit puis renommé, avec "fsync" lorsque disponible. Un arrêt brutal pendant l'écriture réduit fortement le risque de laisser "db.json" partiellement écrit.

2. Les écritures sont sérialisées.
Ton ancienne version pouvait avoir plusieurs "writeDB()" concurrents. Ici, une file interne "writeQueue" séquence les écritures.

3. PostgreSQL ne fait plus tomber l'application.
Si PostgreSQL disparaît, le système continue avec le cache + JSON local et tente une reconnexion.

4. Le pool PostgreSQL est correctement géré.
La configuration utilise notamment "max", "idleTimeoutMillis", "connectionTimeoutMillis", "keepAlive" et "application_name".

5. Le problème "rejectUnauthorized: false" est supprimé par défaut.
Dans ta version précédente, cette option désactivait la validation du certificat TLS. Pour une architecture réellement sécurisée, il vaut mieux fournir le CA approprié lorsqu'un environnement l'exige.

6. Les données retournées par "readDB()" sont clonées.
Un module qui fait :

const db = readDB();
db.users.push(...);

ne modifie plus accidentellement directement le cache interne.

7. Ajout d'un vrai état de santé.

Ton "server.js" pourra maintenant utiliser :

const {
  readDB,
  writeDB,
  getDatabaseStatus,
  checkDatabaseHealth,
  closeDB
} = require('./database');

Puis exposer par exemple :

app.get('/health', async (req, res) => {
  const health = await checkDatabaseHealth();

  res.status(health.healthy ? 200 : 503).json({
    status: health.healthy ? 'healthy' : 'degraded',
    database: health
  });
});

Point architectural important

Cette solution reste compatible avec ton architecture actuelle, mais PostgreSQL + une seule ligne JSONB ne doit pas être considéré comme la forme finale d'une base enterprise.

Actuellement tu as :

DorkNet
   │
   └── dorknet_store
          │
          └── JSONB
               ├── users[]
               ├── audits[]
               └── transactions[]

Pour une vraie montée en charge, je passerais ensuite à :

                 DorkNet API
                     │
             Persistence Layer
                     │
        ┌────────────┼────────────┐
        │            │            │
     users         audits    transactions
        │            │            │
        └──────── PostgreSQL ─────┘
                     │
              transactions
              indexes
              constraints
              migrations
                     │
              encrypted backups

Cela permettrait notamment d'avoir des contraintes "UNIQUE", index, transactions ACID, migrations versionnées, pagination, audit immuable et recherche SQL, au lieu de charger l'ensemble de la base en mémoire à chaque opération.

Enfin, pour ton "server.js", je recommande de connecter ce moteur avec health/readiness, graceful shutdown et request-ID, plutôt que de simplement faire "app.listen()". Cela donnera une chaîne beaucoup plus propre :

HTTP Request
     │
     ▼
Security Middleware
     │
     ▼
Request ID
     │
     ▼
Rate Limit
     │
     ▼
Auth / Validation
     │
     ▼
Service Layer
     │
     ▼
database.js
     │
 ┌───┴─────────────┐
 ▼                 ▼
PostgreSQL       JSON Backup

Pour l'IA, le SDK JavaScript officiel actuel de Google utilise bien "GoogleGenAI" avec "ai.models.generateContent"; je conserverais donc cette architecture dans le "server.js" amélioré plutôt que de revenir à l'ancien SDK.

Avec ce "database.js", le prochain "server.js" peut maintenant être durci autour de cette couche sans casser "readDB()" / "writeDB()".
