/**
 * DorkNet Security - Gestionnaire de persistance hybride sécurisé
 */

const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const DB_PATH = path.join(__dirname, 'db.json');

const DEFAULT_DATA = { 
  users: [], 
  audits: [], 
  transactions: [] 
};

// Charge les données locales au démarrage pour garantir que readDB() renvoie toujours quelque chose de valide
function loadInitialLocalData() {
  try {
    if (fs.existsSync(DB_PATH)) {
      const raw = fs.readFileSync(DB_PATH, 'utf8');
      if (raw.trim()) {
        const parsed = JSON.parse(raw);
        return {
          users: Array.isArray(parsed.users) ? parsed.users : [],
          audits: Array.isArray(parsed.audits) ? parsed.audits : [],
          transactions: Array.isArray(parsed.transactions) ? parsed.transactions : []
        };
      }
    }
  } catch (e) {
    console.error("[DB ERROR] Erreur lecture fichier local :", e.message);
  }
  return JSON.parse(JSON.stringify(DEFAULT_DATA));
}

let memoryCache = loadInitialLocalData();
let pgConnected = false;
let pool = null;

const DATABASE_URL = process.env.DATABASE_URL;

if (DATABASE_URL) {
  try {
    pool = new Pool({
      connectionString: DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      connectionTimeoutMillis: 5000 // Évite de bloquer indéfiniment si PG est injoignable
    });

    initPgStore();
  } catch (err) {
    console.error('[DB PG ERROR] Configuration Pool échouée :', err.message);
  }
}

async function initPgStore() {
  if (!pool) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dorknet_store (
        id INT PRIMARY KEY,
        data JSONB NOT NULL
      );
    `);
    const res = await pool.query('SELECT data FROM dorknet_store WHERE id = 1');
    if (res.rows.length > 0) {
      memoryCache = res.rows[0].data;
    } else {
      await pool.query('INSERT INTO dorknet_store (id, data) VALUES (1, $1)', [JSON.stringify(memoryCache)]);
    }
    pgConnected = true;
    console.log('[OK] Base de données PostgreSQL synchronisée.');
  } catch (err) {
    pgConnected = false;
    console.error('[DB PG ERROR] Échec initialisation PostgreSQL (utilisation du mode secours local) :', err.message);
  }
}

/**
 * Lit les données
 * @returns {Object} Structure de données valide
 */
function readDB() {
  return {
    users: Array.isArray(memoryCache.users) ? memoryCache.users : [],
    audits: Array.isArray(memoryCache.audits) ? memoryCache.audits : [],
    transactions: Array.isArray(memoryCache.transactions) ? memoryCache.transactions : []
  };
}

/**
 * Sauvegarde atomique avec synchronisation PostgreSQL
 * @param {Object} data - Données à enregistrer
 */
function writeDB(data) {
  const formattedData = {
    users: Array.isArray(data.users) ? data.users : [],
    audits: Array.isArray(data.audits) ? data.audits : [],
    transactions: Array.isArray(data.transactions) ? data.transactions : []
  };

  // 1. Toujours mettre à jour la mémoire vive immédiatement
  memoryCache = formattedData;

  // 2. Persistance dans PostgreSQL (en arrière-plan si disponible)
  if (pool && pgConnected) {
    pool.query(
      'INSERT INTO dorknet_store (id, data) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data',
      [JSON.stringify(formattedData)]
    ).catch(err => console.error('[DB PG WRITE ERROR] :', err.message));
  }

  // 3. Écriture de secours sur le fichier local
  const tempPath = `${DB_PATH}.tmp`;
  try {
    fs.writeFileSync(tempPath, JSON.stringify(formattedData, null, 2), 'utf8');
    fs.renameSync(tempPath, DB_PATH);
  } catch (error) {
    if (fs.existsSync(tempPath)) {
      try { fs.unlinkSync(tempPath); } catch (_) {}
    }
  }
}

module.exports = { 
  readDB, 
  writeDB 
};
