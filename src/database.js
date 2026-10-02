/**
 * DorkNet Security - Gestionnaire de persistance hybride (PostgreSQL / JSON local)
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

// Mémoire vive synchronisée avec PostgreSQL si disponible
let memoryCache = null;

// Configuration du pool PostgreSQL si DATABASE_URL est défini
const DATABASE_URL = process.env.DATABASE_URL;
let pool = null;

if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  
  // Initialisation de la table PostgreSQL pour stocker le JSON de façon persistante
  initPgStore();
} else {
  // Initialisation locale si pas de PG
  if (!fs.existsSync(DB_PATH)) {
    try {
      fs.writeFileSync(DB_PATH, JSON.stringify(DEFAULT_DATA, null, 2), 'utf8');
    } catch (err) {
      console.error("[DB ERROR] Échec création initiale db.json :", err.message);
    }
  }
}

async function initPgStore() {
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
      memoryCache = JSON.parse(JSON.stringify(DEFAULT_DATA));
      await pool.query('INSERT INTO dorknet_store (id, data) VALUES (1, $1)', [JSON.stringify(memoryCache)]);
    }
    console.log('[OK] Base de données PostgreSQL synchronisée.');
  } catch (err) {
    console.error('[DB PG ERROR] Échec initialisation PostgreSQL :', err.message);
  }
}

/**
 * Lit les données en s'assurant de l'existence des collections.
 * @returns {Object} Structure de données valide
 */
function readDB() {
  if (pool && memoryCache) {
    return {
      users: Array.isArray(memoryCache.users) ? memoryCache.users : [],
      audits: Array.isArray(memoryCache.audits) ? memoryCache.audits : [],
      transactions: Array.isArray(memoryCache.transactions) ? memoryCache.transactions : []
    };
  }

  try {
    if (!fs.existsSync(DB_PATH)) {
      return JSON.parse(JSON.stringify(DEFAULT_DATA));
    }

    const rawData = fs.readFileSync(DB_PATH, 'utf8');
    if (!rawData.trim()) {
      return JSON.parse(JSON.stringify(DEFAULT_DATA));
    }

    const parsed = JSON.parse(rawData);

    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      audits: Array.isArray(parsed.audits) ? parsed.audits : [],
      transactions: Array.isArray(parsed.transactions) ? parsed.transactions : []
    };
  } catch (error) {
    console.error("[DB ERROR] Échec de la lecture db.json :", error.message);
    return JSON.parse(JSON.stringify(DEFAULT_DATA));
  }
}

/**
 * Sauvegarde atomique avec synchronisation PostgreSQL si présent.
 * @param {Object} data - Données à enregistrer
 */
function writeDB(data) {
  const formattedData = {
    users: Array.isArray(data.users) ? data.users : [],
    audits: Array.isArray(data.audits) ? data.audits : [],
    transactions: Array.isArray(data.transactions) ? data.transactions : []
  };

  // Mise à jour de la mémoire
  memoryCache = formattedData;

  // Persistance dans PostgreSQL si activé
  if (pool) {
    pool.query(
      'INSERT INTO dorknet_store (id, data) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data',
      [JSON.stringify(formattedData)]
    ).catch(err => console.error('[DB PG WRITE ERROR] :', err.message));
  }

  // Écriture de secours sur le fichier local
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
