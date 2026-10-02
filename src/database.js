/**
 * DorkNet Security - Gestionnaire de persistance hybride sécurisé (PostgreSQL / JSON local)
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

// Charge les données locales au démarrage pour garantir que readDB() renvoie toujours un objet valide
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
    console.error("[DB ERROR] Erreur lors de la lecture du fichier local :", e.message);
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
      ssl: process.env.NODE_ENV === 'production' || DATABASE_URL.includes('render') || DATABASE_URL.includes('supabase')
        ? { rejectUnauthorized: false }
        : false,
      connectionTimeoutMillis: 5000
    });

    initPgStore();
  } catch (err) {
    console.error('[DB PG ERROR] Échec de la configuration du Pool PostgreSQL :', err.message);
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
    console.log('[OK] Base de données PostgreSQL synchronisée avec succès.');
  } catch (err) {
    pgConnected = false;
    console.error('[DB PG ERROR] Échec d\'initialisation PostgreSQL (mode secours local actif) :', err.message);
  }
}

/**
 * Lit la structure courante de la base de données
 * @returns {Object} Structure de données { users, audits, transactions }
 */
function readDB() {
  return {
    users: Array.isArray(memoryCache.users) ? memoryCache.users : [],
    audits: Array.isArray(memoryCache.audits) ? memoryCache.audits : [],
    transactions: Array.isArray(memoryCache.transactions) ? memoryCache.transactions : []
  };
}

/**
 * Sauvegarde atomique avec synchronisation PostgreSQL et fallback local
 * @param {Object} data - Données à enregistrer
 */
function writeDB(data) {
  const formattedData = {
    users: Array.isArray(data.users) ? data.users : [],
    audits: Array.isArray(data.audits) ? data.audits : [],
    transactions: Array.isArray(data.transactions) ? data.transactions : []
  };

  // 1. Mise à jour immédiate du cache mémoire
  memoryCache = formattedData;

  // 2. Enregistrement asynchrone dans PostgreSQL
  if (pool && pgConnected) {
    pool.query(
      'INSERT INTO dorknet_store (id, data) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data',
      [JSON.stringify(formattedData)]
    ).catch(err => {
      console.error('[DB PG WRITE ERROR] :', err.message);
      pgConnected = false; // Marquer la déconnexion pour retenter ultérieurement si nécessaire
    });
  }

  // 3. Sauvegarde physique de secours dans le fichier JSON local
  const tempPath = `${DB_PATH}.tmp`;
  try {
    fs.writeFileSync(tempPath, JSON.stringify(formattedData, null, 2), 'utf8');
    fs.renameSync(tempPath, DB_PATH);
  } catch (error) {
    console.error('[DB LOCAL WRITE ERROR] :', error.message);
    if (fs.existsSync(tempPath)) {
      try { fs.unlinkSync(tempPath); } catch (_) {}
    }
  }
}

module.exports = { 
  readDB, 
  writeDB 
};
