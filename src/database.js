/**
 * DorkNet Security - Gestionnaire de persistance JSON atomique
 */

const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'db.json');
const LOCK_PATH = path.join(__dirname, 'db.json.lock');

const DEFAULT_DATA = { 
  users: [], 
  audits: [], 
  transactions: [] 
};

// Vérification et initialisation au démarrage
if (!fs.existsSync(DB_PATH)) {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(DEFAULT_DATA, null, 2), 'utf8');
  } catch (err) {
    console.error("[DB ERROR] Échec de la création initiale de db.json :", err.message);
  }
}

/**
 * Lit et parse les données JSON en s'assurant de l'existence des collections.
 * @returns {Object} Structure de données valide
 */
function readDB() {
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
    console.error("[DB ERROR] Échec de la lecture/parsing de db.json :", error.message);
    return JSON.parse(JSON.stringify(DEFAULT_DATA));
  }
}

/**
 * Sauvegarde atomique avec remplacement du fichier temporaire.
 * @param {Object} data - Données à enregistrer
 */
function writeDB(data) {
  const tempPath = `${DB_PATH}.tmp`;
  try {
    const payload = JSON.stringify({
      users: Array.isArray(data.users) ? data.users : [],
      audits: Array.isArray(data.audits) ? data.audits : [],
      transactions: Array.isArray(data.transactions) ? data.transactions : []
    }, null, 2);

    fs.writeFileSync(tempPath, payload, 'utf8');
    fs.renameSync(tempPath, DB_PATH);
  } catch (error) {
    console.error("[DB ERROR] Échec lors de la sauvegarde atomique :", error.message);
    if (fs.existsSync(tempPath)) {
      try { fs.unlinkSync(tempPath); } catch (_) {}
    }
  }
}

module.exports = { 
  readDB, 
  writeDB 
};
