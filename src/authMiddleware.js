/**
 * DorkNet Security - Middleware d'Authentification JWT (Web AAL3 / Zero Trust Ready)
 */

require('dotenv').config();
const jwt = require('jsonwebtoken');

// Clé secrète partagée pour la signature et vérification des jetons
const JWT_SECRET = process.env.JWT_SECRET || 'dorknet_default_jwt_secret_key_2026_fallback';

if (!process.env.JWT_SECRET) {
  console.warn('[WARNING] JWT_SECRET n\'est pas défini dans le fichier .env ! Utilisation de la clé de secours par défaut.');
}

/**
 * Middleware de vérification du jeton JWT pour sécuriser les routes privées de l'API DorkNet.
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];

  // Vérification de la présence et de la structure "Bearer <token>"
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      error: 'Accès refusé. Token manquant ou format invalide (attendu: Bearer <token>).' 
    });
  }

  const token = authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Accès refusé. Jeton d\'authentification vide.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Session expirée. Veuillez vous reconnecter.' });
      }
      return res.status(403).json({ error: 'Jeton d\'authentification invalide ou altéré.' });
    }

    // Attacher les données de l'utilisateur décodé à la requête
    req.user = decodedUser;
    next();
  });
}

module.exports = { 
  authenticateToken, 
  JWT_SECRET 
};
