/**
 * DorkNet Security - Middleware d'Authentification JWT (Web AAL3 / Zero Trust Ready)
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Sécurisation de la clé JWT en cas d'absence dans .env
if (!process.env.JWT_SECRET) {
  console.warn('[WARNING] JWT_SECRET n\'est pas défini dans le fichier .env ! Génération d\'une clé aléatoire temporaire.');
}

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

/**
 * Middleware de vérification du jeton JWT pour sécuriser les routes privées de l'API DorkNet.
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];

  // Vérification de la présence et du format "Bearer <token>"
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

    req.user = decodedUser;
    next();
  });
}

module.exports = { 
  authenticateToken, 
  JWT_SECRET 
};
