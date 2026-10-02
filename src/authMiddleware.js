'use strict';

/**
 * ============================================================
 * DORKNET SECURITY
 * Zero-Trust JWT Authentication Middleware
 * ============================================================
 *
 * Security objectives:
 *   - No predictable JWT secret fallback
 *   - Explicit JWT algorithm
 *   - Optional issuer / audience validation
 *   - Strict Bearer token parsing
 *   - Required claims validation
 *   - Safe authentication errors
 *   - Request identity propagation
 *   - Production fail-fast configuration
 *
 * Compatible with:
 *   const {
 *     authenticateToken,
 *     JWT_SECRET
 *   } = require('./authMiddleware');
 * ============================================================
 */

require('dotenv').config();

const jwt = require('jsonwebtoken');

// ============================================================
// CONFIGURATION
// ============================================================

const NODE_ENV =
  process.env.NODE_ENV || 'development';

const IS_PRODUCTION =
  NODE_ENV === 'production';

const JWT_SECRET =
  process.env.JWT_SECRET || '';

const JWT_ALGORITHM =
  process.env.JWT_ALGORITHM || 'HS256';

const JWT_ISSUER =
  process.env.JWT_ISSUER || '';

const JWT_AUDIENCE =
  process.env.JWT_AUDIENCE || '';

const JWT_CLOCK_TOLERANCE =
  Number.parseInt(
    process.env.JWT_CLOCK_TOLERANCE || '5',
    10
  );

// ============================================================
// SECURITY CONFIGURATION VALIDATION
// ============================================================

const SUPPORTED_ALGORITHMS = new Set([
  'HS256',
  'HS384',
  'HS512'
]);

if (!SUPPORTED_ALGORITHMS.has(JWT_ALGORITHM)) {
  throw new Error(
    `[AUTH CONFIG] JWT_ALGORITHM invalide: ${JWT_ALGORITHM}. ` +
    `Algorithmes autorisés: ${Array.from(SUPPORTED_ALGORITHMS).join(', ')}`
  );
}

/*
 * En production, aucune clé de secours.
 */
if (!JWT_SECRET) {

  if (IS_PRODUCTION) {

    throw new Error(
      '[AUTH FATAL] JWT_SECRET doit être défini en production.'
    );

  }

  console.warn(
    '[AUTH WARNING] JWT_SECRET absent. ' +
    'Le serveur fonctionne uniquement pour le développement local.'
  );
}

/*
 * Même en développement, générer une clé aléatoire
 * plutôt qu'utiliser une clé statique connue.
 *
 * Cette clé change à chaque redémarrage, ce qui invalide
 * les tokens précédents — comportement acceptable en dev.
 */
const crypto = require('crypto');

const EFFECTIVE_JWT_SECRET =
  JWT_SECRET ||
  crypto.randomBytes(64).toString('base64url');

// ============================================================
// TOKEN EXTRACTION
// ============================================================

function extractBearerToken(req) {

  const authorization =
    req.headers.authorization;

  if (
    typeof authorization !== 'string' ||
    !authorization.trim()
  ) {
    return null;
  }

  /*
   * RFC-style Bearer parsing.
   */
  const match =
    authorization.match(
      /^Bearer[ \t]+([A-Za-z0-9\-._~+/]+=*)$/i
    );

  if (!match) {
    return null;
  }

  const token =
    match[1];

  /*
   * Protection contre les headers anormalement volumineux.
   */
  if (
    token.length < 20 ||
    token.length > 8192
  ) {
    return null;
  }

  return token;
}

// ============================================================
// CLAIM VALIDATION
// ============================================================

function validateDecodedClaims(decoded) {

  if (
    !decoded ||
    typeof decoded !== 'object'
  ) {
    return false;
  }

  /*
   * sub = identifiant stable de l'utilisateur.
   */
  if (
    typeof decoded.sub !== 'string' ||
    decoded.sub.length < 1 ||
    decoded.sub.length > 256
  ) {
    return false;
  }

  /*
   * iat = issued at.
   */
  if (
    typeof decoded.iat !== 'number' ||
    !Number.isFinite(decoded.iat)
  ) {
    return false;
  }

  /*
   * exp = expiration.
   *
   * jsonwebtoken vérifie déjà l'expiration,
   * mais on vérifie également la présence du claim.
   */
  if (
    typeof decoded.exp !== 'number' ||
    !Number.isFinite(decoded.exp)
  ) {
    return false;
  }

  /*
   * Évite les tokens absurdes où l'expiration
   * serait antérieure à l'émission.
   */
  if (decoded.exp <= decoded.iat) {
    return false;
  }

  /*
   * Protection contre des tokens avec une durée
   * anormalement longue.
   *
   * Maximum recommandé ici: 7 jours.
   */
  const lifetime =
    decoded.exp - decoded.iat;

  const MAX_TOKEN_LIFETIME =
    7 * 24 * 60 * 60;

  if (
    lifetime <= 0 ||
    lifetime > MAX_TOKEN_LIFETIME
  ) {
    return false;
  }

  return true;
}

// ============================================================
// JWT VERIFY OPTIONS
// ============================================================

function buildVerifyOptions() {

  const options = {

    algorithms: [
      JWT_ALGORITHM
    ],

    clockTolerance:
      JWT_CLOCK_TOLERANCE,

    /*
     * Ignore les valeurs "none" et impose
     * l'algorithme configuré.
     */
    complete: false
  };

  if (JWT_ISSUER) {
    options.issuer =
      JWT_ISSUER;
  }

  if (JWT_AUDIENCE) {
    options.audience =
      JWT_AUDIENCE;
  }

  return options;
}

// ============================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================

function authenticateToken(req, res, next) {

  const token =
    extractBearerToken(req);

  if (!token) {

    return res.status(401).json({
      error:
        'Authentification requise.'
    });
  }

  jwt.verify(
    token,
    EFFECTIVE_JWT_SECRET,
    buildVerifyOptions(),
    (err, decodedUser) => {

      if (err) {

        /*
         * Token expiré:
         * 401 = authentification non valide/expirée.
         */
        if (
          err.name ===
          'TokenExpiredError'
        ) {

          return res.status(401).json({
            error:
              'Session expirée. Veuillez vous reconnecter.'
          });
        }

        /*
         * Signature, issuer, audience,
         * malformed token, etc.
         */
        return res.status(401).json({
          error:
            'Authentification invalide.'
        });
      }

      /*
       * Vérification supplémentaire des claims.
       */
      if (
        !validateDecodedClaims(
          decodedUser
        )
      ) {

        return res.status(401).json({
          error:
            'Jeton d’authentification invalide.'
        });
      }

      /*
       * Identité authentifiée.
       *
       * On ne transforme pas le token:
       * les claims vérifiés restent accessibles
       * à la couche applicative.
       */
      req.user = Object.freeze({
        ...decodedUser
      });

      /*
       * Métadonnées d'authentification utiles
       * pour l'audit / observabilité.
       */
      req.auth = Object.freeze({

        authenticated: true,

        userId:
          decodedUser.sub,

        tokenId:
          typeof decodedUser.jti === 'string'
            ? decodedUser.jti
            : null,

        issuedAt:
          decodedUser.iat,

        expiresAt:
          decodedUser.exp,

        issuer:
          decodedUser.iss || null,

        audience:
          decodedUser.aud || null
      });

      return next();
    }
  );
}

// ============================================================
// OPTIONAL ROLE / PERMISSION MIDDLEWARE
// ============================================================

function requireRole(...allowedRoles) {

  const normalizedRoles =
    allowedRoles
      .filter(
        role =>
          typeof role === 'string' &&
          role.trim()
      )
      .map(
        role => role.trim()
      );

  return (req, res, next) => {

    if (
      !req.user ||
      !req.auth ||
      !req.auth.authenticated
    ) {

      return res.status(401).json({
        error:
          'Authentification requise.'
      });
    }

    const userRole =
      typeof req.user.role === 'string'
        ? req.user.role
        : null;

    if (
      !userRole ||
      !normalizedRoles.includes(userRole)
    ) {

      return res.status(403).json({
        error:
          'Permissions insuffisantes.'
      });
    }

    return next();
  };
}

// ============================================================
// OPTIONAL PERMISSION MIDDLEWARE
// ============================================================

function requirePermission(...requiredPermissions) {

  const normalizedPermissions =
    requiredPermissions
      .filter(
        permission =>
          typeof permission === 'string' &&
          permission.trim()
      )
      .map(
        permission => permission.trim()
      );

  return (req, res, next) => {

    if (
      !req.user ||
      !req.auth ||
      !req.auth.authenticated
    ) {

      return res.status(401).json({
        error:
          'Authentification requise.'
      });
    }

    const userPermissions =
      Array.isArray(
        req.user.permissions
      )
        ? req.user.permissions
        : [];

    const authorized =
      normalizedPermissions.every(
        permission =>
          userPermissions.includes(
            permission
          )
      );

    if (!authorized) {

      return res.status(403).json({
        error:
          'Permissions insuffisantes.'
      });
    }

    return next();
  };
}

// ============================================================
// AUTHENTICATION INFORMATION
// ============================================================

function getAuthConfigStatus() {

  return {

    configured:
      Boolean(JWT_SECRET),

    algorithm:
      JWT_ALGORITHM,

    issuerConfigured:
      Boolean(JWT_ISSUER),

    audienceConfigured:
      Boolean(JWT_AUDIENCE),

    environment:
      NODE_ENV,

    clockToleranceSeconds:
      JWT_CLOCK_TOLERANCE
  };
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {

  authenticateToken,

  requireRole,

  requirePermission,

  getAuthConfigStatus,

  /*
   * Important:
   * JWT_SECRET reste exporté pour conserver
   * la compatibilité avec server.js.
   */
  JWT_SECRET:
    EFFECTIVE_JWT_SECRET
};
