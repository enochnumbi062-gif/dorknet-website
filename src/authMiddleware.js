'use strict';

/**
 * ============================================================
 * DORKNET SECURITY — AGATA & HYBRID SERVICES
 * Zero-Trust JWT Authentication Middleware
 * ============================================================
 *
 * Security Objectives:
 *   - Fail-fast enforcement in production when JWT_SECRET is omitted
 *   - Ephemeral strong entropy fallback in local development
 *   - Strict RFC 6750 Bearer token format validation
 *   - Explicit algorithm pinning (HS256 / HS384 / HS512)
 *   - Claim validation (sub, iat, exp, lifetime bounds)
 *   - Immutable request identity binding (req.user & req.auth)
 *   - Granular RBAC (requireRole) and ABAC/PBAC (requirePermission)
 * ============================================================
 */

require('dotenv').config();

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// ============================================================
// CONFIGURATION & ENVIRONMENT
// ============================================================

const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';

const JWT_SECRET = process.env.JWT_SECRET || '';
const JWT_ALGORITHM = process.env.JWT_ALGORITHM || 'HS256';
const JWT_ISSUER = process.env.JWT_ISSUER || '';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || '';

const JWT_CLOCK_TOLERANCE = Number.parseInt(
  process.env.JWT_CLOCK_TOLERANCE || '5',
  10
);

// ============================================================
// ALGORITHM & SECRET VALIDATION
// ============================================================

const SUPPORTED_ALGORITHMS = new Set(['HS256', 'HS384', 'HS512']);

if (!SUPPORTED_ALGORITHMS.has(JWT_ALGORITHM)) {
  throw new Error(
    `[AUTH CONFIG ERROR] JWT_ALGORITHM invalide: ${JWT_ALGORITHM}. ` +
      `Algorithmes autorises: ${Array.from(SUPPORTED_ALGORITHMS).join(', ')}`
  );
}

if (!JWT_SECRET) {
  if (IS_PRODUCTION) {
    throw new Error(
      '[AUTH FATAL ERROR] JWT_SECRET doit impérativement être defini en environnement de production.'
    );
  }

  console.warn(
    '[AUTH WARNING] JWT_SECRET absent. Generation d’une cle ephemere pour le developpement local.'
  );
}

// Cle effective : si non definie en dev, generation d'un secret aleatoire de 512 bits
const EFFECTIVE_JWT_SECRET =
  JWT_SECRET || crypto.randomBytes(64).toString('base64url');

// ============================================================
// TOKEN EXTRACTION (RFC 6750)
// ============================================================

function extractBearerToken(req) {
  const authorization = req.headers.authorization;

  if (typeof authorization !== 'string' || !authorization.trim()) {
    return null;
  }

  const match = authorization.match(/^Bearer[ \t]+([A-Za-z0-9\-._~+/]+=*)$/i);

  if (!match) {
    return null;
  }

  const token = match[1];

  // Limites de taille de securite
  if (token.length < 20 || token.length > 8192) {
    return null;
  }

  return token;
}

// ============================================================
// CLAIM VALIDATION
// ============================================================

function validateDecodedClaims(decoded) {
  if (!decoded || typeof decoded !== 'object') {
    return false;
  }

  // Subject (identifiant utilisateur)
  if (
    typeof decoded.sub !== 'string' ||
    decoded.sub.length < 1 ||
    decoded.sub.length > 256
  ) {
    return false;
  }

  // Issued At
  if (typeof decoded.iat !== 'number' || !Number.isFinite(decoded.iat)) {
    return false;
  }

  // Expiration
  if (typeof decoded.exp !== 'number' || !Number.isFinite(decoded.exp)) {
    return false;
  }

  if (decoded.exp <= decoded.iat) {
    return false;
  }

  // Duree de vie maximale autorisee (7 jours)
  const MAX_TOKEN_LIFETIME = 7 * 24 * 60 * 60;
  const lifetime = decoded.exp - decoded.iat;

  if (lifetime <= 0 || lifetime > MAX_TOKEN_LIFETIME) {
    return false;
  }

  return true;
}

// ============================================================
// VERIFICATION OPTIONS
// ============================================================

function buildVerifyOptions() {
  const options = {
    algorithms: [JWT_ALGORITHM],
    clockTolerance: JWT_CLOCK_TOLERANCE,
    complete: false
  };

  if (JWT_ISSUER) {
    options.issuer = JWT_ISSUER;
  }

  if (JWT_AUDIENCE) {
    options.audience = JWT_AUDIENCE;
  }

  return options;
}

// ============================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================

function authenticateToken(req, res, next) {
  const token = extractBearerToken(req);

  if (!token) {
    return res.status(401).json({
      error: 'Authentification requise.'
    });
  }

  jwt.verify(
    token,
    EFFECTIVE_JWT_SECRET,
    buildVerifyOptions(),
    (err, decodedUser) => {
      if (err) {
        if (err.name === 'TokenExpiredError') {
          return res.status(401).json({
            error: 'Session expirée. Veuillez vous reconnecter.'
          });
        }

        return res.status(401).json({
          error: 'Authentification invalide.'
        });
      }

      if (!validateDecodedClaims(decodedUser)) {
        return res.status(401).json({
          error: 'Jeton d’authentification invalide.'
        });
      }

      // Contexte utilisateur immuable
      req.user = Object.freeze({
        ...decodedUser
      });

      // Metadonnees de securite et d'audit
      req.auth = Object.freeze({
        authenticated: true,
        userId: decodedUser.sub,
        tokenId: typeof decodedUser.jti === 'string' ? decodedUser.jti : null,
        issuedAt: decodedUser.iat,
        expiresAt: decodedUser.exp,
        issuer: decodedUser.iss || null,
        audience: decodedUser.aud || null
      });

      return next();
    }
  );
}

// ============================================================
// ROLE & PERMISSION MIDDLEWARES
// ============================================================

function requireRole(...allowedRoles) {
  const normalizedRoles = allowedRoles
    .filter((role) => typeof role === 'string' && role.trim())
    .map((role) => role.trim());

  return (req, res, next) => {
    if (!req.user || !req.auth || !req.auth.authenticated) {
      return res.status(401).json({
        error: 'Authentification requise.'
      });
    }

    const userRole = typeof req.user.role === 'string' ? req.user.role : null;

    if (!userRole || !normalizedRoles.includes(userRole)) {
      return res.status(403).json({
        error: 'Permissions insuffisantes.'
      });
    }

    return next();
  };
}

function requirePermission(...requiredPermissions) {
  const normalizedPermissions = requiredPermissions
    .filter((perm) => typeof perm === 'string' && perm.trim())
    .map((perm) => perm.trim());

  return (req, res, next) => {
    if (!req.user || !req.auth || !req.auth.authenticated) {
      return res.status(401).json({
        error: 'Authentification requise.'
      });
    }

    const userPermissions = Array.isArray(req.user.permissions)
      ? req.user.permissions
      : [];

    const authorized = normalizedPermissions.every((permission) =>
      userPermissions.includes(permission)
    );

    if (!authorized) {
      return res.status(403).json({
        error: 'Permissions insuffisantes.'
      });
    }

    return next();
  };
}

// ============================================================
// DIAGNOSTIC API
// ============================================================

function getAuthConfigStatus() {
  return {
    configured: Boolean(JWT_SECRET),
    algorithm: JWT_ALGORITHM,
    issuerConfigured: Boolean(JWT_ISSUER),
    audienceConfigured: Boolean(JWT_AUDIENCE),
    environment: NODE_ENV,
    clockToleranceSeconds: JWT_CLOCK_TOLERANCE
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
  JWT_SECRET: EFFECTIVE_JWT_SECRET
};
