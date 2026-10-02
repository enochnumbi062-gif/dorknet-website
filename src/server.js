'use strict';

/**
 * ============================================================
 * DORKNET SECURITY BACKEND
 * Enterprise Security API / AGATA-AI
 * ============================================================
 *
 * Security capabilities:
 *
 * - Strict environment configuration
 * - Helmet security headers
 * - Strict CORS allowlist
 * - Request correlation IDs
 * - JSON body limits
 * - Global + route-specific rate limiting
 * - Password hashing with bcrypt
 * - OTP hashing / expiration / attempt limiting
 * - OTP one-time use
 * - JWT issuer / audience / JTI claims
 * - Authentication hardening
 * - Input validation
 * - Output-safe HTML generation
 * - Signed audit PDF integration
 * - Append-only hash-chained audit events
 * - Gemini API isolation + rate limiting
 * - Prompt size limits
 * - AI safety configuration
 * - Graceful shutdown
 * - Centralized error handling
 * - Security-focused logging
 *
 * IMPORTANT:
 * The security assessment functionality must only be used
 * against systems for which explicit authorization exists.
 * ============================================================
 */

require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Resend } = require('resend');
const { GoogleGenAI } = require('@google/genai');

// ============================================================
// INTERNAL MODULES
// ============================================================

const { readDB, writeDB } = require('./database');
const {
  authenticateToken,
  JWT_SECRET: MIDDLEWARE_JWT_SECRET
} = require('./authMiddleware');

const {
  createSignedAuditPDF
} = require('./generatePDF');


// ============================================================
// ENVIRONMENT / CONFIGURATION
// ============================================================

const NODE_ENV =
  process.env.NODE_ENV || 'development';

const PRODUCTION =
  NODE_ENV === 'production';

const APP_NAME =
  process.env.APP_NAME ||
  'DorkNet Security API';

const APP_VERSION =
  process.env.APP_VERSION ||
  '2026.1';

const PORT =
  Number.parseInt(
    process.env.PORT || '5000',
    10
  );

const CLIENT_URL =
  process.env.CLIENT_URL || '';

const GEMINI_API_KEY =
  process.env.GEMINI_API_KEY;

const GEMINI_MODEL =
  process.env.GEMINI_MODEL ||
  'gemini-3.8-flash';

const RESEND_API_KEY =
  process.env.RESEND_API_KEY;

const SENDER_EMAIL =
  process.env.SENDER_EMAIL ||
  'onboarding@resend.dev';

const SENDER_NAME =
  process.env.SENDER_NAME ||
  'DorkNet Security';

const AUDIT_EMAIL =
  process.env.AUDIT_EMAIL ||
  SENDER_EMAIL;

const JWT_SECRET =
  process.env.JWT_SECRET ||
  MIDDLEWARE_JWT_SECRET;

const JWT_ISSUER =
  process.env.JWT_ISSUER ||
  'dorknet-security-api';

const JWT_AUDIENCE =
  process.env.JWT_AUDIENCE ||
  'dorknet-client';

const JWT_TTL =
  process.env.JWT_TTL ||
  '12h';

const TRUST_PROXY =
  process.env.TRUST_PROXY === 'true';

const LOG_LEVEL =
  process.env.LOG_LEVEL ||
  'info';


// ============================================================
// HARD FAIL ON INVALID PRODUCTION CONFIGURATION
// ============================================================

if (!Number.isInteger(PORT) ||
    PORT < 1 ||
    PORT > 65535) {
  throw new Error(
    'PORT configuration is invalid.'
  );
}

if (PRODUCTION) {

  const requiredProductionSecrets = [
    ['JWT_SECRET', JWT_SECRET],
    ['GEMINI_API_KEY', GEMINI_API_KEY],
    ['RESEND_API_KEY', RESEND_API_KEY],
    ['CLIENT_URL', CLIENT_URL]
  ];

  for (
    const [name, value]
    of requiredProductionSecrets
  ) {

    if (!value) {

      throw new Error(
        `${name} must be configured in production.`
      );
    }
  }

  if (CLIENT_URL.includes('*')) {

    throw new Error(
      'Wildcard CORS is forbidden in production.'
    );
  }
}


// ============================================================
// EXPRESS INITIALIZATION
// ============================================================

const app = express();

app.disable('x-powered-by');

if (TRUST_PROXY) {
  app.set('trust proxy', 1);
}


// ============================================================
// RESEND
// ============================================================

const resend =
  RESEND_API_KEY
    ? new Resend(RESEND_API_KEY)
    : null;

if (!resend) {

  console.warn(
    '[WARNING] RESEND_API_KEY non configurée.'
  );

  if (PRODUCTION) {

    throw new Error(
      'Email provider required in production.'
    );
  }
}


// ============================================================
// GEMINI
// ============================================================

const ai =
  GEMINI_API_KEY
    ? new GoogleGenAI({
        apiKey: GEMINI_API_KEY
      })
    : null;

if (!ai) {

  console.warn(
    '[WARNING] GEMINI_API_KEY non configurée.'
  );
}


// ============================================================
// APPLICATION CONSTANTS
// ============================================================

const MAX_JSON_SIZE =
  process.env.MAX_JSON_SIZE ||
  '32kb';

const MAX_NAME_LENGTH = 120;
const MAX_EMAIL_LENGTH = 254;
const MAX_PHONE_LENGTH = 32;
const MAX_SERVICE_LENGTH = 160;
const MAX_MESSAGE_LENGTH = 5000;

const MAX_AI_MESSAGE_LENGTH = 12000;

const OTP_TTL_MS =
  10 * 60 * 1000;

const OTP_MAX_ATTEMPTS =
  5;

const BCRYPT_ROUNDS =
  Number.parseInt(
    process.env.BCRYPT_ROUNDS || '12',
    10
  );

const JWT_CLOCK_TOLERANCE =
  Number.parseInt(
    process.env.JWT_CLOCK_TOLERANCE || '5',
    10
);


// ============================================================
// CORS
// ============================================================

const allowedOrigins =
  CLIENT_URL
    .split(',')
    .map(
      value => value.trim()
    )
    .filter(Boolean);

const corsOptions = {

  origin(origin, callback) {

    /*
     * Requests without Origin are accepted for:
     * - health checks
     * - server-to-server requests
     * - CLI tools
     *
     * Browser origins must match the explicit allowlist.
     */

    if (!origin) {
      return callback(null, true);
    }

    if (
      allowedOrigins.includes(origin)
    ) {

      return callback(
        null,
        true
      );
    }

    return callback(
      new Error(
        'CORS origin denied.'
      )
    );
  },

  methods: [
    'GET',
    'POST',
    'OPTIONS'
  ],

  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Request-ID'
  ],

  exposedHeaders: [
    'X-Request-ID',
    'Retry-After'
  ],

  credentials: false,

  maxAge: 600
};


// ============================================================
// SECURITY MIDDLEWARE
// ============================================================

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"]
      }
    },

    crossOriginEmbedderPolicy: false,

    referrerPolicy: {
      policy: 'no-referrer'
    }
  })
);

app.use(
  cors(corsOptions)
);

app.use(
  express.json({
    limit: MAX_JSON_SIZE,
    strict: true,
    type: [
      'application/json',
      'application/*+json'
    ]
  })
);


// ============================================================
// STATIC FRONTEND
// ============================================================

const publicDirectory =
  path.join(
    __dirname,
    '../public'
  );

app.use(
  express.static(
    publicDirectory,
    {
      index: false,

      etag: true,

      maxAge:
        PRODUCTION
          ? '1h'
          : 0,

      setHeaders(res) {

        res.setHeader(
          'X-Content-Type-Options',
          'nosniff'
        );
      }
    }
  )
);


// ============================================================
// REQUEST ID
// ============================================================

app.use(
  (req, res, next) => {

    const supplied =
      req.get(
        'X-Request-ID'
      );

    const requestId =
      supplied &&
      /^[a-zA-Z0-9._:-]{8,128}$/.test(
        supplied
      )
        ? supplied
        : crypto.randomUUID();

    req.requestId =
      requestId;

    res.setHeader(
      'X-Request-ID',
      requestId
    );

    next();
  }
);


// ============================================================
// SECURITY RESPONSE HEADERS
// ============================================================

app.use(
  (req, res, next) => {

    res.setHeader(
      'Cache-Control',
      'no-store'
    );

    res.setHeader(
      'Pragma',
      'no-cache'
    );

    res.setHeader(
      'X-Content-Type-Options',
      'nosniff'
    );

    res.setHeader(
      'X-Frame-Options',
      'DENY'
    );

    res.setHeader(
      'Referrer-Policy',
      'no-referrer'
    );

    res.setHeader(
      'Permissions-Policy',
      [
        'camera=()',
        'microphone=()',
        'geolocation=()',
        'payment=()',
        'usb=()'
      ].join(', ')
    );

    res.setHeader(
      'Cross-Origin-Opener-Policy',
      'same-origin'
    );

    res.setHeader(
      'Cross-Origin-Resource-Policy',
      'same-site'
    );

    if (PRODUCTION) {

      res.setHeader(
        'Strict-Transport-Security',
        'max-age=31536000; includeSubDomains'
      );
    }

    next();
  }
);


// ============================================================
// RATE LIMITERS
// ============================================================

const commonRateLimitOptions = {

  standardHeaders: 'draft-8',

  legacyHeaders: false,

  handler(req, res) {

    res.setHeader(
      'Retry-After',
      '900'
    );

    return res.status(429).json({
      success: false,

      error: {
        code: 'RATE_LIMITED',

        message:
          'Trop de requêtes. Réessayez plus tard.'
      },

      requestId:
        req.requestId
    });
  }
};


const globalLimiter =
  rateLimit({

    ...commonRateLimitOptions,

    windowMs:
      15 * 60 * 1000,

    max:
      PRODUCTION
        ? 300
        : 1000,

    message: {
      error:
        'Trop de requêtes.'
    }
  });


const auditLimiter =
  rateLimit({

    ...commonRateLimitOptions,

    windowMs:
      15 * 60 * 1000,

    max: 5,

    skipSuccessfulRequests:
      false
  });


const authLimiter =
  rateLimit({

    ...commonRateLimitOptions,

    windowMs:
      15 * 60 * 1000,

    max: 10
  });


const loginLimiter =
  rateLimit({

    ...commonRateLimitOptions,

    windowMs:
      15 * 60 * 1000,

    max: 10,

    skipSuccessfulRequests:
      true
  });


const otpLimiter =
  rateLimit({

    ...commonRateLimitOptions,

    windowMs:
      15 * 60 * 1000,

    max: 5
  });


const aiLimiter =
  rateLimit({

    ...commonRateLimitOptions,

    windowMs:
      60 * 1000,

    max:
      PRODUCTION
        ? 10
        : 30
  });


app.use(
  '/api',
  globalLimiter
);


// ============================================================
// HELPERS
// ============================================================

function isString(value) {

  return (
    typeof value === 'string'
  );
}


function cleanString(
  value,
  maxLength
) {

  if (!isString(value)) {
    return '';
  }

  return value
    .replace(/\u0000/g, '')
    .trim()
    .slice(0, maxLength);
}


/**
 * HTML escaping is performed ONLY when inserting text
 * into HTML. We do NOT store HTML-escaped user data.
 */
function escapeHtml(value) {

  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}


function normalizeEmail(
  value
) {

  const email =
    cleanString(
      value,
      MAX_EMAIL_LENGTH
    ).toLowerCase();

  if (!email) {
    return '';
  }

  /*
   * Structural validation.
   * Email providers perform the final delivery validation.
   */

  const regex =
    /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

  if (!regex.test(email)) {
    return '';
  }

  return email;
}


function normalizePhone(
  value
) {

  const phone =
    cleanString(
      value,
      MAX_PHONE_LENGTH
    );

  if (!phone) {
    return '';
  }

  if (
    !/^[+\d\s().-]{6,32}$/.test(
      phone
    )
  ) {
    return '';
  }

  return phone;
}


function generateOTP() {

  /*
   * crypto.randomInt() is used instead of Math.random().
   */

  return crypto
    .randomInt(
      100000,
      1000000
    )
    .toString();
}


function hashOTP(
  email,
  otp
) {

  return crypto
    .createHmac(
      'sha256',
      JWT_SECRET
    )
    .update(
      `${email}:${otp}`
    )
    .digest('hex');
}


function hashText(
  value
) {

  return crypto
    .createHash('sha256')
    .update(
      String(value),
      'utf8'
    )
    .digest('hex');
}


function safeCompare(
  a,
  b
) {

  if (
    typeof a !== 'string' ||
    typeof b !== 'string'
  ) {
    return false;
  }

  const bufferA =
    Buffer.from(a);

  const bufferB =
    Buffer.from(b);

  if (
    bufferA.length !==
    bufferB.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    bufferA,
    bufferB
  );
}


function generateUserId() {

  return (
    'USR-' +
    crypto.randomUUID()
  );
}


// ============================================================
// DATABASE HELPERS
// ============================================================

function loadDatabase() {

  const db =
    readDB() || {};

  if (
    !Array.isArray(
      db.users
    )
  ) {
    db.users = [];
  }

  return db;
}


function findUserByEmail(
  email
) {

  const db =
    loadDatabase();

  return db.users.find(
    user =>
      typeof user.email === 'string' &&
      user.email.toLowerCase() ===
        email.toLowerCase()
  );
}


function findUserById(
  id
) {

  const db =
    loadDatabase();

  return db.users.find(
    user =>
      user.id === id
  );
}


// ============================================================
// AUDIT HASH CHAIN
// ============================================================

const auditDirectory =
  path.join(
    __dirname,
    'logs'
  );

const auditFile =
  path.join(
    auditDirectory,
    'security-audit.jsonl'
  );

fs.mkdirSync(
  auditDirectory,
  {
    recursive: true
  }
);


let previousAuditHash =
  'GENESIS';


function recoverAuditHash() {

  try {

    if (
      !fs.existsSync(
        auditFile
      )
    ) {
      return 'GENESIS';
    }

    const content =
      fs.readFileSync(
        auditFile,
        'utf8'
      );

    const lines =
      content
        .trim()
        .split('\n')
        .filter(Boolean);

    if (!lines.length) {
      return 'GENESIS';
    }

    const last =
      JSON.parse(
        lines[
          lines.length - 1
        ]
      );

    return (
      last.eventHash ||
      'GENESIS'
    );

  } catch (error) {

    console.error(
      '[AUDIT] Impossible de récupérer la chaîne :',
      error.message
    );

    return 'GENESIS';
  }
}


previousAuditHash =
  recoverAuditHash();


function writeAuditEvent(
  eventType,
  metadata = {},
  req = null
) {

  try {

    const event = {

      timestamp:
        new Date()
          .toISOString(),

      eventId:
        crypto.randomUUID(),

      eventType,

      requestId:
        req?.requestId ||
        null,

      actor:
        req?.user?.email ||
        null,

      sourceIp:
        req?.ip ||
        null,

      metadata,

      previousHash:
        previousAuditHash
    };

    const canonical =
      JSON.stringify(
        event
      );

    const eventHash =
      crypto
        .createHash('sha256')
        .update(
          canonical,
          'utf8'
        )
        .digest('hex');

    event.eventHash =
      eventHash;

    fs.appendFileSync(
      auditFile,
      JSON.stringify(event) +
        '\n',
      {
        encoding: 'utf8',
        mode: 0o600
      }
    );

    previousAuditHash =
      eventHash;

  } catch (error) {

    /*
     * Audit failure is logged, but we avoid crashing
     * the entire application process here.
     */

    console.error(
      '[AUDIT ERROR]',
      error.message
    );
  }
}


// ============================================================
// USER RESPONSE SANITIZATION
// ============================================================

function publicUser(
  user
) {

  if (!user) {
    return null;
  }

  return {

    id:
      user.id,

    nom:
      user.nom,

    email:
      user.email,

    telephone:
      user.telephone || '',

    isVerified:
      Boolean(
        user.isVerified
      ),

    isPremium:
      Boolean(
        user.isPremium
      ),

    scoreCTF:
      Number(
        user.scoreCTF || 0
      )
  };
}


// ============================================================
// JWT
// ============================================================

function issueAccessToken(
  user
) {

  const now =
    Math.floor(
      Date.now() / 1000
    );

  return jwt.sign(

    {
      sub:
        user.id,

      email:
        user.email,

      nom:
        user.nom,

      typ:
        'access',

      jti:
        crypto.randomUUID(),

      iat:
        now
    },

    JWT_SECRET,

    {
      algorithm:
        'HS256',

      expiresIn:
        JWT_TTL,

      issuer:
        JWT_ISSUER,

      audience:
        JWT_AUDIENCE
    }
  );
}


// ============================================================
// EMAIL TEMPLATES
// ============================================================

function buildOTPEmail(
  name,
  otp
) {

  const safeName =
    escapeHtml(
      name || 'Utilisateur'
    );

  const safeOTP =
    escapeHtml(
      otp
    );

  return `
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Activation DorkNet</title>
</head>

<body style="
  margin:0;
  padding:0;
  background:#0d1117;
  color:#f8fafc;
  font-family:Arial,Helvetica,sans-serif;
">

<div style="
  max-width:560px;
  margin:40px auto;
  background:#161b22;
  border:1px solid #30363d;
  border-radius:12px;
  padding:32px;
">

  <h2 style="
    color:#06b6d4;
    margin-top:0;
  ">
    DorkNet Security
  </h2>

  <p>
    Bonjour ${safeName},
  </p>

  <p>
    Votre code de validation est :
  </p>

  <div style="
    background:#0d1117;
    border:1px solid #30363d;
    border-radius:8px;
    padding:20px;
    text-align:center;
    font-size:32px;
    font-weight:bold;
    letter-spacing:8px;
    color:#10b981;
  ">
    ${safeOTP}
  </div>

  <p>
    Ce code expire dans 10 minutes.
  </p>

  <p style="
    color:#94a3b8;
    font-size:13px;
  ">
    Ne communiquez jamais ce code à un tiers.
  </p>

</div>

</body>
</html>
`;
}


async function sendOTPEmail(
  email,
  name,
  otp
) {

  if (!resend) {

    if (PRODUCTION) {
      return false;
    }

    console.log(
      `[DEV] OTP generated for ${email}`
    );

    /*
     * Never print the actual OTP.
     */

    return true;
  }

  try {

    await resend.emails.send({

      from:
        `${SENDER_NAME} <${SENDER_EMAIL}>`,

      to:
        [email],

      subject:
        'Code d’activation DorkNet Security',

      html:
        buildOTPEmail(
          name,
          otp
        )
    });

    return true;

  } catch (error) {

    console.error(
      '[EMAIL OTP ERROR]',
      error.message
    );

    return false;
  }
}


// ============================================================
// FRONTEND
// ============================================================

app.get(
  '/',
  (req, res) => {

    res.sendFile(
      path.join(
        publicDirectory,
        'index.html'
      )
    );
  }
);


// ============================================================
// HEALTH
// ============================================================

app.get(
  '/health',
  (req, res) => {

    return res.status(200).json({

      status:
        'healthy',

      service:
        APP_NAME,

      version:
        APP_VERSION,

      environment:
        NODE_ENV,

      timestamp:
        new Date()
          .toISOString(),

      requestId:
        req.requestId,

      services: {

        gemini:
          ai
            ? 'configured'
            : 'not_configured',

        resend:
          resend
            ? 'configured'
            : 'not_configured',

        database:
          'configured'
      }
    });
  }
);


// ============================================================
// API INFO
// ============================================================

app.get(
  '/api/info',
  (req, res) => {

    return res.json({

      success:
        true,

      service:
        APP_NAME,

      version:
        APP_VERSION,

      capabilities: [

        'JWT authentication',

        'OTP authentication',

        'Rate limiting',

        'Security headers',

        'Strict CORS',

        'Audit hash chain',

        'AGATA-AI',

        'Signed audit PDF'
      ],

      requestId:
        req.requestId
    });
  }
);


// ============================================================
// 1. AUDIT REQUEST
// ============================================================

app.post(
  '/api/audit',
  auditLimiter,
  async (req, res) => {

    const nom =
      cleanString(
        req.body?.nom,
        MAX_NAME_LENGTH
      );

    const email =
      normalizeEmail(
        req.body?.email
      );

    const service =
      cleanString(
        req.body?.service,
        MAX_SERVICE_LENGTH
      );

    const message =
      cleanString(
        req.body?.message,
        MAX_MESSAGE_LENGTH
      );

    if (
      !nom ||
      !email ||
      !service ||
      !message
    ) {

      return res.status(400).json({

        success:
          false,

        error: {
          code:
            'VALIDATION_ERROR',

          message:
            'Tous les champs sont obligatoires.'
        },

        requestId:
          req.requestId
      });
    }

    try {

      let pdfBuffer =
        null;

      /*
       * PDF generation is isolated from
       * email delivery.
       */

      try {

        pdfBuffer =
          await createSignedAuditPDF({

            nom,

            email,

            service,

            message
          });

      } catch (pdfError) {

        console.warn(
          '[AUDIT PDF WARNING]',
          pdfError.message
        );

        writeAuditEvent(
          'audit_pdf_generation_failed',
          {
            error:
              pdfError.message
          },
          req
        );
      }


      if (resend) {

        const emailPayload = {

          from:
            `${SENDER_NAME} <${SENDER_EMAIL}>`,

          to:
            [email],

          subject:
            'Accusé de réception & NDA - DorkNet',

          html: `
<!doctype html>
<html lang="fr">
<body style="
  font-family:Arial,sans-serif;
  background:#0f172a;
  color:#f8fafc;
  padding:30px;
">

<div style="
  max-width:650px;
  margin:auto;
  background:#111827;
  padding:30px;
  border-radius:12px;
">

<h2 style="
  color:#06b6d4;
">
Bonjour ${escapeHtml(nom)},
</h2>

<p>
Nous confirmons la réception de votre
demande d'audit pour :
<strong>
${escapeHtml(service)}
</strong>.
</p>

<p>
Un accusé de réception signé numériquement
est joint à ce courriel.
</p>

<p>
Cordialement,<br>
<strong>
L'équipe DorkNet Security
</strong>
</p>

</div>

</body>
</html>
`
        };


        if (pdfBuffer) {

          emailPayload.attachments = [

            {
              filename:
                'Accuse_Reception_DorkNet.pdf',

              content:
                pdfBuffer.toString(
                  'base64'
                )
            }

          ];
        }


        await resend.emails.send(
          emailPayload
        );

      } else {

        console.log(
          `[DEV EMAIL] Audit request for ${email}`
        );
      }


      writeAuditEvent(
        'audit_request_created',
        {
          emailHash:
            hashText(email),

          service:
            service
        },
        req
      );


      return res.status(200).json({

        success:
          true,

        message:
          'Demande transmise avec succès.',

        requestId:
          req.requestId
      });

    } catch (error) {

      console.error(
        '[AUDIT ERROR]',
        error.message
      );

      writeAuditEvent(
        'audit_request_failed',
        {
          error:
            error.message
        },
        req
      );

      return res.status(500).json({

        success:
          false,

        error: {
          code:
            'AUDIT_PROCESSING_ERROR',

          message:
            'Erreur lors du traitement de la demande.'
        },

        requestId:
          req.requestId
      });
    }
  }
);


// ============================================================
// 2. REGISTER — REQUEST OTP
// ============================================================

app.post(
  '/api/auth/register-otp',
  authLimiter,
  async (req, res) => {

    try {

      const nom =
        cleanString(
          req.body?.nom,
          MAX_NAME_LENGTH
        );

      const email =
        normalizeEmail(
          req.body?.email
        );

      const telephone =
        normalizePhone(
          req.body?.telephone
        );

      const password =
        req.body?.password;


      if (
        !nom ||
        !email ||
        !password
      ) {

        return res.status(400).json({

          success:
            false,

          error: {
            code:
              'MISSING_FIELDS',

            message:
              'Champs obligatoires manquants.'
          },

          requestId:
            req.requestId
        });
      }


      if (
        typeof password !== 'string' ||
        password.length < 12 ||
        password.length > 128
      ) {

        return res.status(400).json({

          success:
            false,

          error: {
            code:
              'WEAK_PASSWORD',

            message:
              'Le mot de passe doit contenir entre 12 et 128 caractères.'
          },

          requestId:
            req.requestId
        });
      }


      /*
       * Password policy.
       */

      const passwordPolicy =
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9])/;

      if (
        !passwordPolicy.test(
          password
        )
      ) {

        return res.status(400).json({

          success:
            false,

          error: {
            code:
              'PASSWORD_POLICY',

            message:
              'Le mot de passe doit contenir une majuscule, une minuscule, un chiffre et un caractère spécial.'
          },

          requestId:
            req.requestId
        });
      }


      const existingUser =
        findUserByEmail(
          email
        );


      if (existingUser) {

        /*
         * Do not reveal unnecessary account details.
         */

        return res.status(409).json({

          success:
            false,

          error: {
            code:
              'ACCOUNT_EXISTS',

            message:
              'Cette adresse est déjà enregistrée.'
          },

          requestId:
            req.requestId
        });
      }


      const otp =
        generateOTP();

      const otpHash =
        hashOTP(
          email,
          otp
        );

      const passwordHash =
        await bcrypt.hash(
          password,
          BCRYPT_ROUNDS
        );


      const newUser = {

        id:
          generateUserId(),

        nom,

        email,

        telephone,

        password:
          passwordHash,

        isVerified:
          false,

        otp: {

          hash:
            otpHash,

          expiresAt:
            Date.now() +
            OTP_TTL_MS,

          attempts:
            0
        },

        isPremium:
          false,

        scoreCTF:
          0,

        createdAt:
          new Date()
            .toISOString()
      };


      const db =
        loadDatabase();

      db.users.push(
        newUser
      );

      writeDB(db);


      const delivered =
        await sendOTPEmail(
          email,
          nom,
          otp
        );


      writeAuditEvent(
        'registration_otp_requested',
        {
          userId:
            newUser.id,

          emailHash:
            hashText(email),

          delivery:
            delivered
              ? 'accepted'
              : 'failed'
        },
        req
      );


      if (!delivered) {

        return res.status(503).json({

          success:
            false,

          error: {
            code:
              'OTP_DELIVERY_FAILED',

            message:
              'Le service de validation est temporairement indisponible.'
          },

          requestId:
            req.requestId
        });
      }


      return res.status(202).json({

        success:
          true,

        message:
          'Code de validation envoyé.',

        expiresIn:
          OTP_TTL_MS / 1000,

        requestId:
          req.requestId
      });

    } catch (error) {

      console.error(
        '[REGISTER ERROR]',
        error.message
      );

      return res.status(500).json({

        success:
          false,

        error: {
          code:
            'REGISTRATION_FAILED',

          message:
            'Échec de l’enregistrement.'
        },

        requestId:
          req.requestId
      });
    }
  }
);


// ============================================================
// 3. VERIFY REGISTRATION OTP
// ============================================================

app.post(
  '/api/auth/verify-registration-otp',
  otpLimiter,
  async (req, res) => {

    try {

      const email =
        normalizeEmail(
          req.body?.email
        );

      const otp =
        cleanString(
          req.body?.otp,
          16
        );


      if (
        !email ||
        !/^\d{6}$/.test(otp)
      ) {

        return res.status(400).json({

          success:
            false,

          error: {
            code:
              'INVALID_OTP',

            message:
              'Code OTP invalide.'
          },

          requestId:
            req.requestId
        });
      }


      const db =
        loadDatabase();

      const user =
        db.users.find(
          candidate =>
            candidate.email ===
            email
        );


      if (!user) {

        return res.status(400).json({

          success:
            false,

          error: {
            code:
              'INVALID_OTP',

            message:
              'Code invalide ou expiré.'
          },

          requestId:
            req.requestId
        });
      }


      if (
        user.isVerified
      ) {

        return res.status(409).json({

          success:
            false,

          error: {
            code:
              'ALREADY_VERIFIED',

            message:
              'Compte déjà vérifié.'
          },

          requestId:
            req.requestId
        });
      }


      if (
        !user.otp ||
        !user.otp.hash
      ) {

        return res.status(400).json({

          success:
            false,

          error: {
            code:
              'INVALID_OTP',

            message:
              'Code invalide ou expiré.'
          },

          requestId:
            req.requestId
        });
      }


      if (
        Date.now() >
        user.otp.expiresAt
      ) {

        user.otp = null;

        writeDB(db);

        return res.status(400).json({

          success:
            false,

          error: {
            code:
              'OTP_EXPIRED',

            message:
              'Code OTP expiré.'
          },

          requestId:
            req.requestId
        });
      }


      if (
        user.otp.attempts >=
        OTP_MAX_ATTEMPTS
      ) {

        user.otp = null;

        writeDB(db);

        writeAuditEvent(
          'registration_otp_locked',
          {
            userId:
              user.id
          },
          req
        );

        return res.status(429).json({

          success:
            false,

          error: {
            code:
              'OTP_LOCKED',

            message:
              'Nombre maximal de tentatives atteint.'
          },

          requestId:
            req.requestId
        });
      }


      const suppliedHash =
        hashOTP(
          email,
          otp
        );


      const valid =
        safeCompare(
          suppliedHash,
          user.otp.hash
        );


      if (!valid) {

        user.otp.attempts += 1;

        writeDB(db);

        writeAuditEvent(
          'registration_otp_failed',
          {
            userId:
              user.id,

            attempt:
              user.otp.attempts
          },
          req
        );

        return res.status(400).json({

          success:
            false,

          error: {
            code:
              'INVALID_OTP',

            message:
              'Code OTP incorrect.'
          },

          requestId:
            req.requestId
        });
      }


      /*
       * OTP is one-time-use.
       */

      user.isVerified =
        true;

      user.otp =
        null;

      user.verifiedAt =
        new Date()
          .toISOString();

      writeDB(db);


      writeAuditEvent(
        'account_verified',
        {
          userId:
            user.id
        },
        req
      );


      return res.status(200).json({

        success:
          true,

        message:
          'Compte vérifié avec succès.',

        user:
          publicUser(
            user
          ),

        requestId:
          req.requestId
      });

    } catch (error) {

      console.error(
        '[OTP VERIFY ERROR]',
        error.message
      );

      return res.status(500).json({

        success:
          false,

        error: {
          code:
            'OTP_VERIFICATION_FAILED',

          message:
            'Erreur lors de la vérification.'
        },

        requestId:
          req.requestId
      });
    }
  }
);


// ============================================================
// 4. LOGIN
// ============================================================

app.post(
  '/api/auth/login',
  loginLimiter,
  async (req, res) => {

    try {

      const email =
        normalizeEmail(
          req.body?.email
        );

      const password =
        req.body?.password;


      if (
        !email ||
        typeof password !== 'string'
      ) {

        return res.status(401).json({

          success:
            false,

          error: {
            code:
              'INVALID_CREDENTIALS',

            message:
              'Identifiants invalides.'
          },

          requestId:
            req.requestId
        });
      }


      const user =
        findUserByEmail(
          email
        );


      /*
       * Use a generic response to reduce
       * account enumeration.
       */

      if (!user) {

        return res.status(401).json({

          success:
            false,

          error: {
            code:
              'INVALID_CREDENTIALS',

            message:
              'Identifiants invalides.'
          },

          requestId:
            req.requestId
        });
      }


      const passwordValid =
        await bcrypt.compare(
          password,
          user.password
        );


      if (!passwordValid) {

        writeAuditEvent(
          'login_failed',
          {
            userId:
              user.id
          },
          req
        );

        return res.status(401).json({

          success:
            false,

          error: {
            code:
              'INVALID_CREDENTIALS',

            message:
              'Identifiants invalides.'
          },

          requestId:
            req.requestId
        });
      }


      if (
        !user.isVerified
      ) {

        return res.status(403).json({

          success:
            false,

          error: {
            code:
              'ACCOUNT_NOT_VERIFIED',

            message:
              'Le compte doit être vérifié avant connexion.'
          },

          requestId:
            req.requestId
        });
      }


      const token =
        issueAccessToken(
          user
        );


      writeAuditEvent(
        'login_success',
        {
          userId:
            user.id
        },
        req
      );


      return res.status(200).json({

        success:
          true,

        token,

        tokenType:
          'Bearer',

        expiresIn:
          JWT_TTL,

        user:
          publicUser(
            user
          ),

        requestId:
          req.requestId
      });

    } catch (error) {

      console.error(
        '[LOGIN ERROR]',
        error.message
      );

      return res.status(500).json({

        success:
          false,

        error: {
          code:
            'LOGIN_FAILED',

          message:
            'Erreur d’authentification.'
        },

        requestId:
          req.requestId
      });
    }
  }
);


// ============================================================
// 5. CURRENT USER
// ============================================================

app.get(
  '/api/auth/me',
  authenticateToken,
  (req, res) => {

    try {

      /*
       * Depending on authMiddleware implementation,
       * req.user may contain the decoded JWT.
       */

      const userId =
        req.user?.id ||
        req.user?.sub;

      const email =
        req.user?.email;


      let user =
        userId
          ? findUserById(
              userId
            )
          : null;


      if (!user && email) {

        user =
          findUserByEmail(
            email
          );
      }


      if (!user) {

        return res.status(404).json({

          success:
            false,

          error: {
            code:
              'USER_NOT_FOUND',

            message:
              'Utilisateur introuvable.'
          },

          requestId:
            req.requestId
        });
      }


      return res.json({

        success:
          true,

        user:
          publicUser(
            user
          ),

        requestId:
          req.requestId
      });

    } catch (error) {

      console.error(
        '[ME ERROR]',
        error.message
      );

      return res.status(500).json({

        success:
          false,

        error: {
          code:
            'PROFILE_ERROR',

          message:
            'Impossible de récupérer le profil.'
        },

        requestId:
          req.requestId
      });
    }
  }
);


// ============================================================
// 6. AGATA-AI
// ============================================================

app.post(
  '/api/agata/chat',
  aiLimiter,
  authenticateToken,
  async (req, res) => {

    const message =
      cleanString(
        req.body?.message,
        MAX_AI_MESSAGE_LENGTH
      );


    if (!message) {

      return res.status(400).json({

        success:
          false,

        error: {
          code:
            'INVALID_MESSAGE',

          message:
            'Message invalide.'
        },

        requestId:
          req.requestId
      });
    }


    if (!ai) {

      return res.status(503).json({

        success:
          false,

        error: {
          code:
            'AI_UNAVAILABLE',

          message:
            'AGATA-AI est temporairement indisponible.'
        },

        requestId:
          req.requestId
      });
    }


    try {

      /*
       * Explicit system instruction.
       *
       * The application does not grant the model
       * direct access to infrastructure.
       */

      const systemInstruction = `
Tu es AGATA-AI, assistant de cybersécurité
du système DorkNet.

OBJECTIFS:
- Fournir des analyses techniques défensives.
- Aider à comprendre les vulnérabilités.
- Proposer des mesures de durcissement.
- Prioriser les risques à partir des preuves fournies.
- Ne jamais prétendre avoir exécuté une action
  qui n'a pas réellement été exécutée.

CONTRAINTES:
- Ne pas inventer de résultats de scan.
- Ne pas inventer de CVE, score ou preuve.
- Distinguer clairement faits, hypothèses
  et recommandations.
- Ne pas divulguer de secrets, tokens ou clés.
- Ne pas demander de mot de passe.
- Les actions sur une infrastructure doivent
  rester dans un contexte explicitement autorisé.
- Répondre de manière concise, professionnelle
  et techniquement précise.

FORMAT:
1. Diagnostic
2. Risque
3. Preuves nécessaires
4. Remédiation
5. Validation
`;


      const response =
        await ai.models.generateContent({

          model:
            GEMINI_MODEL,

          contents:
            message,

          config: {

            systemInstruction,

            temperature:
              0.2,

            maxOutputTokens:
              1800,

            candidateCount:
              1,

            safetySettings: [

              {
                category:
                  'HARM_CATEGORY_HATE_SPEECH',

                threshold:
                  'BLOCK_MEDIUM_AND_ABOVE'
              },

              {
                category:
                  'HARM_CATEGORY_HARASSMENT',

                threshold:
                  'BLOCK_MEDIUM_AND_ABOVE'
              },

              {
                category:
                  'HARM_CATEGORY_DANGEROUS_CONTENT',

                threshold:
                  'BLOCK_MEDIUM_AND_ABOVE'
              }
            ]
          }
        });


      const generatedText =
        response?.text;


      if (
        typeof generatedText !==
        'string' ||
        !generatedText.trim()
      ) {

        writeAuditEvent(
          'ai_empty_response',
          {
            model:
              GEMINI_MODEL
          },
          req
        );

        return res.status(502).json({

          success:
            false,

          error: {
            code:
              'AI_EMPTY_RESPONSE',

            message:
              'AGATA-AI n’a pas produit de réponse.'
          },

          requestId:
            req.requestId
        });
      }


      writeAuditEvent(
        'ai_request_completed',
        {
          model:
            GEMINI_MODEL,

          inputLength:
            message.length,

          outputLength:
            generatedText.length
        },
        req
      );


      return res.status(200).json({

        success:
          true,

        response:
          generatedText,

        model:
          GEMINI_MODEL,

        requestId:
          req.requestId
      });

    } catch (error) {

      console.error(
        '[AGATA-AI ERROR]',
        error.message
      );


      writeAuditEvent(
        'ai_request_failed',
        {
          model:
            GEMINI_MODEL,

          errorType:
            error.name ||
            'UnknownError'
        },
        req
      );


      return res.status(502).json({

        success:
          false,

        error: {
          code:
            'AI_PROVIDER_ERROR',

          message:
            'AGATA-AI est temporairement indisponible.'
        },

        requestId:
          req.requestId
      });
    }
  }
);


// ============================================================
// 7. LOGOUT
// ============================================================

app.post(
  '/api/auth/logout',
  authenticateToken,
  (req, res) => {

    /*
     * JWT access tokens are stateless.
     *
     * For full enterprise revocation:
     * - short-lived access tokens
     * - rotating refresh tokens
     * - Redis JTI denylist
     * - session/device registry
     */

    writeAuditEvent(
      'logout',
      {
        userId:
          req.user?.id ||
          req.user?.sub ||
          null
      },
      req
    );


    return res.status(200).json({

      success:
        true,

      message:
        'Déconnexion enregistrée.',

      requestId:
        req.requestId
    });
  }
);


// ============================================================
// 404 HANDLER
// ============================================================

app.use(
  (req, res) => {

    return res.status(404).json({

      success:
        false,

      error: {
        code:
          'NOT_FOUND',

        message:
          'Ressource introuvable.'
      },

      requestId:
        req.requestId
    });
  }
);


// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================

app.use(
  (error, req, res, next) => {

    console.error(
      '[GLOBAL ERROR]',
      {
        message:
          error.message,

        requestId:
          req.requestId
      }
    );


    writeAuditEvent(
      'unhandled_application_error',
      {
        errorType:
          error.name ||
          'UnknownError'
      },
      req
    );


    if (
      error.message ===
      'CORS origin denied.'
    ) {

      return res.status(403).json({

        success:
          false,

        error: {
          code:
            'CORS_DENIED',

          message:
            'Origine non autorisée.'
        },

        requestId:
          req.requestId
      });
    }


    if (
      error.type ===
      'entity.too.large'
    ) {

      return res.status(413).json({

        success:
          false,

        error: {
          code:
            'PAYLOAD_TOO_LARGE',

          message:
            'Requête trop volumineuse.'
        },

        requestId:
          req.requestId
      });
    }


    return res.status(500).json({

      success:
        false,

      error: {
        code:
          'INTERNAL_ERROR',

        message:
          'Erreur interne du serveur.'
      },

      requestId:
        req.requestId
    });
  }
);


// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

let server;


function shutdown(
  signal
) {

  console.log(
    `[SHUTDOWN] Signal ${signal} reçu.`
  );


  if (!server) {

    process.exit(
      0
    );
  }


  server.close(
    () => {

      console.log(
        '[SHUTDOWN] HTTP server fermé.'
      );

      process.exit(
        0
      );
    }
  );


  setTimeout(
    () => {

      console.error(
        '[SHUTDOWN] Timeout de fermeture.'
      );

      process.exit(
        1
      );

    },
    10000
  ).unref();
}


process.on(
  'SIGTERM',
  () =>
    shutdown(
      'SIGTERM'
    )
);

process.on(
  'SIGINT',
  () =>
    shutdown(
      'SIGINT'
    )
);


// ============================================================
// UNHANDLED PROMISES
// ============================================================

process.on(
  'unhandledRejection',
  reason => {

    console.error(
      '[PROCESS] Unhandled rejection:',
      reason
    );
  }
);


process.on(
  'uncaughtException',
  error => {

    console.error(
      '[PROCESS] Uncaught exception:',
      error
    );

    /*
     * A real process supervisor should restart the process.
     */

    if (PRODUCTION) {

      process.exit(
        1
      );
    }
  }
);


// ============================================================
// START
// ============================================================

server =
  app.listen(
    PORT,
    '0.0.0.0',
    () => {

      console.log(
        '=================================================='
      );

      console.log(
        `[START] ${APP_NAME}`
      );

      console.log(
        `[START] Version: ${APP_VERSION}`
      );

      console.log(
        `[START] Environment: ${NODE_ENV}`
      );

      console.log(
        `[START] Port: ${PORT}`
      );

      console.log(
        `[START] Gemini: ${
          ai
            ? 'enabled'
            : 'disabled'
        }`
      );

      console.log(
        `[START] Gemini model: ${GEMINI_MODEL}`
      );

      console.log(
        `[START] Resend: ${
          resend
            ? 'enabled'
            : 'disabled'
        }`
      );

      console.log(
        `[START] JWT issuer: ${JWT_ISSUER}`
      );

      console.log(
        '[START] Security middleware: enabled'
      );

      console.log(
        '[START] Rate limiting: enabled'
      );

      console.log(
        '[START] Audit hash-chain: enabled'
      );

      console.log(
        '=================================================='
      );
    }
  );


// ============================================================
// EXPORT
// ============================================================

module.exports = app;
const token = jwt.sign(
  {
    sub: user.id,
    id: user.id,
    email: user.email,
    nom: user.nom,
    role: user.role || 'user',
    jti: crypto.randomUUID()
  },
  JWT_SECRET,
  {
    algorithm: process.env.JWT_ALGORITHM || 'HS256',
    expiresIn: process.env.JWT_EXPIRES_IN || '12h',
    ...(process.env.JWT_ISSUER
      ? { issuer: process.env.JWT_ISSUER }
      : {}),
    ...(process.env.JWT_AUDIENCE
      ? { audience: process.env.JWT_AUDIENCE }
      : {})
  }
);
