require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Resend } = require('resend');
const { GoogleGenAI } = require('@google/genai');

// Environment variables
const DATABASE_URL = process.env.DATABASE_URL;
const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const RESEND_API_KEY = process.env.RESEND_API_KEY;

// Modules externes
const { readDB, writeDB } = require('./database');
const { authenticateToken, JWT_SECRET } = require('./authMiddleware');
const { createSignedAuditPDF } = require('./generatePDF');

const app = express();

// Confiance au proxy de Render (indispensable pour express-rate-limit)
app.set('trust proxy', 1);

// ==========================================
// INITIALISATION DES SERVICES EXTERNES
// ==========================================
const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

if (!RESEND_API_KEY) {
  console.warn('[WARNING] RESEND_API_KEY non configurée. Les emails seront simulés dans la console.');
}

// ==========================================
// MIDDLEWARES DE SÉCURITÉ & PARSING
// ==========================================
app.use(express.json({ limit: '10kb' })); // Protection contre le flood JSON
app.use(cors({ 
  origin: CLIENT_URL,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Servir les fichiers statiques HTML/CSS/JS depuis le dossier 'public'
app.use(express.static(path.join(__dirname, '../public')));

// Limiteurs de requêtes anti-bruteforce / anti-spam
const auditLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Trop de requêtes. Veuillez réessayer dans 15 minutes." }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Trop de tentatives d'authentification. Réessayez plus tard." }
});

// Helpers
function sanitizeInput(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[&<>"']/g, (m) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[m]);
}

function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

// ==========================================
// ROUTE PRINCIPALE (FRONTEND)
// ==========================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ==========================================
// 1. ROUTE FORMULAIRE D'AUDIT
// ==========================================
app.post('/api/audit', auditLimiter, async (req, res) => {
  const nom = sanitizeInput(req.body.nom);
  const email = sanitizeInput(req.body.email);
  const service = sanitizeInput(req.body.service);
  const message = sanitizeInput(req.body.message);

  if (!nom || !email || !service || !message) {
    return res.status(400).json({ error: 'Tous les champs sont obligatoires.' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Format d\'adresse email invalide.' });
  }

  try {
    let pdfBuffer = null;
    try {
      pdfBuffer = await createSignedAuditPDF({ nom, email, service, message });
    } catch (pdfErr) {
      console.warn("[WARNING] Échec de la génération du PDF d'audit :", pdfErr.message);
    }

    if (resend) {
      const emailPayload = {
        from: 'DorkNet Security <onboarding@resend.dev>',
        to: [email],
        subject: `Accusé de réception & NDA - Audit DorkNet`,
        html: `
          <div style="font-family: Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 20px;">
            <h2 style="color: #06b6d4;">Bonjour ${nom},</h2>
            <p>Nous vous confirmons la bonne réception de votre demande d'audit pour le service : <strong>${service}</strong>.</p>
            <p>L'accusé de réception signé numériquement et incluant le NDA est joint à ce courriel.</p>
            <br>
            <p>Cordialement,<br><strong>L'équipe DorkNet Security</strong></p>
          </div>
        `
      };

      if (pdfBuffer) {
        emailPayload.attachments = [{
          filename: 'Accuse_Reception_DorkNet.pdf',
          content: pdfBuffer.toString('base64')
        }];
      }

      await resend.emails.send(emailPayload);
      console.log(`[OK] E-mail d'audit envoyé via Resend à ${email}`);
    } else {
      console.log(`[SIMULATION EMAIL AUDIT] Pour: ${email} - Service: ${service}`);
    }

    return res.status(200).json({ 
      success: true, 
      message: 'Demande transmise avec succès. Un reçu PDF vous a été envoyé.' 
    });

  } catch (error) {
    console.error('Erreur traitement audit :', error);
    return res.status(500).json({ error: 'Erreur serveur lors du traitement de l\'audit.' });
  }
});

// ==========================================
// 2. AUTHENTIFICATION & COMPTES
// ==========================================
app.post('/api/auth/register-otp', authLimiter, async (req, res) => {
  try {
    const { nom, email, telephone, password } = req.body;
    if (!nom || !email || !password) {
      return res.status(400).json({ error: "Champs obligatoires manquants." });
    }

    const db = readDB();
    if (!db.users) db.users = [];

    if (db.users.find(u => u.email === email)) {
      return res.status(400).json({ error: 'Adresse e-mail déjà enregistrée.' });
    }

    const otpCode = generateOTP();
    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = {
      id: `USR-${Date.now()}`,
      nom: sanitizeInput(nom),
      email: sanitizeInput(email),
      telephone: sanitizeInput(telephone || ''),
      password: hashedPassword,
      isVerified: false,
      otp: { code: otpCode, expires: Date.now() + 10 * 60 * 1000 },
      isPremium: false,
      scoreCTF: 0
    };

    db.users.push(newUser);
    writeDB(db);

    if (resend) {
      await resend.emails.send({
        from: 'DorkNet Security <onboarding@resend.dev>',
        to: [email],
        subject: `Code d'activation DorkNet : ${otpCode}`,
        html: `
          <div style="font-family: Arial, sans-serif; background-color: #0d1117; color: #ffffff; padding: 20px;">
            <h2>Activation de votre compte DorkNet</h2>
            <p>Votre code de validation est : <strong style="font-size: 24px; color: #10b981;">${otpCode}</strong></p>
          </div>
        `
      });
      console.log(`[OK] Code d'activation transmis via Resend à ${email}`);
    } else {
      console.log(`[SIMULATION OTP REGISTER] Code pour ${email} : ${otpCode}`);
    }

    res.json({ success: true, message: "Code OTP transmis par courrier électronique." });
  } catch (err) {
    console.error('[AUTH REGISTER ERROR]:', err);
    res.status(500).json({ error: "Échec de l'enregistrement." });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const db = readDB();

  const user = db.users?.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Identifiants invalides.' });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, nom: user.nom },
    JWT_SECRET,
    { expiresIn: '12h' }
  );

  res.json({ success: true, token, user: { id: user.id, nom: user.nom, email: user.email } });
});

// ==========================================
// 3. INTELLIGENCE ARTIFICIELLE AGATA-AI
// ==========================================
app.post('/api/agata/chat', authenticateToken, async (req, res) => {
  const { message } = req.body;

  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: "Requête invalide." });
  }

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-1.5-flash',
      contents: message,
      config: {
        systemInstruction: "Tu es AGATA-AI, l'assistant virtuel de cybersécurité du système DorkNet. Tes réponses doivent être concises, techniques et professionnelles."
      }
    });

    return res.json({ success: true, response: response.text });
  } catch (error) {
    console.error('[ERREUR AGATA-AI] :', error);
    return res.status(500).json({ error: "L'assistant IA est temporairement indisponible." });
  }
});

// ==========================================
// DÉMARRAGE DU SERVEUR
// ==========================================
app.listen(PORT, () => {
  console.log(`[START] Serveur Backend DorkNet actif sur le port ${PORT}`);
});
