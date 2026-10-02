const PDFDocument = require('pdfkit');
const crypto = require('crypto');

/**
 * Nettoie et sécurise un texte pour le rendu PDFKit.
 * @param {any} text - Texte brut à assainir
 * @param {number} maxLength - Longueur maximale autorisée
 * @returns {string}
 */
function sanitizeText(text, maxLength = 350) {
  if (typeof text !== 'string') return '';
  const cleaned = text.replace(/[\r\n\t]+/g, ' ').trim();
  return cleaned.length > maxLength ? `${cleaned.substring(0, maxLength)}...` : cleaned;
}

/**
 * Génère un accusé de réception PDF standard pour les demandes d'audit.
 * @param {Object} data - Données du client (nom, email, service, message)
 * @returns {Promise<Buffer>}
 */
function createAuditConfirmationPDF(data = {}) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 50, size: 'A4' });
      const buffers = [];

      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => resolve(Buffer.concat(buffers)));
      doc.on('error', reject);

      // En-tête (#0f172a)
      doc.rect(0, 0, 612, 120).fill('#0f172a');

      // Titre & Branding
      doc.font('Helvetica-Bold').fillColor('#06b6d4').fontSize(24).text('DORKNET SECURITY', 50, 40);
      doc.font('Helvetica').fillColor('#ffffff').fontSize(12).text("Accuse de Reception - Demande d'Audit", 50, 70);

      // Métadonnées
      const reference = `AUD-${Date.now().toString().slice(-6)}`;
      const dateStr = new Date().toLocaleDateString('fr-FR', {
        year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit'
      });

      doc.font('Helvetica').fillColor('#94a3b8').fontSize(10)
         .text(`Reference : ${reference}`, 400, 40, { align: 'right' })
         .text(`Date : ${dateStr}`, 400, 55, { align: 'right' });

      // Infos Client
      doc.font('Helvetica-Bold').fillColor('#0f172a').fontSize(14).text('INFORMATIONS CLIENT', 50, 150);
      
      doc.font('Helvetica').fontSize(10).fillColor('#334155');
      doc.text(`Nom / Entreprise : ${data.nom || 'N/A'}`, 50, 175);
      doc.text(`Email de Contact : ${data.email || 'N/A'}`, 50, 190);
      doc.text(`Service Sollicite : ${data.service || 'N/A'}`, 50, 205);

      // Encadré Résumé
      doc.rect(50, 235, 512, 110).fillAndStroke('#f8fafc', '#cbd5e1');
      doc.font('Helvetica-Bold').fillColor('#0f172a').fontSize(11).text('Details de la demande :', 65, 248);
      doc.font('Helvetica').fillColor('#475569').fontSize(9).text(sanitizeText(data.message), 65, 268, { width: 480, height: 65 });

      // Bannière de Statut
      doc.rect(50, 365, 512, 45).fill('#1e293b');
      doc.font('Helvetica-Bold').fillColor('#10b981').fontSize(11).text("Statut : En cours d'evaluation par nos experts", 65, 382);

      // Prochaines Étapes
      doc.font('Helvetica-Bold').fillColor('#0f172a').fontSize(12).text('Prochaines Etapes :', 50, 435);
      doc.font('Helvetica').fillColor('#334155').fontSize(10);
      doc.text("1. Un ingenieur en cybersecurite analysera la portee de votre perimetre.", 65, 455);
      doc.text("2. Vous recevrez une proposition d'intervention sous 24h.", 65, 473);
      doc.text("3. Pour toute urgence, contactez l'equipe directement sur WhatsApp.", 65, 491);

      // Pied de page
      doc.font('Helvetica').fontSize(9).fillColor('#94a3b8')
         .text('DorkNet Security - Expertise Pentesting & Cybersecurite', 50, 700, { align: 'center' })
         .text('Email : dorknet2024@gmail.com | WhatsApp : +243 859 148 909', 50, 715, { align: 'center' });

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

/**
 * Génère un document d'audit officiel incluant la clause NDA et l'empreinte cryptographique SHA-256.
 * @param {Object} data - Données du client (nom, email, service, message, timestamp)
 * @returns {Promise<Buffer>}
 */
function createSignedAuditPDF(data = {}) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 40, size: 'A4' });
      const buffers = [];

      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => resolve(Buffer.concat(buffers)));
      doc.on('error', reject);

      const timestamp = data.timestamp || Date.now();
      const rawDataToSign = `${data.nom || ''}|${data.email || ''}|${data.service || ''}|${timestamp}`;
      const digitalSignature = crypto.createHash('sha256').update(rawDataToSign).digest('hex');

      // Fond Dark Theme (#0f172a)
      doc.rect(0, 0, 612, 792).fill('#0f172a');

      // En-tête
      doc.font('Helvetica-Bold').fillColor('#06b6d4').fontSize(22).text('DORKNET SECURITY', 40, 40);
      doc.font('Helvetica').fillColor('#94a3b8').fontSize(9).text('INFRASTRUCTURES & HACKING ETHIQUE', 40, 65);

      const reference = `DNX-AUD-${timestamp.toString().slice(-6)}`;
      doc.font('Helvetica-Bold').fillColor('#38bdf8').fontSize(10).text('ACCUSE DE RECEPTION OFFICIEL', 350, 40, { align: 'right' });
      doc.font('Helvetica').fillColor('#cbd5e1').fontSize(9)
         .text(`Ref : ${reference}`, 350, 55, { align: 'right' })
         .text(`Date : ${new Date(timestamp).toLocaleDateString('fr-FR')}`, 350, 70, { align: 'right' });

      doc.moveTo(40, 90).lineTo(572, 90).strokeColor('#334155').lineWidth(1).stroke();

      // Section 1: Spécifications
      doc.rect(40, 105, 532, 120).fillAndStroke('#1e293b', '#334155');
      doc.font('Helvetica-Bold').fillColor('#06b6d4').fontSize(11).text('1. SPECIFICATIONS DE LA DEMANDE', 55, 118);
      
      doc.font('Helvetica').fillColor('#94a3b8').fontSize(9)
         .text('Entite / Entreprise :', 55, 140)
         .text('Email de Contact :', 55, 155)
         .text('Service Sollicite :', 55, 170)
         .text('Statut du Dossier :', 55, 185);

      doc.font('Helvetica-Bold').fillColor('#f8fafc').fontSize(9)
         .text(sanitizeText(data.nom, 50) || 'N/A', 170, 140)
         .text(sanitizeText(data.email, 50) || 'N/A', 170, 155)
         .text(sanitizeText(data.service, 50) || 'N/A', 170, 170);
      
      doc.fillColor('#10b981').text('VALIDE - TRANSMIS AU POLE TECHNIQUE', 170, 185);

      // Section 2: NDA / Termes Juridiques
      doc.rect(40, 240, 532, 150).fillAndStroke('#0b1120', '#06b6d4');
      doc.font('Helvetica-Bold').fillColor('#38bdf8').fontSize(10).text('2. CADRE REGLEMENTAIRE & ENGAGEMENT DE CONFIDENTIALITE (NDA)', 55, 252);

      const legalText = 
        "- Engagement de Confidentialite : L'equipe DorkNet s'engage a maintenir la stricte " +
        "confidentialite de toutes les donnees et vulnerabilites decouvertes lors des analyses preliminaires.\n\n" +
        "- Portee Reglementaire : Aucune tentative d'intrusion sur les systemes cibles ne sera " +
        "executee sans la signature prealable d'un mandat d'autorisation formel (Rules of Engagement - RoE).\n\n" +
        "- Assistance Premium 24/7 : Pour beneficier de l'accompagnement technique sur mesure a la resolution " +
        "des vulnerabilites, l'entreprise doit souscrire a la formule Premium DorkNet.";

      doc.font('Helvetica').fillColor('#94a3b8').fontSize(8.5).text(legalText, 55, 275, { width: 500, align: 'justify', lineGap: 2 });

      // Section 3: Signature Cryptographique
      doc.rect(40, 405, 532, 110).fillAndStroke('#1e293b', '#334155');
      doc.font('Helvetica-Bold').fillColor('#06b6d4').fontSize(11).text('3. AUTHENTIFICATION & SIGNATURE NUMERIQUE', 55, 418);

      doc.font('Helvetica').fillColor('#94a3b8').fontSize(8).text('Empreinte Cryptographique (SHA-256) :', 55, 438);
      doc.rect(55, 450, 500, 20).fill('#0f172a');
      doc.fillColor('#10b981').fontSize(7.5).font('Courier').text(digitalSignature, 60, 456);

      doc.font('Helvetica-Bold').fillColor('#f8fafc').fontSize(9).text('Validation Technique :', 55, 480);
      doc.font('Helvetica').fillColor('#38bdf8').fontSize(8.5).text('Enoch Numbi - Lead Pentester & Fondateur DorkNet', 55, 492);

      // Pied de page
      doc.font('Helvetica').fillColor('#64748b').fontSize(8)
         .text('DorkNet Security * Email : dorknet2024@gmail.com * WhatsApp : +243 859 148 909', 40, 720, { align: 'center' })
         .text('Kinshasa, Republique Democratique du Congo * Assistance Technique 24/7', 40, 732, { align: 'center' });

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

module.exports = { 
  createAuditConfirmationPDF, 
  createSignedAuditPDF 
};
