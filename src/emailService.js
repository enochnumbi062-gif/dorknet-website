const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);

/**
 * Envoie un e-mail de bienvenue au nouvel utilisateur.
 * @param {string} to - L'adresse e-mail du destinataire.
 * @param {string} username - Le nom d'utilisateur.
 */
const sendWelcomeEmail = async (to, username) => {
  try {
    const data = await resend.emails.send({
      from: 'DorkNet <onboarding@resend.dev>', // Pensez à configurer votre propre domaine sur Resend en production
      to: [to],
      subject: 'Bienvenue sur DorkNet !',
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #0d1117; color: #ffffff; border-radius: 8px;">
          <h2 style="color: #06b6d4;">Bienvenue sur DorkNet, ${username} !</h2>
          <p>Votre compte a été créé avec succès.</p>
          <p>Vous pouvez dès à présent vous connecter et explorer la plateforme.</p>
        </div>
      `,
    });

    console.log('[OK] E-mail de bienvenue envoyé via Resend:', data.id);
    return data;
  } catch (error) {
    console.error('[ERREUR] Échec de l\'envoi d\'e-mail via Resend:', error.message);
    // On ne stoppe pas l'exécution pour ne pas bloquer l'inscription
  }
};

module.exports = {
  sendWelcomeEmail
};
