import os
import ssl
import socket
import datetime
import time
import random
import ipaddress
import secrets
from functools import wraps
from urllib.parse import urlparse

import jwt
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

# Laisser simplement la lecture depuis l'environnement :
DATABASE_URL = os.getenv("DATABASE_URL")

# ==========================================
# INITIALISATION ET CONFIGURATION
# ==========================================
load_dotenv()

app = Flask(__name__)

# Restriction du CORS à l'origine cliente si spécifiée
CLIENT_URL = os.getenv("CLIENT_URL", "*")
CORS(app, resources={r"/api/*": {"origins": CLIENT_URL}})

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", secrets.token_hex(32))
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "dorknet2024@gmail.com")
SENDER_NAME = os.getenv("SENDER_NAME", "DorkNet Security")

if BREVO_API_KEY:
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key['api-key'] = BREVO_API_KEY
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
else:
    api_instance = None
    print("[WARNING] BREVO_API_KEY non trouvée. Les e-mails seront simulés en console.")

# ==========================================
# STOCKAGE OTP CENTRALISÉ (REDIS / FALLBACK)
# ==========================================
REDIS_URL = os.getenv("REDIS_URL")

if REDIS_URL:
    import redis
    redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
else:
    class SimpleRedisMock:
        def __init__(self):
            self.store = {}

        def setex(self, name, time_sec, value):
            expires = time.time() + time_sec
            self.store[name] = (value, expires)

        def get(self, name):
            if name in self.store:
                val, expires = self.store[name]
                if time.time() < expires:
                    return val
                del self.store[name]
            return None

        def delete(self, name):
            self.store.pop(name, None)

    redis_client = SimpleRedisMock()

USERS_DB = {}
CTF_CHALLENGES = {
    "chall-01": {"title": "Injection SQL basique", "flag": "DORKNET{sqli_bypass_2026}", "points": 100},
    "chall-02": {"title": "Analyse de trame Wireshark", "flag": "DORKNET{pcap_leak_found}", "points": 150},
    "chall-03": {"title": "Défaitement de Stéganographie LSB", "flag": "DORKNET{lsb_hidden_data}", "points": 200}
}

# ==========================================
# HELPER FUNCTIONS & PROTECTIONS
# ==========================================
def sanitize_text(text):
    """Nettoie une chaîne de caractères pour empêcher les injections HTML/XSS."""
    if not isinstance(text, str):
        return ""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

def is_private_or_loopback_ip(hostname):
    """Résout le nom de domaine et vérifie si l'IP est privée, locale ou réservée (Protection SSRF)."""
    try:
        ip_addr = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip_addr)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local, ip_addr
    except socket.gaierror:
        return True, None

def send_email_otp(user_email, otp_code):
    """Envoie le code OTP à l'utilisateur via l'API Brevo."""
    if not api_instance:
        print(f"[OTP SIMULATION] Code OTP pour {user_email} : {otp_code}")
        return True

    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": user_email}],
        sender={"name": SENDER_NAME, "email": SENDER_EMAIL},
        subject=f"Code d'authentification DorkNet : {otp_code}",
        html_content=f"""
        <div style="font-family: Arial, sans-serif; background-color: #0d1117; color: #ffffff; padding: 25px; border-radius: 8px; border: 1px solid #30363d;">
            <h2 style="color: #06b6d4; margin-top: 0;">DorkNet Security</h2>
            <p>Bonjour,</p>
            <p>Voici votre code de validation à usage unique (OTP) pour sécuriser votre accès :</p>
            <div style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #10b981; margin: 25px 0; background-color: #161b22; padding: 15px; text-align: center; border-radius: 6px;">
                {otp_code}
            </div>
            <p>Ce code expire dans <b>5 minutes</b>.</p>
        </div>
        """
    )
    try:
        api_instance.send_transac_email(send_smtp_email)
        return True
    except ApiException as e:
        print(f"[ERROR] Erreur d'envoi Brevo API: {e}")
        return False

# ==========================================
# DÉCORATEUR D'AUTHENTIFICATION JWT
# ==========================================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Accès refusé. Token d'authentification manquant."}), 401

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            current_user = data.get("email")
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Session expirée. Veuillez vous reconnecter."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Jeton d'authentification invalide."}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# ==========================================
# 1. FORMULAIRE D'AUDIT
# ==========================================
@app.route('/api/audit', methods=['POST'])
def handle_audit():
    data = request.get_json() or {}
    nom = sanitize_text(data.get("nom"))
    email = sanitize_text(data.get("email"))
    service = sanitize_text(data.get("service"))
    message = sanitize_text(data.get("message"))

    if not nom or not email or not message:
        return jsonify({"error": "Tous les champs obligatoires doivent être renseignés."}), 400

    if api_instance:
        try:
            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                to=[{"email": SENDER_EMAIL}],
                sender={"name": SENDER_NAME, "email": SENDER_EMAIL},
                subject=f"DEMANDE D'AUDIT : {service or 'Général'}",
                html_content=f"""
                <h3>Nouvelle demande d'audit DorkNet</h3>
                <p><b>Nom :</b> {nom}</p>
                <p><b>Email :</b> {email}</p>
                <p><b>Service :</b> {service}</p>
                <p><b>Message :</b></p>
                <pre>{message}</pre>
                """
            )
            api_instance.send_transac_email(send_smtp_email)
        except ApiException as e:
            print(f"[ERROR] Envoi mail d'audit: {e}")

    return jsonify({"success": True, "message": "Votre demande d'audit a été transmise avec succès !"}), 200

# ==========================================
# 2. AUTHENTIFICATION & GESTION OTP
# ==========================================
@app.route('/api/auth/request-otp', methods=['POST'])
def request_otp():
    data = request.get_json() or {}
    email = sanitize_text(data.get("email"))

    if not email:
        return jsonify({"error": "Adresse e-mail requise."}), 400

    otp_code = f"{random.randint(100000, 999999)}"
    redis_client.setex(f"otp:{email}", 300, otp_code)

    if send_email_otp(email, otp_code):
        return jsonify({"success": True, "message": "Code OTP envoyé par e-mail."}), 200
    else:
        return jsonify({"error": "Échec d'envoi de l'OTP."}), 500

@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json() or {}
    email = sanitize_text(data.get("email"))
    input_otp = str(data.get("otp", "")).strip()

    stored_otp = redis_client.get(f"otp:{email}")

    if not stored_otp:
        return jsonify({"error": "Code OTP inexistant ou expiré."}), 400

    if str(stored_otp) == input_otp:
        redis_client.delete(f"otp:{email}")
        
        expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
        token = jwt.encode({
            "email": email,
            "exp": expiration
        }, JWT_SECRET, algorithm="HS256")

        return jsonify({"success": True, "message": "Authentification réussie !", "token": token}), 200
    else:
        return jsonify({"error": "Code OTP incorrect."}), 400

# ==========================================
# 3. SCANNER D'AUDIT (PROTÉGÉ + PROTECTION SSRF)
# ==========================================
@app.route('/api/scanner/express', methods=['POST'])
@token_required
def express_scan(current_user):
    data = request.get_json() or {}
    target_url = data.get("url", "").strip()
    
    if not target_url:
        return jsonify({"error": "Veuillez fournir une URL valide."}), 400

    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    parsed_url = urlparse(target_url)
    domain = parsed_url.hostname or parsed_url.path.split('/')[0]

    if not domain:
        return jsonify({"error": "Impossible de déterminer l'hôte cible."}), 400

    # Protection contre les attaques SSRF
    is_private, resolved_ip = is_private_or_loopback_ip(domain)
    if is_private:
        return jsonify({
            "error": "Accès refusé. L'analyse d'adresses privées, locales ou non résolubles est strictement interdite."
        }), 403

    vulnerabilities = []
    score = 100

    # 1. Analyse du certificat SSL/TLS
    if target_url.startswith('https://'):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssock.getpeercert()
        except ssl.SSLError as e:
            vulnerabilities.append({"level": "CRITICAL", "issue": f"Erreur Certificat SSL/TLS : {getattr(e, 'reason', str(e))}"})
            score -= 40
        except Exception:
            vulnerabilities.append({"level": "HIGH", "issue": "Échec de connexion ou poignée de main SSL/TLS."})
            score -= 30
    else:
        vulnerabilities.append({"level": "CRITICAL", "issue": "Absence de chiffrement HTTPS"})
        score -= 40

    # 2. Analyse des En-têtes HTTP
    try:
        res = requests.get(target_url, timeout=5, headers={"User-Agent": "DorkNet-Scanner/1.0"}, allow_redirects=True)
        headers = res.headers

        security_headers = [
            "Strict-Transport-Security", 
            "X-Content-Type-Options", 
            "X-Frame-Options", 
            "Content-Security-Policy"
        ]
        for header in security_headers:
            if header not in headers:
                vulnerabilities.append({"level": "MEDIUM", "issue": f"En-tête manquant : {header}"})
                score -= 10

    except requests.exceptions.RequestException as e:
        vulnerabilities.append({"level": "MEDIUM", "issue": f"Erreur de communication HTTP : {str(e)}"})
        score -= 10

    return jsonify({
        "requested_by": current_user,
        "target": target_url,
        "resolved_ip": resolved_ip,
        "score": max(score, 0),
        "vulnerabilities": vulnerabilities,
        "recommendation": "Souscrivez à l'offre Premium DorkNet pour un audit approfondi."
    })

# ==========================================
# 4. ARÈNE CTF
# ==========================================
@app.route('/api/ctf/challenges', methods=['GET'])
@token_required
def get_challenges(current_user):
    public_list = [{"id": k, "title": v["title"], "points": v["points"]} for k, v in CTF_CHALLENGES.items()]
    return jsonify({"user": current_user, "challenges": public_list})

@app.route('/api/ctf/submit-flag', methods=['POST'])
@token_required
def submit_flag(current_user):
    data = request.get_json() or {}
    chall_id = data.get("challenge_id")
    submitted_flag = sanitize_text(data.get("flag", "")).strip()

    challenge = CTF_CHALLENGES.get(chall_id)
    if not challenge:
        return jsonify({"error": "Challenge inexistant"}), 404

    if submitted_flag == challenge["flag"]:
        user = USERS_DB.setdefault(current_user, {"score": 0})
        user["score"] += challenge["points"]
        
        return jsonify({
            "success": True, 
            "message": f"Flag correct ! +{challenge['points']} points attribués.",
            "total_score": user["score"]
        })
    else:
        return jsonify({"error": "Flag incorrect. Réessayez !"}), 400

# ==========================================
# LANCEMENT DU SERVEUR FLASK
# ==========================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    is_debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=is_debug)
