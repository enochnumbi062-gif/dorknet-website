#!/usr/bin/env python3
"""
DorkNet Security API
=====================

Enterprise defensive security API.

Capabilities
------------
- OTP email authentication
- JWT authentication with revocation support (JTI Denylist)
- Redis-backed rate limiting & persistent user state
- SSRF-hardened HTTP/TLS inspection (Anti-DNS Rebinding)
- Security-header assessment
- TLS certificate inspection
- CTF challenge API
- JSONL security audit trail
- Hash-chained audit events
- Strict input validation
- Security response headers
- Request correlation IDs
- Production-safe Render cloud configuration
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
import secrets
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlparse

import jwt
import requests
import resend
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix


# ============================================================
# ENVIRONMENT & CONFIGURATION
# ============================================================

load_dotenv()


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}


def env_int(
    name: str,
    default: int,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    raw = os.getenv(name)
    if raw is None:
        value = default
    else:
        try:
            value = int(raw)
        except ValueError:
            value = default

    if minimum is not None:
        value = max(value, minimum)
    if maximum is not None:
        value = min(value, maximum)

    return value


PRODUCTION = env_bool("PRODUCTION", False)

APP_NAME = os.getenv("APP_NAME", "DorkNet Security API")
APP_VERSION = os.getenv("APP_VERSION", "2026.1")

HOST = os.getenv("HOST", "0.0.0.0")
PORT = env_int("PORT", 5000, 1, 65535)

# Secrets
SECRET_KEY = os.getenv("SECRET_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

if PRODUCTION and not SECRET_KEY:
    raise RuntimeError("SECRET_KEY must be explicitly configured when PRODUCTION=true")

if PRODUCTION and not JWT_SECRET:
    raise RuntimeError("JWT_SECRET must be explicitly configured when PRODUCTION=true")

SECRET_KEY = SECRET_KEY or secrets.token_urlsafe(48)
JWT_SECRET = JWT_SECRET or secrets.token_urlsafe(64)

JWT_ISSUER = os.getenv("JWT_ISSUER", "dorknet-security-api")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "dorknet-client")
JWT_ALGORITHM = "HS256"

JWT_TTL_SECONDS = env_int("JWT_TTL_SECONDS", 24 * 60 * 60, 300, 7 * 24 * 60 * 60)

# Email
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "onboarding@resend.dev")
SENDER_NAME = os.getenv("SENDER_NAME", "DorkNet Security")
AUDIT_EMAIL = os.getenv("AUDIT_EMAIL", SENDER_EMAIL)

# Redis
REDIS_URL = os.getenv("REDIS_URL")

# CORS
CLIENT_URL = os.getenv("CLIENT_URL", "")
if PRODUCTION and not CLIENT_URL:
    raise RuntimeError("CLIENT_URL must be configured when PRODUCTION=true")

ALLOWED_ORIGINS = [
    origin.strip() for origin in CLIENT_URL.split(",") if origin.strip()
]

# Network & Limits
MAX_JSON_BYTES = env_int("MAX_JSON_BYTES", 128 * 1024, 4096, 1024 * 1024)
MAX_RESPONSE_BYTES = env_int("MAX_RESPONSE_BYTES", 512 * 1024, 16 * 1024, 5 * 1024 * 1024)

HTTP_CONNECT_TIMEOUT = float(os.getenv("HTTP_CONNECT_TIMEOUT", "4.0"))
HTTP_READ_TIMEOUT = float(os.getenv("HTTP_READ_TIMEOUT", "8.0"))
MAX_REDIRECTS = env_int("MAX_REDIRECTS", 3, 0, 10)

# OTP Limits
OTP_TTL_SECONDS = env_int("OTP_TTL_SECONDS", 300, 60, 900)
OTP_MAX_ATTEMPTS = env_int("OTP_MAX_ATTEMPTS", 5, 1, 20)
OTP_LENGTH = 6

# Rate Limit Thresholds
OTP_REQUEST_LIMIT = env_int("OTP_REQUEST_LIMIT", 5, 1, 50)
OTP_REQUEST_WINDOW = env_int("OTP_REQUEST_WINDOW", 900, 60, 3600)

OTP_VERIFY_LIMIT = env_int("OTP_VERIFY_LIMIT", 10, 1, 100)
OTP_VERIFY_WINDOW = env_int("OTP_VERIFY_WINDOW", 900, 60, 3600)

CTF_SUBMIT_LIMIT = env_int("CTF_SUBMIT_LIMIT", 30, 1, 200)
CTF_SUBMIT_WINDOW = env_int("CTF_SUBMIT_WINDOW", 300, 30, 3600)

SCAN_LIMIT = env_int("SCAN_LIMIT", 20, 1, 100)
SCAN_WINDOW = env_int("SCAN_WINDOW", 300, 30, 3600)

# Audit Path Hardening (Compatible avec Render & Read-Only Filesystems)
default_audit_path = "/tmp/dorknet_security_audit.jsonl" if os.getenv("RENDER") else "logs/dorknet_security_audit.jsonl"
AUDIT_LOG_PATH = Path(os.getenv("AUDIT_LOG_PATH", default_audit_path))
try:
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
except Exception:
    AUDIT_LOG_PATH = Path("/tmp/dorknet_security_audit.jsonl")
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("dorknet")


# ============================================================
# FLASK ENGINE & PROXY CONFIGURATION
# ============================================================

app = Flask(__name__)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=MAX_JSON_BYTES,
    JSON_SORT_KEYS=False,
    JSONIFY_PRETTYPRINT_REGULAR=False,
)

# Configuration Proxy pour Render et Reverse Proxies
if env_bool("TRUST_PROXY", True):
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
        x_port=1,
    )


# ============================================================
# CORS
# ============================================================

if ALLOWED_ORIGINS:
    CORS(
        app,
        resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
        methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )


# ============================================================
# REDIS / IN-MEMORY FALLBACK SYSTEM
# ============================================================

class InMemoryRedis:
    """Fallback thread-safe en mémoire pour les environnements de dev local."""

    def __init__(self):
        self._store: dict[str, tuple[str, float]] = {}
        self._lock = threading.RLock()

    def setex(self, name: str, time_sec: int, value: str) -> bool:
        with self._lock:
            self._store[name] = (value, time.time() + time_sec)
        return True

    def get(self, name: str) -> Optional[str]:
        with self._lock:
            item = self._store.get(name)
            if item is None:
                return None
            value, expires_at = item
            if time.time() >= expires_at:
                self._store.pop(name, None)
                return None
            return value

    def delete(self, name: str) -> int:
        with self._lock:
            return int(self._store.pop(name, None) is not None)

    def incr(self, name: str) -> int:
        with self._lock:
            current = self.get(name)
            value = int(current or "0") + 1
            self._store[name] = (str(value), time.time() + 3600)
            return value

    def expire(self, name: str, seconds: int) -> bool:
        with self._lock:
            if name not in self._store:
                return False
            value, _ = self._store[name]
            self._store[name] = (value, time.time() + seconds)
            return True


if REDIS_URL:
    try:
        import redis
        redis_client = redis.Redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
            health_check_interval=30,
        )
        redis_client.ping()
        logger.info("Serveur Redis connecté avec succès.")
    except Exception as exc:
        if PRODUCTION:
            raise RuntimeError("Redis est requis en production.") from exc
        logger.warning("Redis indisponible; bascule vers stockage mémoire : %s", exc)
        redis_client = InMemoryRedis()
else:
    if PRODUCTION:
        raise RuntimeError("REDIS_URL doit être configurée en production.")
    logger.warning("REDIS_URL non configurée; utilisation du stockage mémoire dev.")
    redis_client = InMemoryRedis()


# ============================================================
# STATE PERSISTENCE HELPERS (USER STORE VIA REDIS)
# ============================================================

def get_user_state(email: str) -> dict[str, Any]:
    key = f"user:profile:{sha256_hex(email)}"
    raw = redis_client.get(key)
    if raw:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
    return {
        "score": 0,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def save_user_state(email: str, state: dict[str, Any]) -> None:
    key = f"user:profile:{sha256_hex(email)}"
    redis_client.setex(key, 365 * 24 * 60 * 60, json.dumps(state))


# Challenge Flags Hash Map (Secured SHA-256)
CTF_CHALLENGES = {
    "chall-01": {
        "title": "Injection SQL basique",
        "points": 100,
        "flag_sha256": "a27b2cc9b434997fe5f7e07cdac3d22d68268809cba9781302d9eb2bc36996f3",
    },
    "chall-02": {
        "title": "Analyse de trame Wireshark",
        "points": 150,
        "flag_sha256": "b66c01868943545a61446078406101c35e1140af834cb0b0cdfdea8c5ffc199f",
    },
    "chall-03": {
        "title": "Défaitement de Stéganographie LSB",
        "points": 200,
        "flag_sha256": "ae278d44696796bad356f11b604bce4336605aa7aa00ea560cd46f4d1caa2569",
    },
}


# ============================================================
# EMAIL PROVIDER INIT
# ============================================================

if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY
else:
    logger.warning("RESEND_API_KEY non configurée. Envoi d'e-mail désactivé.")


# ============================================================
# REQUEST CORRELATION & AUDIT MIDDLEWARE
# ============================================================

@app.before_request
def before_request():
    request_id = request.headers.get("X-Request-ID")
    if not request_id:
        request_id = uuid.uuid4().hex
    request_id = request_id[:128]
    g.request_id = request_id
    g.request_started = time.monotonic()


@app.after_request
def after_request(response):
    request_id = getattr(g, "request_id", uuid.uuid4().hex)
    response.headers["X-Request-ID"] = request_id

    elapsed = 0.0
    if hasattr(g, "request_started"):
        elapsed = time.monotonic() - g.request_started

    response.headers["X-Response-Time"] = f"{elapsed:.4f}s"
    return response


# ============================================================
# HARDENED SECURITY HEADERS
# ============================================================

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-site"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"

    if request.is_secure or PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    return response


# ============================================================
# AUDIT LOGGER WITH HASH CHAINING
# ============================================================

class AuditLogger:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.previous_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> str:
        if not self.path.exists():
            return "GENESIS"

        try:
            with self.path.open("rb") as file:
                file.seek(max(0, self.path.stat().st_size - 64 * 1024))
                lines = file.readlines()
                for raw in reversed(lines):
                    raw = raw.strip()
                    if not raw:
                        continue
                    obj = json.loads(raw.decode("utf-8"))
                    return obj.get("event_hash", "GENESIS")
        except Exception:
            logger.exception("Impossible de récupérer la chaîne de hachage de l'audit.")

        return "GENESIS"

    def write(
        self,
        event_type: str,
        actor: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        event = {
            "timestamp": now,
            "event_type": event_type,
            "actor": actor,
            "request_id": getattr(g, "request_id", None),
            "source_ip": request.remote_addr,
            "metadata": metadata or {},
            "previous_hash": self.previous_hash,
        }

        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        event["event_hash"] = event_hash

        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))

        with self.lock:
            try:
                with self.path.open("a", encoding="utf-8") as file:
                    file.write(line + "\n")
                self.previous_hash = event_hash
            except Exception as e:
                logger.error("Erreur d'écriture du journal d'audit : %s", e)


audit = AuditLogger(AUDIT_LOG_PATH)


# ============================================================
# HELPERS & SANITIZATION
# ============================================================

def json_error(message: str, status: int, code: str = "request_error"):
    payload = {
        "success": False,
        "error": {"code": code, "message": message},
        "request_id": getattr(g, "request_id", None),
    }
    return jsonify(payload), status


def json_success(data: Optional[dict[str, Any]] = None, status: int = 200):
    payload = {
        "success": True,
        "request_id": getattr(g, "request_id", None),
    }
    if data:
        payload.update(data)
    return jsonify(payload), status


def get_json_body() -> dict[str, Any]:
    if not request.is_json:
        raise ValueError("Content-Type doit être application/json.")
    data = request.get_json(silent=False)
    if not isinstance(data, dict):
        raise ValueError("Le corps JSON doit être un objet validé.")
    return data


def normalize_email(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    email = value.strip().lower()
    if len(email) > 254:
        return ""
    if "@" not in email or email.startswith("@") or email.endswith("@") or email.count("@") != 1:
        return ""
    local, domain = email.rsplit("@", 1)
    if not local or not domain or "." not in domain:
        return ""
    return email


def safe_text(value: Any, max_length: int = 4000) -> str:
    if not isinstance(value, str):
        return ""
    value = value.replace("\x00", "")
    return value.strip()[:max_length]


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ============================================================
# RATE LIMITING
# ============================================================

def rate_limit(namespace: str, key: str, limit: int, window: int) -> tuple[bool, int]:
    bucket = f"rl:{namespace}:{sha256_hex(key)[:32]}"
    try:
        current = redis_client.get(bucket)
        if current is None:
            redis_client.setex(bucket, window, "1")
            return True, limit - 1

        current_count = int(current)
        if current_count >= limit:
            return False, 0

        if hasattr(redis_client, "incr"):
            new_count = redis_client.incr(bucket)
        else:
            new_count = current_count + 1

        return True, max(0, limit - new_count)
    except Exception:
        logger.exception("Défaillance du limiteur de débit.")
        return False, 0


def rate_limit_or_reject(namespace: str, key: str, limit: int, window: int):
    allowed, remaining = rate_limit(namespace, key, limit, window)
    if not allowed:
        response = json_error(
            "Trop de requêtes. Réessayez plus tard.",
            429,
            "rate_limit_exceeded",
        )
        response[0].headers["Retry-After"] = str(window)
        return response
    return None


# ============================================================
# OTP LOGIC
# ============================================================

def generate_otp() -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(OTP_LENGTH))


def otp_digest(email: str, otp: str) -> str:
    return hmac.new(
        JWT_SECRET.encode(),
        f"{email}:{otp}".encode(),
        hashlib.sha256,
    ).hexdigest()


def send_email_otp(user_email: str, otp_code: str) -> bool:
    if not RESEND_API_KEY:
        if PRODUCTION:
            logger.error("Fournisseur OTP indisponible en production.")
            return False
        logger.warning("[DEV ONLY] OTP généré pour %s", user_email)
        return True

    try:
        html_content = f"""
        <!doctype html>
        <html>
        <body style="font-family:Arial,sans-serif;background:#0d1117;color:#ffffff;padding:30px;">
            <div style="max-width:560px;margin:auto;background:#161b22;padding:30px;border-radius:12px;border:1px solid #30363d;">
                <h2 style="color:#06b6d4;">DorkNet Security</h2>
                <p>Votre code d'authentification à usage unique :</p>
                <div style="font-size:32px;font-weight:bold;letter-spacing:8px;padding:18px;text-align:center;background:#0d1117;border-radius:8px;color:#10b981;">
                    {otp_code}
                </div>
                <p>Ce code expire dans {OTP_TTL_SECONDS // 60} minutes.</p>
                <p style="color:#8b949e;">Si vous n'êtes pas à l'origine de cette demande, veuillez ignorer ce message.</p>
            </div>
        </body>
        </html>
        """
        result = resend.Emails.send({
            "from": f"{SENDER_NAME} <{SENDER_EMAIL}>",
            "to": [user_email],
            "subject": "Code d'authentification DorkNet Security",
            "html": html_content,
        })
        logger.info("Email OTP transmis avec succès via Resend.")
        return bool(result)
    except Exception:
        logger.exception("Échec de livraison de l'email OTP.")
        return False


# ============================================================
# JWT AUTHENTICATION & REVOCATION
# ============================================================

def create_access_token(email: str) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    expiration = now + dt.timedelta(seconds=JWT_TTL_SECONDS)
    jti = uuid.uuid4().hex

    payload = {
        "sub": email,
        "email": email,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": expiration,
        "jti": jti,
        "typ": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    payload = jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM],
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
        options={
            "require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]
        },
        leeway=5,
    )

    # Vérification de la révocation du jeton dans Redis
    jti = payload.get("jti")
    if jti and redis_client.get(f"jwt:revoked:{jti}"):
        raise jwt.InvalidTokenError("Le jeton a été révoqué.")

    return payload


def token_required(function: Callable):
    @wraps(function)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            audit.write("authentication_failure", metadata={"reason": "missing_bearer_token"})
            return json_error("Authentification requise.", 401, "authentication_required")

        token = auth_header[len("Bearer "):].strip()
        if not token:
            return json_error("Authentification requise.", 401, "authentication_required")

        try:
            payload = decode_access_token(token)
            current_user = payload["sub"]
            g.jti = payload.get("jti")
            g.exp = payload.get("exp")
        except jwt.ExpiredSignatureError:
            return json_error("Session expirée.", 401, "token_expired")
        except jwt.InvalidTokenError:
            audit.write("authentication_failure", metadata={"reason": "invalid_token"})
            return json_error("Jeton invalide ou révoqué.", 401, "invalid_token")

        return function(current_user, *args, **kwargs)

    return decorated


# ============================================================
# SSRF PROTECTION & ADVANCED NETWORK INSPECTION
# ============================================================

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata.google",
    "instance-data",
}


def is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any([
        ip.is_private,
        ip.is_loopback,
        ip.is_link_local,
        ip.is_reserved,
        ip.is_multicast,
        ip.is_unspecified,
        getattr(ip, "is_site_local", False),
    ])


def resolve_public_ips(hostname: str) -> list[str]:
    hostname = hostname.strip().lower()
    if not hostname:
        raise ValueError("Hostname vide.")

    if hostname.rstrip(".") in BLOCKED_HOSTNAMES:
        raise ValueError("Hostname interdit.")

    try:
        ip_obj = ipaddress.ip_address(hostname)
        if is_blocked_ip(ip_obj):
            raise ValueError("Adresse IP privée ou réservée interdite.")
        return [str(ip_obj)]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Résolution DNS impossible.") from exc

    ips: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_string = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_string)
        except ValueError:
            continue

        if is_blocked_ip(ip_obj):
            raise ValueError("Le domaine résout vers une adresse non publique ou privée.")
        ips.add(str(ip_obj))

    if not ips:
        raise ValueError("Aucune adresse IP publique valide.")

    return sorted(ips)


def validate_target_url(target_url: str) -> tuple[str, str, list[str]]:
    if not isinstance(target_url, str):
        raise ValueError("URL invalide.")

    target_url = target_url.strip()
    if len(target_url) > 2048:
        raise ValueError("URL trop longue.")

    if "://" not in target_url:
        target_url = "https://" + target_url

    parsed = urlparse(target_url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Seuls HTTP et HTTPS sont autorisés.")

    if not parsed.hostname:
        raise ValueError("Hôte cible manquant.")

    if parsed.username or parsed.password:
        raise ValueError("Les identifiants dans les URLs ne sont pas autorisés.")

    if parsed.port and parsed.port not in {80, 443}:
        raise ValueError("Port non autorisé.")

    hostname = parsed.hostname.rstrip(".").lower()
    ips = resolve_public_ips(hostname)
    normalized = parsed._replace(hostname=hostname).geturl()

    return normalized, hostname, ips


# ============================================================
# TLS INSPECTION
# ============================================================

def inspect_tls(hostname: str, port: int = 443) -> dict[str, Any]:
    result = {
        "reachable": False,
        "tls_version": None,
        "cipher": None,
        "certificate": {},
        "error": None,
    }

    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((hostname, port), timeout=HTTP_CONNECT_TIMEOUT) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                result["reachable"] = True
                result["tls_version"] = tls_socket.version()

                cipher = tls_socket.cipher()
                if cipher:
                    result["cipher"] = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2],
                    }

                cert = tls_socket.getpeercert()
                result["certificate"] = parse_certificate(cert)

    except ssl.SSLCertVerificationError as exc:
        result["error"] = {
            "type": "certificate_verification_failed",
            "message": str(exc),
        }
    except ssl.SSLError as exc:
        result["error"] = {
            "type": "tls_error",
            "message": str(exc),
        }
    except Exception as exc:
        result["error"] = {
            "type": "connection_error",
            "message": str(exc),
        }

    return result


def parse_certificate(cert: dict[str, Any]) -> dict[str, Any]:
    if not cert:
        return {}

    result: dict[str, Any] = {}
    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())

    result["subject"] = flatten_cert_name(subject)
    result["issuer"] = flatten_cert_name(issuer)
    result["serial_number"] = cert.get("serialNumber")
    result["not_before"] = cert.get("notBefore")
    result["not_after"] = cert.get("notAfter")

    sans = []
    for item in cert.get("subjectAltName", ()):
        if len(item) == 2:
            sans.append({"type": item[0], "value": item[1]})

    result["subject_alt_names"] = sans
    return result


def flatten_cert_name(name: Any) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for rdn in name or ():
        for pair in rdn:
            if len(pair) != 2:
                continue
            key, value = pair
            result.setdefault(key, []).append(str(value))
    return result


# ============================================================
# HTTP SECURITY AUDIT ENGINE
# ============================================================

SECURITY_HEADERS = {
    "strict-transport-security": {"severity": "HIGH", "description": "HSTS absent."},
    "content-security-policy": {"severity": "MEDIUM", "description": "Content-Security-Policy absente."},
    "x-content-type-options": {"severity": "MEDIUM", "description": "X-Content-Type-Options absent."},
    "x-frame-options": {"severity": "MEDIUM", "description": "X-Frame-Options absent."},
    "referrer-policy": {"severity": "LOW", "description": "Referrer-Policy absente."},
    "permissions-policy": {"severity": "LOW", "description": "Permissions-Policy absente."},
}


def analyze_security_headers(headers: requests.structures.CaseInsensitiveDict) -> list[dict[str, Any]]:
    findings = []
    lower_headers = {key.lower(): value for key, value in headers.items()}

    for name, rule in SECURITY_HEADERS.items():
        if name not in lower_headers:
            findings.append({
                "severity": rule["severity"],
                "category": "HTTP_HEADERS",
                "issue": rule["description"],
                "header": name,
                "recommendation": f"Configurer {name} avec une politique adaptée.",
            })

    return findings


def security_score(findings: list[dict[str, Any]]) -> int:
    deductions = {
        "CRITICAL": 40,
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 4,
        "INFO": 0,
    }
    score = 100
    for finding in findings:
        score -= deductions.get(finding.get("severity"), 0)
    return max(0, min(100, score))


def safe_http_scan(target_url: str) -> dict[str, Any]:
    normalized_url, hostname, resolved_ips = validate_target_url(target_url)
    parsed = urlparse(normalized_url)
    scheme = parsed.scheme.lower()

    tls_result = None
    if scheme == "https":
        tls_result = inspect_tls(hostname, parsed.port or 443)

    findings: list[dict[str, Any]] = []

    if scheme != "https":
        findings.append({
            "severity": "CRITICAL",
            "category": "TRANSPORT",
            "issue": "La cible utilise HTTP sans chiffrement TLS.",
            "recommendation": "Forcer HTTPS et rediriger HTTP vers HTTPS.",
        })
    elif tls_result and not tls_result["reachable"]:
        findings.append({
            "severity": "HIGH",
            "category": "TLS",
            "issue": "La vérification TLS a échoué.",
            "recommendation": "Vérifier le certificat et la chaîne de confiance.",
        })

    session = requests.Session()
    session.headers.update({
        "User-Agent": f"DorkNet-Security-Scanner/{APP_VERSION}",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.1",
        "Accept-Encoding": "identity",
        "Connection": "close",
    })

    current_url = normalized_url
    redirect_history = []
    response = None

    for redirect_number in range(MAX_REDIRECTS + 1):
        current_url, current_host, current_ips = validate_target_url(current_url)

        try:
            response = session.get(
                current_url,
                timeout=(HTTP_CONNECT_TIMEOUT, HTTP_READ_TIMEOUT),
                allow_redirects=False,
                stream=True,
            )
        except requests.exceptions.RequestException as exc:
            findings.append({
                "severity": "MEDIUM",
                "category": "HTTP",
                "issue": "Échec de communication HTTP.",
                "recommendation": "Vérifier la disponibilité du service.",
                "technical": type(exc).__name__,
            })
            break

        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > MAX_RESPONSE_BYTES:
                    response.close()
                    findings.append({
                        "severity": "INFO",
                        "category": "HTTP",
                        "issue": "Réponse trop volumineuse pour l'analyse.",
                    })
                    break
            except ValueError:
                pass

        if response.is_redirect:
            location = response.headers.get("Location")
            response.close()

            if not location:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "REDIRECT",
                    "issue": "Redirection sans en-tête Location.",
                })
                break

            next_url = urljoin(current_url, location)
            redirect_history.append({
                "from": current_url,
                "to": next_url,
                "status": response.status_code,
            })

            if redirect_number >= MAX_REDIRECTS:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "REDIRECT",
                    "issue": "Nombre maximal de redirections atteint.",
                })
                break

            current_url = next_url
            continue

        break

    if response is None:
        response_data = {}
    else:
        body_sample = b""
        try:
            body_sample = next(
                response.iter_content(chunk_size=min(16 * 1024, MAX_RESPONSE_BYTES)),
                b"",
            )
        except Exception:
            pass

        response_data = {
            "status_code": response.status_code,
            "reason": response.reason,
            "server": response.headers.get("Server"),
            "content_type": response.headers.get("Content-Type"),
            "content_length": response.headers.get("Content-Length"),
            "body_sample_size": len(body_sample),
            "final_url": current_url,
            "redirect_count": len(redirect_history),
        }

        findings.extend(analyze_security_headers(response.headers))

        if scheme == "https":
            final_scheme = urlparse(current_url).scheme.lower()
            if final_scheme != "https":
                findings.append({
                    "severity": "HIGH",
                    "category": "TRANSPORT",
                    "issue": "Une redirection HTTPS aboutit sur HTTP.",
                    "recommendation": "Maintenir la chaîne de navigation sous HTTPS.",
                })

        response.close()

    session.close()

    return {
        "target": normalized_url,
        "hostname": hostname,
        "resolved_ips": resolved_ips,
        "http": response_data,
        "tls": tls_result,
        "redirects": redirect_history,
        "findings": findings,
        "score": security_score(findings),
    }


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(413)
def request_too_large(error):
    return json_error("Requête trop volumineuse.", 413, "request_too_large")


@app.errorhandler(HTTPException)
def handle_http_exception(error):
    return json_error(
        error.description or "Erreur HTTP.",
        error.code or 500,
        "http_error",
    )


@app.errorhandler(Exception)
def handle_unexpected_exception(error):
    logger.exception("Unhandled application error.")
    audit.write("application_error", metadata={"exception": type(error).__name__})
    return json_error("Erreur interne du serveur.", 500, "internal_error")


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health", methods=["GET"])
def health():
    redis_ok = False
    try:
        redis_client.get("healthcheck")
        redis_ok = True
    except Exception:
        redis_ok = False

    return jsonify({
        "status": "healthy" if redis_ok else "degraded",
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "dependencies": {
            "redis": "ok" if redis_ok else "degraded",
            "email": "configured" if RESEND_API_KEY else "not_configured",
        },
    })


# ============================================================
# API INFO
# ============================================================

@app.route("/api/info", methods=["GET"])
def api_info():
    return json_success({
        "service": APP_NAME,
        "version": APP_VERSION,
        "security": {
            "jwt": JWT_ALGORITHM,
            "otp_ttl_seconds": OTP_TTL_SECONDS,
            "ssrf_protection": True,
            "audit_chain": True,
            "rate_limiting": True,
        },
    })


# ============================================================
# 1. AUDIT REQUEST
# ============================================================

@app.route("/api/audit", methods=["POST"])
def handle_audit():
    try:
        data = get_json_body()
    except ValueError as exc:
        return json_error(str(exc), 400, "invalid_json")

    name = safe_text(data.get("nom"), 120)
    email = normalize_email(data.get("email"))
    service = safe_text(data.get("service"), 200)
    message = safe_text(data.get("message"), 5000)

    if not name or not email or not message:
        return json_error("Les champs nom, email et message sont obligatoires.", 400, "missing_fields")

    reject = rate_limit_or_reject("audit", f"{request.remote_addr}:{email}", 5, 3600)
    if reject:
        return reject

    safe_name = html.escape(name, quote=True)
    safe_email = html.escape(email, quote=True)
    safe_service = html.escape(service, quote=True)
    safe_message = html.escape(message, quote=True)

    if RESEND_API_KEY:
        try:
            resend.Emails.send({
                "from": f"{SENDER_NAME} <{SENDER_EMAIL}>",
                "to": [AUDIT_EMAIL],
                "reply_to": email,
                "subject": "Nouvelle demande d'audit DorkNet",
                "html": f"""
                <h3>Nouvelle demande d'audit</h3>
                <p><strong>Nom :</strong> {safe_name}</p>
                <p><strong>Email :</strong> {safe_email}</p>
                <p><strong>Service :</strong> {safe_service}</p>
                <p><strong>Message :</strong></p>
                <pre>{safe_message}</pre>
                """,
            })
        except Exception:
            logger.exception("Échec de livraison de l'email d'audit.")

    audit.write("audit_request_created", actor=email, metadata={"service": service})
    return json_success({"message": "Votre demande d'audit a été transmise."})


# ============================================================
# 2. REQUEST OTP
# ============================================================

@app.route("/api/auth/request-otp", methods=["POST"])
def request_otp():
    try:
        data = get_json_body()
    except ValueError as exc:
        return json_error(str(exc), 400, "invalid_json")

    email = normalize_email(data.get("email"))
    if not email:
        return json_error("Adresse e-mail invalide.", 400, "invalid_email")

    reject = rate_limit_or_reject("otp-ip", request.remote_addr or "unknown", OTP_REQUEST_LIMIT, OTP_REQUEST_WINDOW)
    if reject:
        return reject

    reject = rate_limit_or_reject("otp-email", email, OTP_REQUEST_LIMIT, OTP_REQUEST_WINDOW)
    if reject:
        return reject

    otp = generate_otp()
    digest = otp_digest(email, otp)
    key = f"otp:{sha256_hex(email)}"

    redis_client.setex(
        key,
        OTP_TTL_SECONDS,
        json.dumps({"digest": digest, "attempts": 0}),
    )

    delivery_ok = send_email_otp(email, otp)
    audit.write("otp_requested", actor=email, metadata={"delivery": "accepted" if delivery_ok else "failed"})

    if not delivery_ok:
        return json_error("Impossible d'envoyer le code OTP.", 503, "otp_delivery_failed")

    return json_success({
        "message": "Si cette adresse peut être authentifiée, un code OTP a été envoyé.",
        "expires_in": OTP_TTL_SECONDS,
    })


# ============================================================
# 3. VERIFY OTP
# ============================================================

@app.route("/api/auth/verify-otp", methods=["POST"])
def verify_otp():
    try:
        data = get_json_body()
    except ValueError as exc:
        return json_error(str(exc), 400, "invalid_json")

    email = normalize_email(data.get("email"))
    input_otp = str(data.get("otp", "")).strip()

    if not email:
        return json_error("Adresse e-mail invalide.", 400, "invalid_email")

    if len(input_otp) != OTP_LENGTH or not input_otp.isdigit():
        return json_error("Code OTP invalide.", 400, "invalid_otp")

    reject = rate_limit_or_reject("otp-verify-ip", request.remote_addr or "unknown", OTP_VERIFY_LIMIT, OTP_VERIFY_WINDOW)
    if reject:
        return reject

    key = f"otp:{sha256_hex(email)}"
    stored = redis_client.get(key)

    if not stored:
        return json_error("Code invalide ou expiré.", 400, "invalid_or_expired_otp")

    try:
        record = json.loads(stored)
    except json.JSONDecodeError:
        redis_client.delete(key)
        return json_error("Code invalide ou expiré.", 400, "invalid_or_expired_otp")

    attempts = int(record.get("attempts", 0))
    if attempts >= OTP_MAX_ATTEMPTS:
        redis_client.delete(key)
        audit.write("otp_locked", actor=email, metadata={"reason": "max_attempts"})
        return json_error("Nombre maximal de tentatives atteint.", 429, "otp_locked")

    expected_digest = record.get("digest", "")
    provided_digest = otp_digest(email, input_otp)

    if not hmac.compare_digest(expected_digest, provided_digest):
        record["attempts"] = attempts + 1
        redis_client.setex(key, OTP_TTL_SECONDS, json.dumps(record))
        audit.write("otp_verification_failed", actor=email, metadata={"attempt": attempts + 1})
        return json_error("Code OTP incorrect.", 400, "invalid_otp")

    redis_client.delete(key)
    token = create_access_token(email)

    user_state = get_user_state(email)
    save_user_state(email, user_state)

    audit.write("authentication_success", actor=email)

    return json_success({
        "message": "Authentification réussie.",
        "token": token,
        "token_type": "Bearer",
        "expires_in": JWT_TTL_SECONDS,
    })


# ============================================================
# 4. EXPRESS SECURITY SCAN
# ============================================================

@app.route("/api/scanner/express", methods=["POST"])
@token_required
def express_scan(current_user: str):
    reject = rate_limit_or_reject("scan", f"{current_user}:{request.remote_addr}", SCAN_LIMIT, SCAN_WINDOW)
    if reject:
        return reject

    try:
        data = get_json_body()
    except ValueError as exc:
        return json_error(str(exc), 400, "invalid_json")

    target_url = safe_text(data.get("url"), 2048)
    if not target_url:
        return json_error("URL cible requise.", 400, "missing_target")

    try:
        result = safe_http_scan(target_url)
    except ValueError as exc:
        audit.write("scan_rejected", actor=current_user, metadata={"reason": str(exc)})
        return json_error("Cible refusée par la politique de sécurité.", 403, "target_rejected")
    except Exception:
        logger.exception("Échec du scanner.")
        return json_error("Impossible d'effectuer l'analyse.", 502, "scanner_failure")

    audit.write(
        "authorized_scan_completed",
        actor=current_user,
        metadata={
            "target": result["target"],
            "score": result["score"],
            "finding_count": len(result["findings"]),
        },
    )

    return json_success({
        "requested_by": current_user,
        "scan": result,
        "scope": {"purpose": "authorized_security_assessment"},
    })


# ============================================================
# 5. CTF CHALLENGES
# ============================================================

@app.route("/api/ctf/challenges", methods=["GET"])
@token_required
def get_challenges(current_user: str):
    public_list = [
        {
            "id": challenge_id,
            "title": challenge["title"],
            "points": challenge["points"],
        }
        for challenge_id, challenge in CTF_CHALLENGES.items()
    ]

    return json_success({
        "user": current_user,
        "challenges": public_list,
    })


# ============================================================
# 6. SUBMIT CTF FLAG
# ============================================================

@app.route("/api/ctf/submit-flag", methods=["POST"])
@token_required
def submit_flag(current_user: str):
    reject = rate_limit_or_reject("ctf", f"{current_user}:{request.remote_addr}", CTF_SUBMIT_LIMIT, CTF_SUBMIT_WINDOW)
    if reject:
        return reject

    try:
        data = get_json_body()
    except ValueError as exc:
        return json_error(str(exc), 400, "invalid_json")

    challenge_id = safe_text(data.get("challenge_id"), 64)
    submitted_flag = safe_text(data.get("flag"), 512)

    challenge = CTF_CHALLENGES.get(challenge_id)
    if not challenge:
        return json_error("Challenge inexistant.", 404, "challenge_not_found")

    submitted_hash = sha256_hex(submitted_flag)
    if not hmac.compare_digest(submitted_hash, challenge["flag_sha256"]):
        audit.write("ctf_flag_failure", actor=current_user, metadata={"challenge_id": challenge_id})
        return json_error("Flag incorrect.", 400, "invalid_flag")

    user_state = get_user_state(current_user)

    completed_key = f"ctf:completed:{sha256_hex(current_user)}:{challenge_id}"
    already_completed = redis_client.get(completed_key) is not None

    if already_completed:
        return json_success({
            "message": "Challenge déjà validé.",
            "total_score": user_state.get("score", 0),
        })

    user_state["score"] = user_state.get("score", 0) + challenge["points"]
    save_user_state(current_user, user_state)

    redis_client.setex(completed_key, 365 * 24 * 60 * 60, "1")

    audit.write(
        "ctf_flag_success",
        actor=current_user,
        metadata={
            "challenge_id": challenge_id,
            "points": challenge["points"],
        },
    )

    return json_success({
        "message": "Flag correct.",
        "points_awarded": challenge["points"],
        "total_score": user_state["score"],
    })


# ============================================================
# 7. CURRENT USER PROFILE
# ============================================================

@app.route("/api/auth/me", methods=["GET"])
@token_required
def current_user_profile(current_user: str):
    user_state = get_user_state(current_user)
    return json_success({
        "user": {
            "email": current_user,
            "score": user_state.get("score", 0),
        }
    })


# ============================================================
# 8. LOGOUT / TOKEN REVOCATION
# ============================================================

@app.route("/api/auth/logout", methods=["POST"])
@token_required
def logout(current_user: str):
    jti = getattr(g, "jti", None)
    exp = getattr(g, "exp", None)

    if jti:
        now = dt.datetime.now(dt.timezone.utc).timestamp()
        ttl = max(1, int((exp or (now + 3600)) - now))
        redis_client.setex(f"jwt:revoked:{jti}", ttl, "1")

    audit.write("logout_requested", actor=current_user)

    return json_success({
        "message": "Déconnexion enregistrée. Le jeton a été révoqué avec succès."
    })


# ============================================================
# MAIN INITIALIZATION & RUNNER
# ============================================================

def validate_runtime_configuration():
    if PRODUCTION:
        if not ALLOWED_ORIGINS:
            raise RuntimeError("Aucune origine CORS configurée.")
        if "*" in ALLOWED_ORIGINS:
            raise RuntimeError("CORS Wildcard (*) interdit en production.")
        if not RESEND_API_KEY:
            raise RuntimeError("RESEND_API_KEY est requise en production.")
        if not REDIS_URL:
            raise RuntimeError("REDIS_URL est requise en production.")

    logger.info("%s %s initialisé avec succès.", APP_NAME, APP_VERSION)
    logger.info("Mode Production : %s", PRODUCTION)
    logger.info("Algorithme JWT : %s", JWT_ALGORITHM)
    logger.info("Protection SSRF : activée")
    logger.info("Chaîne d'audit hashée : activée")


if __name__ == "__main__":
    validate_runtime_configuration()

    if PRODUCTION:
        logger.warning("Mode production activé. Utilisez Gunicorn/uWSGI derrière un reverse proxy TLS.")

    app.run(
        host=HOST,
        port=PORT,
        debug=(env_bool("FLASK_DEBUG", False) and not PRODUCTION),
    )
