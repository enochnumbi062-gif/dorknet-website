/**
 * DorkNet Security - Script Frontend Unifié & Durci (Zero Trust & Matrix Rain)
 */

document.addEventListener('DOMContentLoaded', () => {

    // --- 1. GESTION DU MENU MOBILE SIDEBAR ---
    const mobileMenu = document.getElementById('mobileMenu');
    const navLinks = document.getElementById('navLinks');
    const menuIcon = mobileMenu ? mobileMenu.querySelector('i') : null;

    if (mobileMenu && navLinks && menuIcon) {
        mobileMenu.addEventListener('click', () => {
            const isActive = navLinks.classList.toggle('active');
            menuIcon.classList.toggle('fa-bars', !isActive);
            menuIcon.classList.toggle('fa-xmark', isActive);
        });

        document.querySelectorAll('.nav-links a').forEach(link => {
            link.addEventListener('click', () => {
                navLinks.classList.remove('active');
                if (menuIcon) {
                    menuIcon.classList.remove('fa-xmark');
                    menuIcon.classList.add('fa-bars');
                }
            });
        });
    }

    // --- 2. INDICATEUR DE SECTION ACTIVE (IntersectionObserver) ---
    const sections = document.querySelectorAll('section');
    const navItems = document.querySelectorAll('.nav-links a');

    if ('IntersectionObserver' in window && sections.length > 0) {
        const observerOptions = {
            root: null,
            rootMargin: '-20% 0px -70% 0px',
            threshold: 0
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const id = entry.target.getAttribute('id');
                    navItems.forEach(item => {
                        const href = item.getAttribute('href');
                        item.classList.toggle('active', href === `#${id}`);
                    });
                }
            });
        }, observerOptions);

        sections.forEach(section => observer.observe(section));
    }

    // --- 3. FERMETURE UNIVERSELLE DES MODALES (CLIC EXTÉRIEUR ET TOUCHE ESC) ---
    const modals = document.querySelectorAll('.info-modal, .agata-modal, #authModal');
    
    window.addEventListener('click', (e) => {
        modals.forEach(modal => {
            if (e.target === modal) {
                modal.style.display = 'none';
            }
        });
    });

    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            modals.forEach(modal => {
                modal.style.display = 'none';
            });
            const chatPanel = document.getElementById('chatPanel');
            if (chatPanel) chatPanel.style.display = 'none';
        }
    });

    // --- 4. ANIMATION CANVAS MATRIX RAIN & LOADER ---
    const canvas = document.getElementById('matrix-canvas');
    if (canvas) {
        const ctx = canvas.getContext('2d');
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$#@%&*アイウエオカキクケコサシスセソタチツテト";
        const fontSize = 14;
        let columns = 0;
        let drops = [];

        function resizeCanvas() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            columns = Math.floor(canvas.width / fontSize);
            drops = Array(columns).fill(1);
        }

        resizeCanvas();
        window.addEventListener('resize', resizeCanvas);

        function drawMatrix() {
            ctx.fillStyle = "rgba(9, 13, 22, 0.08)";
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.font = `${fontSize}px 'JetBrains Mono', monospace`;

            for (let i = 0; i < drops.length; i++) {
                const text = chars.charAt(Math.floor(Math.random() * chars.length));
                
                if (Math.random() > 0.85) {
                    ctx.fillStyle = "#22d3ee";
                } else {
                    ctx.fillStyle = "rgba(6, 182, 212, 0.7)";
                }

                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
            requestAnimationFrame(drawMatrix);
        }

        drawMatrix();
    }

    // --- 5. PROGRESSION DU CHARGEMENT EN POURCENTAGE ---
    const percentElement = document.getElementById('loader-percent');
    if (percentElement) {
        let progress = 0;
        const interval = setInterval(() => {
            progress += 1;
            percentElement.innerText = `${progress}%`;
            if (progress >= 100) clearInterval(interval);
        }, 50);
    }

    // --- 9. INTERCEPTION DES FORMULAIRES & AUTHENTIFICATION OTP ---
    const registerForm = document.getElementById('registerForm');
    const loginForm = document.getElementById('loginForm');

    // Traitement du formulaire d'inscription / Connexion (Demande d'OTP)
    const handleAuthSubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
        const emailInput = form.querySelector('input[type="email"]');
        const submitBtn = form.querySelector('button[type="submit"]');

        if (!emailInput || !emailInput.value) {
            alert("Veuillez saisir une adresse e-mail valide.");
            return;
        }

        const email = emailInput.value.trim();
        const originalBtnText = submitBtn ? submitBtn.innerText : '';

        try {
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerText = "Envoi du code OTP...";
            }

            // Étape 1 : Demande du code OTP au backend Flask
            const response = await fetch('/api/auth/request-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });

            const result = await response.json();

            if (response.ok && result.success) {
                // Étape 2 : Saisie du code OTP par l'utilisateur
                const userOtp = prompt(`Un code de validation a été envoyé à : ${email}\nVeuillez saisir votre code à 6 chiffres :`);

                if (!userOtp) {
                    alert("Validation annulée.");
                    return;
                }

                // Étape 3 : Vérification du code OTP auprès du backend
                const verifyResponse = await fetch('/api/auth/verify-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, otp: userOtp.trim() })
                });

                const verifyResult = await verifyResponse.json();

                if (verifyResponse.ok && verifyResult.success) {
                    // Stockage du jeton JWT dans le navigateur
                    localStorage.setItem('token', verifyResult.token);
                    alert("Authentification réussie ! Bienvenue sur DorkNet.");
                    closeAuthModal();
                    window.location.reload();
                } else {
                    alert(`Erreur : ${verifyResult.error || 'Code OTP incorrect.'}`);
                }
            } else {
                alert(`Erreur : ${result.error || 'Échec de l\'envoi du code OTP.'}`);
            }
        } catch (err) {
            console.error("Erreur d'authentification :", err);
            alert("Impossible de contacter le serveur d'authentification.");
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerText = originalBtnText;
            }
        }
    };

    if (registerForm) registerForm.addEventListener('submit', handleAuthSubmit);
    if (loginForm) loginForm.addEventListener('submit', handleAuthSubmit);
});

// --- 6. SÉCURITÉ & SANITIZATION XSS ---
function sanitizeHTML(str) {
    const temp = document.createElement('div');
    temp.textContent = str;
    return temp.innerHTML;
}

// --- 7. CLIENT API ET GESTION DES JETONS DE SÉCURITÉ ---
function getAuthHeaders() {
    const token = localStorage.getItem('token');
    return {
        'Content-Type': 'application/json',
        'Authorization': token ? `Bearer ${token}` : ''
    };
}

// --- 8. FONCTIONS GLOBALES POUR LA MODALE D'AUTHENTIFICATION ---
function openAuthModal(mode) {
    const modal = document.getElementById('authModal');
    if (modal) {
        modal.style.display = 'flex';
        switchAuthTab(mode);
    }
}

function closeAuthModal() {
    const modal = document.getElementById('authModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function switchAuthTab(mode) {
    const regForm = document.getElementById('registerForm');
    const loginForm = document.getElementById('loginForm');
    const title = document.getElementById('authModalTitle');

    if (regForm && loginForm && title) {
        if (mode === 'register') {
            regForm.style.display = 'flex';
            loginForm.style.display = 'none';
            title.innerText = "Créer un compte DorkNet";
        } else {
            regForm.style.display = 'none';
            loginForm.style.display = 'flex';
            title.innerText = "Connexion DorkNet";
        }
    }
}
