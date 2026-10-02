/**
 * DorkNet Security - Script Frontend Unifié & Durci (Zero Trust)
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

    // --- 3. FERMETURE UNIVERSELLE DES MODALES ---
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

    // --- 4. ANIMATION CANVAS MATRIX RAIN ---
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
            ctx.fillStyle = "rgba(13, 17, 23, 0.08)";
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.font = `${fontSize}px 'JetBrains Mono', monospace`;

            for (let i = 0; i < drops.length; i++) {
                const text = chars.charAt(Math.floor(Math.random() * chars.length));
                
                if (Math.random() > 0.85) {
                    ctx.fillStyle = "#00f2fe";
                } else {
                    ctx.fillStyle = "rgba(0, 242, 254, 0.5)";
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

    // --- 5. PROGRESSION DU CHARGEMENT ---
    const percentElement = document.getElementById('loader-percent');
    const loaderBar = document.getElementById('loader-bar');
    const loader = document.getElementById('cyber-loader');

    if (percentElement && loaderBar && loader) {
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.floor(Math.random() * 8) + 2;
            if (progress >= 100) {
                progress = 100;
                clearInterval(interval);
                setTimeout(() => {
                    loader.style.opacity = '0';
                    loader.style.visibility = 'hidden';
                }, 400);
            }
            loaderBar.style.width = `${progress}%`;
            percentElement.innerText = `${progress}%`;
        }, 50);
    }

    // --- 6. GESTION DES FORMULAIRES D'AUTHENTIFICATION ---
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = registerForm.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn ? submitBtn.innerText : '';

            const payload = {
                nom: document.getElementById('regName')?.value || '',
                email: document.getElementById('regEmail')?.value || '',
                password: document.getElementById('regPassword')?.value || ''
            };

            if (!payload.email || !payload.password || !payload.nom) {
                alert("Veuillez remplir tous les champs obligatoires.");
                return;
            }

            try {
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.innerText = "Création du compte...";
                }

                const response = await fetch('/api/auth/register-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    alert("Inscription réussie ! Un code d'activation a été envoyé à votre adresse e-mail.");
                    switchAuthTab('login');
                } else {
                    alert(`Erreur : ${result.error || 'Échec de l\'inscription.'}`);
                }
            } catch (err) {
                console.error("Erreur Inscription :", err);
                alert("Erreur de connexion au serveur d'authentification.");
            } finally {
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerText = originalBtnText;
                }
            }
        });
    }

    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = loginForm.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn ? submitBtn.innerText : '';

            const payload = {
                email: document.getElementById('loginEmail')?.value || '',
                password: document.getElementById('loginPassword')?.value || ''
            };

            if (!payload.email || !payload.password) {
                alert("Veuillez saisir votre e-mail et votre mot de passe.");
                return;
            }

            try {
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.innerText = "Connexion...";
                }

                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const result = await response.json();

                if (response.ok && result.success && result.token) {
                    localStorage.setItem('token', result.token);
                    alert(`Authentification réussie ! Bienvenue ${result.user?.nom || 'sur DorkNet'}.`);
                    closeAuthModal();
                    window.location.reload();
                } else {
                    alert(`Erreur : ${result.error || 'Identifiants invalides.'}`);
                }
            } catch (err) {
                console.error("Erreur Connexion :", err);
                alert("Impossible de contacter le serveur d'authentification.");
            } finally {
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerText = originalBtnText;
                }
            }
        });
    }
});

// --- 7. SÉCURITÉ & SANITIZATION XSS ---
function sanitizeHTML(str) {
    const temp = document.createElement('div');
    temp.textContent = str;
    return temp.innerHTML;
}

// --- 8. CLIENT API ET GESTION DES JETONS DE SÉCURITÉ ---
function getAuthHeaders() {
    const token = localStorage.getItem('token');
    return {
        'Content-Type': 'application/json',
        'Authorization': token ? `Bearer ${token}` : ''
    };
}

// --- 9. FONCTIONS GLOBALES POUR LA MODALE D'AUTHENTIFICATION ---
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
