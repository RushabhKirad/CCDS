// Mobile Navigation
const hamburger = document.querySelector('.hamburger');
const navMenu = document.querySelector('.nav-menu');

hamburger.addEventListener('click', () => {
    hamburger.classList.toggle('active');
    navMenu.classList.toggle('active');
});

// Close mobile menu when clicking on a link
document.querySelectorAll('.nav-link').forEach(n => n.addEventListener('click', () => {
    hamburger.classList.remove('active');
    navMenu.classList.remove('active');
}));

// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Password Toggle Function
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const toggle = input.nextElementSibling;
    const icon = toggle.querySelector('i');
    
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

// Password Strength Checker
function checkPasswordStrength(password) {
    let score = 0;
    
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    
    if (score < 3) {
        return { strength: 'weak', message: '🔴 Weak - Add uppercase, numbers, and symbols' };
    } else if (score < 4) {
        return { strength: 'medium', message: '🟡 Medium - Add more character variety' };
    } else if (score < 6) {
        return { strength: 'strong', message: '🟢 Strong - Good password!' };
    } else {
        return { strength: 'very-strong', message: '🔵 Very Strong - Excellent password!' };
    }
}

// Email validation
const allowedEmailProviders = [
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'live.com',
    'icloud.com', 'protonmail.com', 'zoho.com', 'aol.com'
];

function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    if (!emailRegex.test(email)) {
        return { valid: false, message: 'Please enter a valid email address.' };
    }
    
    const domain = email.split('@')[1].toLowerCase();
    
    if (!allowedEmailProviders.includes(domain)) {
        return { valid: false, message: 'Please use a valid email provider (Gmail, Yahoo, Outlook, etc.).' };
    }
    
    return { valid: true };
}

// Authentication Functions
function openLoginModal() {
    document.getElementById('loginModal').classList.remove('hidden');
    document.body.style.overflow = 'hidden';
}

function openSignupModal() {
    document.getElementById('signupModal').classList.remove('hidden');
    document.body.style.overflow = 'hidden';
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.add('hidden');
    document.body.style.overflow = 'auto';
    clearMessages();
    clearFormData(modalId);
}

function clearFormData(modalId) {
    const modal = document.getElementById(modalId);
    const inputs = modal.querySelectorAll('input');
    inputs.forEach(input => input.value = '');
    
    // Clear password strength indicator
    const strengthDiv = document.getElementById('passwordStrength');
    if (strengthDiv) {
        strengthDiv.style.display = 'none';
        strengthDiv.textContent = '';
    }
}

function switchToSignup() {
    closeModal('loginModal');
    openSignupModal();
}

function switchToLogin() {
    closeModal('signupModal');
    openLoginModal();
}

function showMessage(message, type, formId) {
    clearMessages();
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.textContent = message;
    
    const form = document.getElementById(formId);
    form.insertBefore(messageDiv, form.firstChild);
}

function clearMessages() {
    document.querySelectorAll('.message').forEach(msg => msg.remove());
}

let currentUser = JSON.parse(localStorage.getItem('currentUser') || 'null');

// Login Form Handler
async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    const submitBtn = e.target.querySelector('.auth-submit-btn');
    const originalText = submitBtn.textContent;
    
    // Add loading state
    submitBtn.textContent = 'Logging in...';
    submitBtn.disabled = true;
    
    try {
        const response = await fetch('http://localhost:4000/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        
        const result = await response.json();
        
        if (result.success) {
            currentUser = result.user;
            localStorage.setItem('currentUser', JSON.stringify(result.user));
            localStorage.setItem('authToken', result.token);
            showMessage('Login successful! Welcome back.', 'success', 'loginForm');
            
            setTimeout(() => {
                closeModal('loginModal');
                updateAuthUI();
            }, 1500);
        } else {
            showMessage(result.message, 'error', 'loginForm');
        }
    } catch (error) {
        showMessage('Connection error. Please try again.', 'error', 'loginForm');
    } finally {
        // Reset button state
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
    }
}

// Signup Form Handler
async function handleSignup(e) {
    e.preventDefault();
    
    const name = document.getElementById('signupName').value;
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    const confirmPassword = document.getElementById('signupConfirmPassword').value;
    const submitBtn = e.target.querySelector('.auth-submit-btn');
    const originalText = submitBtn.textContent;
    
    // Email validation
    const emailValidation = validateEmail(email);
    if (!emailValidation.valid) {
        showMessage(emailValidation.message, 'error', 'signupForm');
        return;
    }
    
    // Password validation
    if (password !== confirmPassword) {
        showMessage('Passwords do not match.', 'error', 'signupForm');
        return;
    }
    
    const passwordCheck = checkPasswordStrength(password);
    if (passwordCheck.strength === 'weak') {
        showMessage('Password is too weak. Please create a stronger password.', 'error', 'signupForm');
        return;
    }
    
    if (password.length < 6) {
        showMessage('Password must be at least 6 characters.', 'error', 'signupForm');
        return;
    }
    
    // Add loading state
    submitBtn.textContent = 'Creating Account...';
    submitBtn.disabled = true;
    
    try {
        const response = await fetch('http://localhost:4000/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showMessage('Account created successfully! You can now login.', 'success', 'signupForm');
            
            setTimeout(() => {
                closeModal('signupModal');
                openLoginModal();
            }, 1500);
        } else {
            showMessage(result.message, 'error', 'signupForm');
        }
    } catch (error) {
        showMessage('Connection error. Please try again.', 'error', 'signupForm');
    } finally {
        // Reset button state
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
    }
}



// Real-time password strength checking
document.getElementById('signupPassword').addEventListener('input', function() {
    const password = this.value;
    const strengthDiv = document.getElementById('passwordStrength');
    
    if (password.length > 0) {
        const result = checkPasswordStrength(password);
        strengthDiv.className = `password-strength ${result.strength}`;
        strengthDiv.textContent = result.message;
        strengthDiv.style.display = 'block';
    } else {
        strengthDiv.style.display = 'none';
    }
});

// Update Auth UI
function updateAuthUI() {
    const authButtons = document.querySelector('.auth-buttons');
    
    if (currentUser) {
        const firstName = currentUser.name.split(' ')[0];
        authButtons.innerHTML = `
            <span class="user-welcome">Welcome, ${firstName}</span>
            <button class="logout-btn" onclick="logout()">Logout</button>
        `;
    } else {
        authButtons.innerHTML = `
            <button class="login-btn" onclick="openLoginModal()">Login</button>
            <button class="signup-btn" onclick="openSignupModal()">Sign Up</button>
        `;
    }
}

function logout() {
    currentUser = null;
    localStorage.removeItem('currentUser');
    localStorage.removeItem('authToken');
    updateAuthUI();
    showNotification('Logged out successfully!');
}

function showNotification(message) {
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 100px;
        right: 20px;
        background: linear-gradient(45deg, #00ffff, #00ff7f);
        color: #0a0a0a;
        padding: 1rem 2rem;
        border-radius: 25px;
        font-weight: bold;
        z-index: 4000;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Close modals on outside click
document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', function(e) {
        if (e.target === this) {
            closeModal(this.id);
        }
    });
});

// Module Loading Function
function loadModule(moduleName) {
    if (!currentUser) {
        showNotification('Please login to access this module');
        openLoginModal();
        return;
    }
    
    let moduleUrl = '';
    let moduleName_display = '';
    
    switch(moduleName) {
        case 'anomaly':
            moduleUrl = 'http://localhost:8001';
            moduleName_display = 'Anomaly Detection System (Port 8001)';
            break;
        case 'phishing':
            moduleUrl = 'http://localhost:5001';
            moduleName_display = 'Phishing Detection System (Port 5001)';
            break;
        case 'insider':
            moduleUrl = 'http://localhost:5002';
            moduleName_display = 'Insider Threat Detection (Port 5002)';
            break;
        default:
            showNotification('Module not found!');
            return;
    }
    
    showNotification(`Opening ${moduleName_display}...`);
    window.open(moduleUrl, '_blank');
}

// Initialize auth UI on page load
document.addEventListener('DOMContentLoaded', updateAuthUI);

// Sparkle Animation
function createSparkle() {
    const sparkle = document.createElement('div');
    sparkle.className = 'sparkle';
    sparkle.style.left = Math.random() * 100 + '%';
    sparkle.style.animationDelay = Math.random() * 3 + 's';
    document.querySelector('.sparkles').appendChild(sparkle);
    
    setTimeout(() => {
        sparkle.remove();
    }, 2500);
}

setInterval(createSparkle, 150);