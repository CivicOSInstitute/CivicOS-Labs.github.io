/**
 * CivicOS Labs — Publishing Auth
 * 
 * Client-side authentication for curriculum access.
 * Credentials are SHA-256 hashed — never stored in plain text.
 * Session uses sessionStorage (cleared on tab close).
 * 
 * To generate new password hashes:
 *   In browser console: sha256('your-password').then(h => console.log(h))
 */

// --- Configuration ---
// SHA-256 hashes of username and password.
// Default credentials set by admin; change these via the hash generator below.

const AUTH_CONFIG = {
    // Hashed username (default: "civicos")
    USER_HASH: "2a96f9a78be0c8bb728431d148cf2c8edfe617237b8d72d0ccac55b31d053d51",
    // Hashed password (default: set below)
    PASS_HASH: "faf3529fece1b1dd55ef39153f7889a0f484ff7ebbf3594ad089610959476bc9",
    // Session duration in ms (8 hours)
    SESSION_DURATION: 8 * 60 * 60 * 1000,
    // Session key
    SESSION_KEY: 'civicos_pub_auth'
};

// --- Real hashes will be set on first deploy ---
// This file gets patched with actual hashes during setup.

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function handleLogin(event) {
    event.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const errorEl = document.getElementById('loginError');
    const btn = document.getElementById('loginBtn');

    errorEl.classList.remove('visible');
    btn.disabled = true;
    btn.textContent = 'Verifying…';

    try {
        const [userHash, passHash] = await Promise.all([
            sha256(username),
            sha256(password)
        ]);

        if (userHash === AUTH_CONFIG.USER_HASH && passHash === AUTH_CONFIG.PASS_HASH) {
            // Auth success — create session
            const session = {
                user: username,
                ts: Date.now(),
                token: crypto.randomUUID()
            };
            sessionStorage.setItem(AUTH_CONFIG.SESSION_KEY, JSON.stringify(session));
            // Redirect to dashboard
            window.location.replace('/publishing/');
        } else {
            // Auth failure
            errorEl.classList.add('visible');
            btn.disabled = false;
            btn.textContent = 'Authenticate →';
        }
    } catch (err) {
        errorEl.textContent = 'Authentication error. Please try again.';
        errorEl.classList.add('visible');
        btn.disabled = false;
        btn.textContent = 'Authenticate →';
    }

    return false;
}

function isAuthenticated() {
    try {
        const raw = sessionStorage.getItem(AUTH_CONFIG.SESSION_KEY);
        if (!raw) return false;
        const session = JSON.parse(raw);
        if (!session.ts || !session.token) return false;
        // Check session expiry
        if (Date.now() - session.ts > AUTH_CONFIG.SESSION_DURATION) {
            sessionStorage.removeItem(AUTH_CONFIG.SESSION_KEY);
            return false;
        }
        return true;
    } catch {
        return false;
    }
}

function logout() {
    sessionStorage.removeItem(AUTH_CONFIG.SESSION_KEY);
    window.location.replace('/publishing/login/');
}

// Hash generator utility (run in console to create new credentials)
// Usage: generateHash('my-username') or generateHash('my-password')
async function generateHash(input) {
    const hash = await sha256(input);
    console.log(`SHA-256("${input}") = ${hash}`);
    return hash;
}
