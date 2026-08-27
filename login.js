// login.js - Handles authentication for BernishVuln_Shield
async function performLogin(e) {
    if (e) e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const errorMsg = document.getElementById('errorMsg');
    const loginBtn = document.getElementById('loginBtn');
    
    errorMsg.textContent = '';

    if (!username || !password) {
        errorMsg.textContent = 'Please enter both username and password.';
        return;
    }

    if (loginBtn) {
        loginBtn.disabled = true;
        loginBtn.textContent = 'Authenticating...';
    }
    
    try {
        const resp = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await resp.json();
        if (resp.ok && data.success) {
            // Save token in sessionStorage so each tab requires authentication
            sessionStorage.setItem('vulnshield_token', data.token);
            // Redirect to dashboard
            window.location.href = '/index.html';
        } else {
            errorMsg.textContent = data.error || 'Invalid username or password.';
            if (loginBtn) {
                loginBtn.disabled = false;
                loginBtn.textContent = 'Login';
            }
        }
    } catch (e) {
        console.error('Login error:', e);
        errorMsg.textContent = 'Network error. Please try again.';
        if (loginBtn) {
            loginBtn.disabled = false;
            loginBtn.textContent = 'Login';
        }
    }
}

const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', performLogin);
} else {
    document.getElementById('loginBtn').addEventListener('click', performLogin);
}
