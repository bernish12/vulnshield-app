(async function () {
    const rawPath = window.location.pathname.toLowerCase();
    const isLoginPage = rawPath.endsWith('login.html') || rawPath.endsWith('/login') || rawPath === '/login';

    // Clear legacy localStorage token if present so old persistent logins don't bypass tab isolation
    localStorage.removeItem('vulnshield_token');

    // Handle cross-tab storage changes (logging out on another tab)
    window.addEventListener('storage', (e) => {
        if (e.key === 'vulnshield_token') {
            if (!e.newValue && !isLoginPage) {
                window.location.href = '/login.html';
            }
        }
    });

    // Expose global Logout function
    window.logout = function () {
        localStorage.removeItem('vulnshield_token');
        sessionStorage.removeItem('vulnshield_token');
        window.location.href = '/login.html';
    };

    const token = sessionStorage.getItem('vulnshield_token');

    if (isLoginPage) {
        // On login page: if token exists in this tab, verify and redirect to main app if valid
        if (token) {
            try {
                const resp = await fetch('/api/verify', {
                    method: 'GET',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (resp.ok) {
                    window.location.href = '/index.html';
                } else {
                    sessionStorage.removeItem('vulnshield_token');
                }
            } catch (e) {
                console.warn('[VulnShield] Login page token check network error:', e.message);
            }
        }
        return;
    }

    // On protected page: no token stored -> go to login immediately
    if (!token) {
        window.location.href = '/login.html';
        return;
    }

    // Validate token with server
    async function checkToken() {
        if (!token) return;
        try {
            const resp = await fetch('/api/verify', {
                method: 'GET',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!resp.ok) {
                // Token rejected — clear it and redirect to login
                sessionStorage.removeItem('vulnshield_token');
                window.location.href = '/login.html';
            }
        } catch (e) {
            console.warn('[VulnShield] Token verification failed due to network error:', e.message);
        }
    }

    // Run validation immediately and then check every 5 seconds
    await checkToken();
    setInterval(checkToken, 5000);
})();
