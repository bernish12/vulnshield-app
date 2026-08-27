/* ===========================================================================
   VulnShield - Frontend OWASP Top 10 Scanner Wrapper (API Integration)
   =========================================================================== */

/**
 * Frontend wrapper that forwards OWASP web-app scan requests to the backend
 * API.  The backend performs passive HTTP analysis against 10 OWASP categories.
 * This module keeps the same interface shape as WebScanner / AppScanner so
 * existing UI helpers (renderFindings, filters, etc.) work unchanged.
 */
const OwaspScanner = {

    /**
     * Basic URL validation & normalisation.
     * Returns the cleaned URL string or null if invalid.
     */
    sanitizeUrl: function (input) {
        if (!input) return null;
        let url = input.trim();

        // Prepend https:// if the user typed just a domain
        if (!/^https?:\/\//i.test(url)) {
            url = 'https://' + url;
        }

        try {
            const parsed = new URL(url);
            // Only allow http / https schemes
            if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
            return parsed.href;
        } catch (_) {
            return null;
        }
    },

    /**
     * Initiates a full OWASP Top 10 scan for a given URL.
     * @param {string} targetUrl - The full target URL.
     * @param {function} logCallback - Receives log strings for terminal UI.
     * @returns {Promise<Array>} - Array of finding objects.
     */
    scan: async function (targetUrl, logCallback) {
        logCallback(`[SYSTEM] Initiating OWASP Top 10 analysis for: ${targetUrl}`);
        try {
            const token = sessionStorage.getItem('vulnshield_token');
            const response = await fetch('/api/scan/owasp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': token ? `Bearer ${token}` : ''
                },
                body: JSON.stringify({ url: targetUrl })
            });
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Server error');
            }
            const data = await response.json();
            // Replay backend logs into the terminal panel
            if (Array.isArray(data.logs)) {
                data.logs.forEach(l => logCallback(l));
            }
            return data.findings;
        } catch (e) {
            logCallback(`[ERROR] OWASP scan failed: ${e.message}`);
            throw e;
        }
    }
};
