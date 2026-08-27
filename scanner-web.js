/* ===========================================================================
   VulnShield - Frontend Web Scanner Wrapper (API Integration)
   =========================================================================== */

/**
 * Frontend wrapper that forwards web scan requests to the backend API.
 * The backend performs real DNS lookups and security header audits.
 * This module mirrors the previous interface (`scan(domain, logCallback)`) so
 * existing UI code does not need to change.
 */
const WebScanner = {
    /**
     * Strips protocol, www prefix, and path — returns a clean hostname
     * or null if the input looks invalid.
     * @param {string} input - Raw user input (URL or domain).
     * @returns {string|null} - Cleaned hostname, or null if invalid.
     */
    sanitizeDomain: function (input) {
        if (!input) return null;
        let clean = input.trim().toLowerCase();
        // Strip protocol and www
        clean = clean.replace(/^(https?:\/\/)?(www\.)?/, '');
        // Take only the hostname part (strip path/query/hash)
        clean = clean.split('/')[0].split('?')[0].split('#')[0];
        // Basic domain format validation
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
        return domainRegex.test(clean) ? clean : null;
    },

    /**
     * Initiates a scan for a given domain.
     * @param {string} domain - The target domain (e.g., "example.com").
     * @param {function} logCallback - Function to receive log strings for UI rendering.
     * @returns {Promise<Array>} - Resolves to an array of finding objects.
     */
    scan: async function (domain, logCallback) {
        logCallback(`[SYSTEM] Initiating server‑side scan for: ${domain}`);
        try {
            const token = sessionStorage.getItem('vulnshield_token');
            const response = await fetch('/api/scan/web', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': token ? `Bearer ${token}` : '' },
                body: JSON.stringify({ domain })
            });
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Server error');
            }
            const data = await response.json();
            // Replay backend logs for UI consistency
            if (Array.isArray(data.logs)) {
                data.logs.forEach(l => logCallback(l));
            }
            return data.findings;
        } catch (e) {
            logCallback(`[ERROR] Scan failed: ${e.message}`);
            throw e;
        }
    }
};
