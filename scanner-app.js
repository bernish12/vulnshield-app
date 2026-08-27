/* ===========================================================================
   VulnShield - Frontend App Scanner Wrapper (API Integration)
   =========================================================================== */

/**
 * Frontend wrapper that forwards app scan requests to the backend API.
 * The backend replicates the same static analysis logic as the previous client-side
 * implementation, ensuring a single source of truth and allowing server-side logging.
 */
const AppScanner = {
    /**
     * Submits the file for analysis to the backend.
     * @param {string} filename - Name of the uploaded file.
     * @param {string} content - File content as a string.
     * @returns {Promise<Array>} - Resolves to an array of finding objects.
     */
    scan: async function (filename, content) {
        try {
            const token = sessionStorage.getItem('vulnshield_token');
            const response = await fetch('/api/scan/app', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': token ? `Bearer ${token}` : '' },
                body: JSON.stringify({ filename, content })
            });
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Server error');
            }
            const data = await response.json();
            return data.findings || [];
        } catch (e) {
            console.error('App scan failed:', e);
            throw e;
        }
    }
};

// Export for possible external use (e.g., testing)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AppScanner;
}
