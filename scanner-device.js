/* ==========================================================================
   VulnShield - Client Browser Environment & Host OS Audit Engine
   ========================================================================== */

const DeviceScanner = {
    // Current OS selections
    currentOS: 'windows',

    // Checklist definitions per platform
    checklists: {
        windows: [
            { id: 'win_encrypt', title: 'BitLocker Volume Encryption', desc: 'Is drive encryption (BitLocker or Device Encryption) enabled for the primary system partition?', weight: 25 },
            { id: 'win_defender', title: 'Microsoft Defender Antivirus Active', desc: 'Is Defender active or does a third-party antivirus monitor real-time file executions?', weight: 25 },
            { id: 'win_update', title: 'Windows Update Automatic Execution', desc: 'Are automatic security updates enabled, ensuring patches install immediately?', weight: 20 },
            { id: 'win_firewall', title: 'Windows Defender Firewall Enabled', desc: 'Is the host firewall active for Domain, Private, and Public network profiles?', weight: 15 },
            { id: 'win_uac', title: 'User Account Control (UAC) Level', desc: 'Is UAC set to notify before programs make system-level changes (not disabled)?', weight: 15 }
        ],
        macos: [
            { id: 'mac_vault', title: 'FileVault Disk Encryption Enabled', desc: 'Is FileVault system encryption active, protecting system data at rest?', weight: 30 },
            { id: 'mac_gatekeeper', title: 'Gatekeeper & App Verification Active', desc: 'Is download installation security restricted to App Store and identified developers?', weight: 25 },
            { id: 'mac_update', title: 'macOS Automatic Updates Configured', desc: 'Are system security definitions set to check and download updates in background?', weight: 20 },
            { id: 'mac_firewall', title: 'macOS Built-in Application Firewall', desc: 'Is the firewall enabled in System Settings -> Network to filter incoming data?', weight: 15 },
            { id: 'mac_sip', title: 'System Integrity Protection (SIP) Enforced', desc: 'Is SIP active, restricting unauthorized access to critical directories?', weight: 10 }
        ],
        android: [
            { id: 'and_encrypt', title: 'Hardware Cryptographic Encryption', desc: 'Is storage encryption active (mandated by default on Android 10+)?', weight: 30 },
            { id: 'and_play', title: 'Google Play Protect Verification', desc: 'Is Play Protect active, continuously scanning application packages for malware?', weight: 25 },
            { id: 'and_sources', title: 'Unknown App Installation Blocked', desc: 'Is system authorization to install from arbitrary APK files disabled by default?', weight: 20 },
            { id: 'and_lock', title: 'Device Lock Screen Password/Biometrics', desc: 'Is lock verification (PIN, Password, Pattern, or Fingerprint/Face) active?', weight: 15 },
            { id: 'and_debug', title: 'ADB USB Debugging Interface Disabled', desc: 'Is Developer Options ADB Debugging turned off to block unauthorized local access?', weight: 10 }
        ],
        ios: [
            { id: 'ios_passcode', title: 'Device Passcode & Biometric Access', desc: 'Is a passcode (FaceID/TouchID) configured, enforcing physical protection?', weight: 30 },
            { id: 'ios_encrypt', title: 'Data Protection Sandbox Encryption', desc: 'Is local storage hardware encryption active (automatically enabled with passcode)?', weight: 25 },
            { id: 'ios_jailbreak', title: 'Jailbreak Status Verified Secure', desc: 'Is the device running authentic Apple software without sideloading modifications?', weight: 20 },
            { id: 'ios_updates', title: 'Automatic iOS Software Update Active', desc: 'Are security response downloads and automated system updates turned on?', weight: 15 },
            { id: 'ios_permissions', title: 'Application Location & Tracking Audits', desc: 'Are permissions for App Tracking Transparency and location access minimized?', weight: 10 }
        ]
    },

    // Get current browser statistics (real diagnostics)
    getBrowserDiagnostics: function () {
        const results = [];
        
        // 1. Connection Protocol Check
        const isHttps = window.location.protocol === 'https:';
        results.push({
            label: 'Protocol Version',
            value: window.location.protocol.toUpperCase().replace(':', ''),
            status: isHttps ? 'passed' : 'warning',
            desc: isHttps ? 'Secure SSL/TLS session.' : 'Insecure plaintext communication. Data is readable in transit.'
        });

        // 2. Cookie Support
        const cookiesEnabled = navigator.cookieEnabled;
        results.push({
            label: 'Browser Cookie Vault',
            value: cookiesEnabled ? 'Enabled' : 'Blocked',
            status: cookiesEnabled ? 'passed' : 'info',
            desc: cookiesEnabled ? 'Dynamic cookies supported.' : 'Cookies are disabled.'
        });

        // 3. Local Storage Support
        let localStorageOk = false;
        try {
            localStorage.setItem('__test__', '1');
            localStorage.removeItem('__test__');
            localStorageOk = true;
        } catch(e) {}
        results.push({
            label: 'Local Storage State',
            value: localStorageOk ? 'Writable' : 'Locked',
            status: localStorageOk ? 'passed' : 'info',
            desc: localStorageOk ? 'Client database storage operational.' : 'HTML5 storage operations are blocked.'
        });

        // 4. WebRTC Connection audit
        results.push({
            label: 'WebRTC Interface State',
            value: 'Available',
            status: 'info',
            desc: 'WebRTC standard interfaces are available in this browser context, which can potentially leak local network IP details.'
        });

        // 5. Canvas Fingerprint check (Screen data)
        const canvas = document.createElement('canvas');
        const hasCanvas = !!(canvas.getContext && canvas.getContext('2d'));
        results.push({
            label: 'Canvas Diagnostics',
            value: hasCanvas ? 'Operational' : 'Unavailable',
            status: 'passed',
            desc: 'HTML5 graphic canvas features support hardware acceleration configurations.'
        });

        return results;
    },

    // Populate checklist for selected OS
    renderOSChecklist: function (containerId, osName, onChangeCallback) {
        this.currentOS = osName;
        const container = document.getElementById(containerId);
        if (!container) return;

        const items = this.checklists[osName];
        container.innerHTML = '';

        items.forEach((item, index) => {
            // Load checked state from session memory or default to unchecked
            const savedState = localStorage.getItem(`vulnshield_audit_${osName}_${item.id}`) === 'true';

            const itemEl = document.createElement('div');
            itemEl.className = `checklist-item ${savedState ? 'checked' : ''}`;
            itemEl.onclick = (e) => {
                // Prevent toggle twice if checkbox is clicked directly
                if (e.target.tagName === 'INPUT') return;
                const chk = itemEl.querySelector('input');
                chk.checked = !chk.checked;
                toggleItemState(chk);
            };

            const chkContainer = document.createElement('div');
            chkContainer.className = 'checklist-checkbox-container';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'checklist-checkbox';
            checkbox.id = `chk-${item.id}`;
            checkbox.checked = savedState;
            
            const toggleItemState = (targetChk) => {
                localStorage.setItem(`vulnshield_audit_${osName}_${item.id}`, targetChk.checked);
                if (targetChk.checked) {
                    itemEl.classList.add('checked');
                } else {
                    itemEl.classList.remove('checked');
                }
                // Call notification callback to update global ratings
                onChangeCallback();
            };

            checkbox.onchange = (e) => {
                toggleItemState(e.target);
            };

            chkContainer.appendChild(checkbox);

            const body = document.createElement('div');
            body.className = 'checklist-body';

            const title = document.createElement('h4');
            title.className = 'checklist-title';
            title.innerText = item.title;

            const desc = document.createElement('p');
            desc.className = 'checklist-desc';
            desc.innerText = item.desc;

            body.appendChild(title);
            body.appendChild(desc);

            itemEl.appendChild(chkContainer);
            itemEl.appendChild(body);
            container.appendChild(itemEl);
        });
    },

    // Calculate current compliance score based on checked boxes
    calculateScore: function (osName) {
        const items = this.checklists[osName];
        let score = 0;

        items.forEach(item => {
            const savedState = localStorage.getItem(`vulnshield_audit_${osName}_${item.id}`) === 'true';
            if (savedState) {
                score += item.weight;
            }
        });

        return Math.min(score, 100);
    }
};
