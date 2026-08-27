/* ==========================================================================
   VulnShield - Integrated Security Reporting & Executive PDF Compilation Engine
   ========================================================================== */

const ReportGenerator = {
    calculateGrade: function (score) {
        if (score === null || score === undefined) return { grade: 'N/A', label: 'UNAUDITED', color: '#a8b2d1' };
        if (score >= 95) return { grade: 'A+', label: 'EXCELLENT POSTURE', color: '#00e676' };
        if (score >= 90) return { grade: 'A', label: 'STRONG POSTURE', color: '#64ffda' };
        if (score >= 80) return { grade: 'B', label: 'GOOD POSTURE', color: '#82aaff' };
        if (score >= 70) return { grade: 'C', label: 'ATTENTION NEEDED', color: '#ffd700' };
        if (score >= 60) return { grade: 'D', label: 'ELEVATED RISK', color: '#ff9100' };
        return { grade: 'F', label: 'CRITICAL RISK', color: '#ff5252' };
    },

    getRemediation: function (findingTitle, severity) {
        const titleLower = (findingTitle || '').toLowerCase();
        if (titleLower.includes('ssl') || titleLower.includes('tls') || titleLower.includes('https')) {
            return 'Enforce HTTPS redirect and configure TLS 1.3 with strong cipher suites. Install valid SSL certificate via Let\'s Encrypt.';
        }
        if (titleLower.includes('csp') || titleLower.includes('content security policy')) {
            return 'Implement a strict Content-Security-Policy header (default-src \'self\') to mitigate XSS and unauthorized data injection.';
        }
        if (titleLower.includes('xss') || titleLower.includes('cross-site scripting')) {
            return 'Sanitize all user-controlled input on server & client side using DOMPurify and encode HTML output parameters.';
        }
        if (titleLower.includes('bitlocker') || titleLower.includes('encryption')) {
            return 'Enable BitLocker Volume Encryption via Control Panel or PowerShell (Enable-BitLocker -MountPoint "C:").';
        }
        if (titleLower.includes('antivirus') || titleLower.includes('defender')) {
            return 'Ensure Microsoft Defender / Real-time Protection is active in Windows Security settings.';
        }
        if (titleLower.includes('secret') || titleLower.includes('api key') || titleLower.includes('credential')) {
            return 'Revoke exposed API keys immediately. Store secrets in environment variables or cloud secret managers (AWS Secrets Manager / Vault).';
        }
        if (titleLower.includes('hsts') || titleLower.includes('strict-transport')) {
            return 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header to all web responses.';
        }
        if (severity === 'high') {
            return 'Immediate remediation required: Apply security patch, enforce access control policies, and re-audit.';
        }
        if (severity === 'warning' || severity === 'medium') {
            return 'Review configuration parameters and apply recommended security hardening guidelines.';
        }
        return 'Control parameter is verified active. Maintain current security baseline.';
    },

    // Generate full summary data structure
    compileReport: function () {
        const state = {
            timestamp: new Date().toISOString(),
            webScan: this.getSavedWebScan(),
            appScan: this.getSavedAppScan(),
            owaspScan: this.getSavedOwaspScan(),
            deviceAudit: this.getSavedDeviceAudit(),
            summary: {
                high: 0,
                medium: 0,
                low: 0,
                passed: 0,
                totalScore: 0
            }
        };

        // Calculate counts
        if (state.webScan && state.webScan.findings) {
            state.webScan.findings.forEach(f => {
                if (f.severity === 'high' || f.severity === 'critical') state.summary.high++;
                else if (f.severity === 'warning') state.summary.medium++;
                else if (f.severity === 'info') state.summary.low++;
                else if (f.severity === 'passed') state.summary.passed++;
            });
        }

        if (state.appScan && state.appScan.findings) {
            state.appScan.findings.forEach(f => {
                if (f.severity === 'high' || f.severity === 'critical') state.summary.high++;
                else if (f.severity === 'warning') state.summary.medium++;
                else if (f.severity === 'info') state.summary.low++;
                else if (f.severity === 'passed') state.summary.passed++;
            });
        }

        if (state.deviceAudit) {
            const os = state.deviceAudit.os;
            const checklists = (typeof DeviceScanner !== 'undefined' && DeviceScanner.checklists) ? DeviceScanner.checklists[os] : [];
            checklists.forEach(item => {
                const passed = localStorage.getItem(`vulnshield_audit_${os}_${item.id}`) === 'true';
                if (passed) {
                    state.summary.passed++;
                } else {
                    state.summary.medium++;
                }
            });
        }

        if (state.owaspScan && state.owaspScan.findings) {
            state.owaspScan.findings.forEach(f => {
                if (f.severity === 'high' || f.severity === 'critical') state.summary.high++;
                else if (f.severity === 'warning') state.summary.medium++;
                else if (f.severity === 'info') state.summary.low++;
                else if (f.severity === 'passed') state.summary.passed++;
            });
        }

        // Global Score Algorithm
        const scores = [];
        if (state.webScan && state.webScan.findings) {
            const bad = state.webScan.findings.filter(f => f.severity === 'high' || f.severity === 'critical').length * 25 +
                        state.webScan.findings.filter(f => f.severity === 'warning').length * 10;
            scores.push(Math.max(100 - bad, 0));
        }
        if (state.appScan && state.appScan.findings) {
            const bad = state.appScan.findings.filter(f => f.severity === 'high' || f.severity === 'critical').length * 30 +
                        state.appScan.findings.filter(f => f.severity === 'warning').length * 15;
            scores.push(Math.max(100 - bad, 0));
        }
        if (state.deviceAudit && state.deviceAudit.score !== undefined) {
            scores.push(state.deviceAudit.score);
        }
        if (state.owaspScan && state.owaspScan.findings) {
            const bad = state.owaspScan.findings.filter(f => f.severity === 'high' || f.severity === 'critical').length * 20 +
                        state.owaspScan.findings.filter(f => f.severity === 'warning').length * 8;
            scores.push(Math.max(100 - bad, 0));
        }

        if (scores.length > 0) {
            const sum = scores.reduce((a, b) => a + b, 0);
            state.summary.totalScore = Math.round(sum / scores.length);
        } else {
            state.summary.totalScore = null;
        }

        return state;
    },

    getSavedWebScan: function () {
        const raw = localStorage.getItem('vulnshield_web_scan');
        return raw ? JSON.parse(raw) : null;
    },

    getSavedAppScan: function () {
        const raw = localStorage.getItem('vulnshield_app_scan');
        return raw ? JSON.parse(raw) : null;
    },

    getSavedOwaspScan: function () {
        const raw = localStorage.getItem('vulnshield_owasp_scan');
        return raw ? JSON.parse(raw) : null;
    },

    getSavedDeviceAudit: function () {
        const activeOS = localStorage.getItem('vulnshield_device_active_os') || 'windows';
        const score = (typeof DeviceScanner !== 'undefined') ? DeviceScanner.calculateScore(activeOS) : 0;
        return { os: activeOS, score: score, timestamp: new Date().toISOString() };
    },

    exportJson: function () {
        const data = this.compileReport();
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 4));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `vulnshield_security_report_${new Date().getTime()}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
    },

    exportPdf: function () {
        if (typeof window.jspdf === 'undefined') {
            alert('PDF Library is still loading, please try again in a few seconds.');
            return;
        }

        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        const report = this.compileReport();
        const gradeInfo = this.calculateGrade(report.summary.totalScore);
        const dateStr = new Date().toLocaleString();

        // 1. Title & Header
        doc.setFont("helvetica", "bold");
        doc.setFontSize(22);
        doc.setTextColor(16, 185, 129); // Emerald Green
        doc.text("BERNISH VULNSHIELD", 14, 20);

        doc.setFont("helvetica", "normal");
        doc.setFontSize(12);
        doc.setTextColor(100, 100, 100);
        doc.text("Executive Security Audit & Vulnerability Scorecard", 14, 28);
        
        doc.setFontSize(10);
        doc.text(`Audit Date: ${dateStr}`, 14, 34);

        // 2. Grade Badge
        doc.setFont("helvetica", "bold");
        doc.setFontSize(26);
        doc.setTextColor(0, 0, 0); 
        doc.text(gradeInfo.grade, 160, 24);
        doc.setFontSize(10);
        doc.text(gradeInfo.label, 150, 30);

        // 3. Stats Summary
        doc.setFontSize(12);
        doc.setTextColor(0, 0, 0);
        doc.text(`Overall Score: ${report.summary.totalScore !== null ? report.summary.totalScore + '/100' : 'N/A'}`, 14, 45);
        doc.text(`High Critical Risks: ${report.summary.high}`, 14, 52);
        doc.text(`Medium Warnings: ${report.summary.medium}`, 100, 52);
        doc.text(`Passed Controls: ${report.summary.passed}`, 14, 59);

        // 4. Prepare Table Data
        const allFindings = [];
        if (report.webScan && report.webScan.findings) {
            report.webScan.findings.forEach(f => allFindings.push({ title: `[Web] ${f.title}`, severity: f.severity, desc: f.desc }));
        }
        if (report.appScan && report.appScan.findings) {
            report.appScan.findings.forEach(f => allFindings.push({ title: `[Code] ${f.title}`, severity: f.severity, desc: f.desc }));
        }
        if (report.owaspScan && report.owaspScan.findings) {
            report.owaspScan.findings.forEach(f => allFindings.push({ title: `[OWASP] ${f.title}`, severity: f.severity, desc: f.desc }));
        }
        if (report.deviceAudit) {
            const os = report.deviceAudit.os;
            const items = (typeof DeviceScanner !== 'undefined' && DeviceScanner.checklists) ? DeviceScanner.checklists[os] : [];
            items.forEach(item => {
                const passed = localStorage.getItem(`vulnshield_audit_${os}_${item.id}`) === 'true';
                allFindings.push({
                    title: `[OS] ${item.title}`,
                    severity: passed ? 'passed' : 'warning',
                    desc: passed ? 'Control parameter is verified active.' : 'Security standard is unverified or disabled.'
                });
            });
        }

        const tableColumn = ["Audit Vector / Finding", "Severity", "Diagnostic Details", "Remediation Guidance"];
        const tableRows = [];

        if (allFindings.length === 0) {
            tableRows.push(["No audit scans recorded yet.", "-", "-", "-"]);
        } else {
            allFindings.forEach(f => {
                const remediation = this.getRemediation(f.title, f.severity);
                const sev = (f.severity || '').toUpperCase();
                tableRows.push([f.title, sev, f.desc, remediation]);
            });
        }

        // 5. Generate Table
        doc.autoTable({
            startY: 65,
            head: [tableColumn],
            body: tableRows,
            theme: 'grid',
            headStyles: { fillColor: [16, 185, 129] },
            styles: { fontSize: 9, cellPadding: 3 },
            columnStyles: {
                0: { cellWidth: 40 },
                1: { cellWidth: 20 },
                2: { cellWidth: 60 },
                3: { cellWidth: 60 }
            },
            didParseCell: function (data) {
                if (data.section === 'body' && data.column.index === 1) {
                    if (data.cell.raw === 'HIGH') {
                        data.cell.styles.textColor = [255, 82, 82];
                        data.cell.styles.fontStyle = 'bold';
                    } else if (data.cell.raw === 'CRITICAL') {
                        data.cell.styles.textColor = [220, 38, 38];
                        data.cell.styles.fontStyle = 'bold';
                    } else if (data.cell.raw === 'WARNING' || data.cell.raw === 'MEDIUM') {
                        data.cell.styles.textColor = [255, 153, 0];
                        data.cell.styles.fontStyle = 'bold';
                    } else if (data.cell.raw === 'PASSED') {
                        data.cell.styles.textColor = [0, 200, 83];
                        data.cell.styles.fontStyle = 'bold';
                    }
                }
            }
        });

        // 6. Footer
        const pageCount = doc.internal.getNumberOfPages();
        for(let i = 1; i <= pageCount; i++) {
            doc.setPage(i);
            doc.setFontSize(8);
            doc.setTextColor(150, 150, 150);
            doc.text(
                'Confidential Security Report — Compiled automatically by BernishVuln_Shield Executive Security Engine',
                14,
                doc.internal.pageSize.height - 10
            );
        }

        // 7. Save PDF
        doc.save(`VulnShield_Report_${new Date().getTime()}.pdf`);
    },

    renderReportLogs: function (containerId) {
        const report = this.compileReport();
        const container = document.getElementById(containerId);
        if (!container) return;

        // Update overall counters
        const globalScoreVal = document.getElementById('report-global-score');
        const highCountVal = document.getElementById('report-high-count');
        const medCountVal = document.getElementById('report-med-count');
        const passedCountVal = document.getElementById('report-passed-count');
        
        const gradeBadgeVal = document.getElementById('report-executive-grade');
        const gradeLabelVal = document.getElementById('report-executive-label');

        const gradeInfo = this.calculateGrade(report.summary.totalScore);

        if (gradeBadgeVal) {
            gradeBadgeVal.innerText = gradeInfo.grade;
            gradeBadgeVal.style.color = gradeInfo.color;
        }
        if (gradeLabelVal) {
            gradeLabelVal.innerText = gradeInfo.label;
            gradeLabelVal.style.color = gradeInfo.color;
        }

        if (report.summary.totalScore !== null) {
            globalScoreVal.innerText = `${report.summary.totalScore}/100`;
            globalScoreVal.className = 'num ' + (report.summary.totalScore >= 80 ? 'text-green' : (report.summary.totalScore >= 50 ? 'text-yellow' : 'text-red'));
        } else {
            globalScoreVal.innerText = '--';
            globalScoreVal.className = 'num text-accent';
        }

        highCountVal.innerText = report.summary.high;
        medCountVal.innerText = report.summary.medium;
        passedCountVal.innerText = report.summary.passed;

        // Render detailed findings tables with Remediation column
        container.innerHTML = '';
        let html = '';
        let hasContent = false;

        if (report.webScan) {
            hasContent = true;
            html += `
                <div class="report-section-log mb-4">
                    <h5 class="text-blue" style="font-size: 15px; margin-bottom: 8px;"><i class="fa-solid fa-globe"></i> Website Scan Summary (${report.webScan.domain})</h5>
                    <table class="summary-log-table">
                        <thead>
                            <tr>
                                <th>Finding</th>
                                <th>Severity</th>
                                <th>Remediation Advice</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            report.webScan.findings.forEach(f => {
                html += `
                    <tr>
                        <td style="font-weight: 600;">${f.title}</td>
                        <td><span class="severity-label ${f.severity === 'warning' ? 'warning' : f.severity}">${f.severity}</span></td>
                        <td class="text-muted small">${this.getRemediation(f.title, f.severity)}</td>
                    </tr>
                `;
            });
            html += `</tbody></table></div>`;
        }

        if (report.appScan) {
            hasContent = true;
            html += `
                <div class="report-section-log mb-4">
                    <h5 class="text-purple" style="font-size: 15px; margin-bottom: 8px;"><i class="fa-solid fa-mobile-screen-button"></i> Static Code Scanner Summary (${report.appScan.filename})</h5>
                    <table class="summary-log-table">
                        <thead>
                            <tr>
                                <th>Vulnerability</th>
                                <th>Severity</th>
                                <th>Remediation Advice</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            report.appScan.findings.forEach(f => {
                html += `
                    <tr>
                        <td style="font-weight: 600;">${f.title}</td>
                        <td><span class="severity-label ${f.severity === 'warning' ? 'warning' : f.severity}">${f.severity}</span></td>
                        <td class="text-muted small">${this.getRemediation(f.title, f.severity)}</td>
                    </tr>
                `;
            });
            html += `</tbody></table></div>`;
        }

        if (report.owaspScan) {
            hasContent = true;
            html += `
                <div class="report-section-log mb-4">
                    <h5 class="text-accent" style="font-size: 15px; margin-bottom: 8px;"><i class="fa-solid fa-bug-slash"></i> OWASP Top 10 Scanner Summary (${report.owaspScan.url})</h5>
                    <table class="summary-log-table">
                        <thead>
                            <tr>
                                <th>Category / Vulnerability</th>
                                <th>Severity</th>
                                <th>Remediation Advice</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            report.owaspScan.findings.forEach(f => {
                html += `
                    <tr>
                        <td style="font-weight: 600;">[${f.category}] ${f.title}</td>
                        <td><span class="severity-label ${f.severity === 'warning' ? 'warning' : f.severity}">${f.severity}</span></td>
                        <td class="text-muted small">${this.getRemediation(f.title, f.severity)}</td>
                    </tr>
                `;
            });
            html += `</tbody></table></div>`;
        }

        if (report.deviceAudit) {
            hasContent = true;
            html += `
                <div class="report-section-log mb-4">
                    <h5 class="text-green" style="font-size: 15px; margin-bottom: 8px;"><i class="fa-solid fa-laptop-shield"></i> Local Host OS Compliance (${report.deviceAudit.os.toUpperCase()})</h5>
                    <table class="summary-log-table">
                        <thead>
                            <tr>
                                <th>Audit Control Item</th>
                                <th>Status</th>
                                <th>Remediation Advice</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            const os = report.deviceAudit.os;
            const items = (typeof DeviceScanner !== 'undefined' && DeviceScanner.checklists) ? DeviceScanner.checklists[os] : [];
            items.forEach(item => {
                const passed = localStorage.getItem(`vulnshield_audit_${os}_${item.id}`) === 'true';
                html += `
                    <tr>
                        <td style="font-weight: 600;">${item.title}</td>
                        <td><span class="severity-label ${passed ? 'passed' : 'warning'}">${passed ? 'passed' : 'warning'}</span></td>
                        <td class="text-muted small">${passed ? 'Control parameter is verified active.' : this.getRemediation(item.title, 'warning')}</td>
                    </tr>
                `;
            });
            html += `</tbody></table></div>`;
        }

        if (!hasContent) {
            container.innerHTML = `<div class="empty-state">No security audits committed. Please scan a website, run static file scanner, or update device profiles.</div>`;
        } else {
            container.innerHTML = html;
        }
    }
};
