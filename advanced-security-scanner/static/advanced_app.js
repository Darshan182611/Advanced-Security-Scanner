// Advanced Security Scanner - Interactive Dashboard JavaScript
// Includes real-time progress tracking, dark mode, and advanced features

class SecurityScanner {
    constructor() {
        this.currentScanId = null;
        this.progressInterval = null;
        this.darkMode = localStorage.getItem('darkMode') === 'true';
        this.scanHistory = [];
        
        this.initializeApp();
    }

    initializeApp() {
        // Initialize dark mode
        if (this.darkMode) {
            document.documentElement.setAttribute('data-theme', 'dark');
            document.getElementById('theme-icon').className = 'fas fa-sun';
        }

        // Bind event listeners
        this.bindEventListeners();
        
        // Load initial data
        this.loadScanHistory();
        
        console.log('🔒 Advanced Security Scanner initialized');
    }

    bindEventListeners() {
        // Main scan form
        const scanForm = document.getElementById('advancedScanForm');
        if (scanForm) {
            scanForm.addEventListener('submit', (e) => this.startAdvancedScan(e));
        }

        // URL input validation
        const urlInput = document.getElementById('urlInput');
        if (urlInput) {
            urlInput.addEventListener('input', () => this.validateUrlInput());
            urlInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !this.isScanRunning()) {
                    this.startAdvancedScan(e);
                }
            });
        }

        // Auto-focus URL input
        if (urlInput) urlInput.focus();
    }

    validateUrlInput() {
        const urlInput = document.getElementById('urlInput');
        const url = urlInput.value.trim();
        
        if (url && !this.isValidUrl(url)) {
            urlInput.style.borderColor = 'var(--danger-color)';
            urlInput.title = 'Please enter a valid URL';
        } else {
            urlInput.style.borderColor = 'var(--border-color)';
            urlInput.title = '';
        }
    }

    isValidUrl(string) {
        const urlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
        return urlPattern.test(string) || /^[\da-z\.-]+\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/.test(string);
    }

    async startAdvancedScan(e) {
        e.preventDefault();
        
        const url = document.getElementById('urlInput').value.trim();
        if (!url) {
            this.showNotification('Please enter a URL to scan', 'error');
            return;
        }

        if (!this.isValidUrl(url)) {
            this.showNotification('Please enter a valid URL', 'error');
            return;
        }

        const options = this.collectScanOptions();
        
        try {
            this.startScanUI();
            
            const response = await fetch('/scan/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url, options })
            });

            const data = await response.json();
            
            if (response.ok) {
                this.currentScanId = data.scan_id;
                this.showNotification('Advanced scan started successfully!', 'success');
                this.startProgressTracking(data.scan_id);
            } else {
                throw new Error(data.error || 'Failed to start scan');
            }
            
        } catch (error) {
            console.error('Scan start error:', error);
            this.stopScanUI();
            this.showNotification(`Error: ${error.message}`, 'error');
        }
    }

    collectScanOptions() {
        return {
            deepScan: document.getElementById('deepScan')?.checked || false,
            sslCheck: document.getElementById('sslCheck')?.checked || false,
            xssCheck: document.getElementById('xssCheck')?.checked || false
        };
    }

    startScanUI() {
        // Update button state
        const scanBtn = document.getElementById('scanBtn');
        const btnText = scanBtn.querySelector('.btn-text');
        const btnLoading = scanBtn.querySelector('.btn-loading');
        
        scanBtn.disabled = true;
        btnText.style.display = 'none';
        btnLoading.style.display = 'flex';

        // Show progress section
        const progressSection = document.getElementById('scanProgress');
        const resultsSection = document.getElementById('scanResults');
        
        if (progressSection) {
            progressSection.style.display = 'block';
            progressSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
        
        if (resultsSection) {
            resultsSection.style.display = 'none';
        }

        // Reset progress
        this.updateProgress(0, 'Initializing advanced scan...', {});
    }

    stopScanUI() {
        const scanBtn = document.getElementById('scanBtn');
        const btnText = scanBtn.querySelector('.btn-text');
        const btnLoading = scanBtn.querySelector('.btn-loading');
        
        scanBtn.disabled = false;
        btnText.style.display = 'flex';
        btnLoading.style.display = 'none';
        
        if (this.progressInterval) {
            clearInterval(this.progressInterval);
            this.progressInterval = null;
        }
    }

    startProgressTracking(scanId) {
        this.progressInterval = setInterval(async () => {
            try {
                const response = await fetch(`/scan/status/${scanId}`);
                const progress = await response.json();
                
                if (!response.ok) {
                    throw new Error(progress.error || 'Failed to get scan status');
                }

                this.updateProgressUI(progress);

                if (progress.status === 'completed') {
                    clearInterval(this.progressInterval);
                    this.handleScanComplete(progress);
                } else if (progress.status === 'error') {
                    clearInterval(this.progressInterval);
                    this.handleScanError(progress);
                }
                
            } catch (error) {
                console.error('Progress tracking error:', error);
                clearInterval(this.progressInterval);
                this.showNotification('Error tracking scan progress', 'error');
                this.stopScanUI();
            }
        }, 1000); // Update every second
    }

    updateProgressUI(progress) {
        // Update progress bar
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        const progressPercent = document.getElementById('progressPercent');
        const progressTitle = document.getElementById('progressTitle');
        
        if (progressFill) {
            progressFill.style.width = `${progress.progress || 0}%`;
        }
        
        if (progressText) {
            progressText.textContent = `${progress.progress || 0}%`;
        }
        
        if (progressPercent) {
            progressPercent.textContent = `${progress.progress || 0}%`;
        }
        
        if (progressTitle) {
            progressTitle.textContent = progress.current_step || 'Processing...';
        }

        // Update stats
        const formsFound = document.getElementById('formsFound');
        const vulnCount = document.getElementById('vulnCount');
        
        if (formsFound && progress.details) {
            formsFound.textContent = progress.details.forms_found || 0;
        }
        
        if (vulnCount && progress.details) {
            vulnCount.textContent = progress.details.vulnerabilities_found || 0;
        }

        // Update scan steps
        this.updateScanSteps(progress.progress);
    }

    updateScanSteps(progress) {
        const steps = [
            { id: 'step-ssl', threshold: 20 },
            { id: 'step-forms', threshold: 40 },
            { id: 'step-vulnerabilities', threshold: 80 },
            { id: 'step-report', threshold: 100 }
        ];

        steps.forEach(step => {
            const element = document.getElementById(step.id);
            if (element) {
                if (progress >= step.threshold) {
                    element.classList.add('completed');
                    element.classList.remove('active');
                } else if (progress >= step.threshold - 20) {
                    element.classList.add('active');
                    element.classList.remove('completed');
                } else {
                    element.classList.remove('active', 'completed');
                }
            }
        });
    }

    async handleScanComplete(progress) {
        this.stopScanUI();
        
        try {
            // Load detailed report
            const reportResponse = await fetch(`/scan/report/${this.currentScanId}`);
            const detailedReport = await reportResponse.json();
            
            // Display results
            this.displayScanResults(progress, detailedReport);
            
            // Add to history
            this.addToScanHistory(progress);
            
            this.showNotification('Security scan completed successfully!', 'success');
            
        } catch (error) {
            console.error('Error loading detailed report:', error);
            this.displayScanResults(progress, null);
        }
    }

    handleScanError(progress) {
        this.stopScanUI();
        this.showNotification(`Scan failed: ${progress.error}`, 'error');
        
        // Hide progress section
        const progressSection = document.getElementById('scanProgress');
        if (progressSection) {
            progressSection.style.display = 'none';
        }
    }

    displayScanResults(progress, detailedReport) {
        const resultsSection = document.getElementById('scanResults');
        const progressSection = document.getElementById('scanProgress');
        
        if (progressSection) progressSection.style.display = 'none';
        if (resultsSection) {
            resultsSection.style.display = 'block';
            resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        // Update summary card
        this.updateSummaryCard(progress, detailedReport);
        
        // Update statistics
        this.updateResultStats(progress, detailedReport);
        
        // Display vulnerabilities
        this.displayVulnerabilities(detailedReport);
        
        // Show detailed report
        this.setupDetailedReport(detailedReport);
    }

    updateSummaryCard(progress, detailedReport) {
        const summaryCard = document.querySelector('.summary-card');
        const riskLevel = document.getElementById('riskLevel');
        const summaryText = document.getElementById('summaryText');
        const cardIcon = summaryCard?.querySelector('.card-icon i');
        
        if (!summaryCard) return;
        
        const isVulnerable = progress.vulnerability_found;
        const vulnCount = progress.details?.vulnerabilities_found || 0;
        
        // Reset classes
        summaryCard.className = 'summary-card';
        
        if (isVulnerable) {
            summaryCard.classList.add('vulnerable');
            if (riskLevel) riskLevel.textContent = 'High Risk';
            if (summaryText) summaryText.textContent = `${vulnCount} security vulnerabilities detected`;
            if (cardIcon) cardIcon.className = 'fas fa-shield-virus';
        } else {
            summaryCard.classList.add('safe');
            if (riskLevel) riskLevel.textContent = 'Low Risk';
            if (summaryText) summaryText.textContent = 'No critical vulnerabilities found';
            if (cardIcon) cardIcon.className = 'fas fa-shield-check';
        }
    }

    updateResultStats(progress, detailedReport) {
        const totalVulns = document.getElementById('totalVulns');
        const scanDuration = document.getElementById('scanDuration');
        const formsScanned = document.getElementById('formsScanned');
        
        if (totalVulns) {
            totalVulns.textContent = progress.details?.vulnerabilities_found || 0;
        }
        
        if (scanDuration) {
            scanDuration.textContent = `${progress.details?.scan_duration || 0}s`;
        }
        
        if (formsScanned) {
            formsScanned.textContent = progress.details?.forms_tested || 0;
        }
    }

    displayVulnerabilities(detailedReport) {
        const vulnerabilityList = document.getElementById('vulnerabilityList');
        if (!vulnerabilityList || !detailedReport) return;
        
        const vulnerabilities = detailedReport.technical_details?.vulnerabilities || [];
        
        if (vulnerabilities.length === 0) {
            vulnerabilityList.innerHTML = `
                <div class="no-vulnerabilities">
                    <i class="fas fa-shield-check" style="font-size: 3rem; color: var(--success-color); margin-bottom: 1rem;"></i>
                    <h4>No Vulnerabilities Found</h4>
                    <p>The security scan did not detect any critical vulnerabilities.</p>
                </div>
            `;
            return;
        }
        
        vulnerabilityList.innerHTML = vulnerabilities.map(vuln => `
            <div class="vulnerability-item ${(vuln.severity || 'low').toLowerCase()}">
                <div class="vuln-header">
                    <div>
                        <div class="vuln-title">${this.escapeHtml(vuln.type || 'Unknown Vulnerability')}</div>
                        <div class="vuln-url">${this.escapeHtml(vuln.url || '')}</div>
                    </div>
                    <span class="vuln-severity ${(vuln.severity || 'low').toLowerCase()}">${vuln.severity || 'Low'}</span>
                </div>
                <div class="vuln-description">
                    ${this.escapeHtml(vuln.description || 'No description available')}
                </div>
                ${vuln.payload ? `<div class="vuln-details">Payload: ${this.escapeHtml(vuln.payload)}</div>` : ''}
                ${vuln.remediation ? `<div class="vuln-remediation"><strong>Remediation:</strong> ${this.escapeHtml(vuln.remediation)}</div>` : ''}
            </div>
        `).join('');
    }

    setupDetailedReport(detailedReport) {
        const detailedReportDiv = document.getElementById('detailedReport');
        if (!detailedReportDiv || !detailedReport) return;
        
        detailedReportDiv.innerHTML = `
            <div class="report-section">
                <h4>Executive Summary</h4>
                <pre>${JSON.stringify(detailedReport.executive_summary || {}, null, 2)}</pre>
            </div>
            <div class="report-section">
                <h4>Risk Assessment</h4>
                <pre>${JSON.stringify(detailedReport.risk_matrix || {}, null, 2)}</pre>
            </div>
            <div class="report-section">
                <h4>Technical Details</h4>
                <pre>${JSON.stringify(detailedReport.technical_details || {}, null, 2)}</pre>
            </div>
        `;
    }

    // Export functionality
    async exportReport(format) {
        if (!this.currentScanId) {
            this.showNotification('No scan report available to export', 'error');
            return;
        }
        
        try {
            const response = await fetch(`/scan/export/${this.currentScanId}/${format}`);
            
            if (!response.ok) {
                throw new Error('Export failed');
            }
            
            if (format === 'json') {
                const data = await response.json();
                this.downloadJson(data, `security_report_${this.currentScanId}.json`);
            } else {
                const blob = await response.blob();
                this.downloadBlob(blob, `security_report_${this.currentScanId}.${format}`);
            }
            
            this.showNotification(`Report exported as ${format.toUpperCase()}`, 'success');
            
        } catch (error) {
            console.error('Export error:', error);
            this.showNotification('Failed to export report', 'error');
        }
    }

    downloadJson(data, filename) {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        this.downloadBlob(blob, filename);
    }

    downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // Navigation functionality
    showTab(tabName) {
        // Hide all tabs
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });
        
        // Remove active class from all menu items
        document.querySelectorAll('.menu-item').forEach(item => {
            item.classList.remove('active');
        });
        
        // Show selected tab
        const selectedTab = document.getElementById(`${tabName}-tab`);
        if (selectedTab) {
            selectedTab.classList.add('active');
        }
        
        // Add active class to selected menu item
        const selectedMenuItem = document.querySelector(`[onclick="showTab('${tabName}')"]`);
        if (selectedMenuItem) {
            selectedMenuItem.classList.add('active');
        }
        
        // Load tab-specific data
        if (tabName === 'history') {
            this.loadScanHistory();
        } else if (tabName === 'reports') {
            this.loadReports();
        }
    }

    // Scan history functionality
    async loadScanHistory() {
        try {
            const response = await fetch('/history');
            const history = await response.json();
            this.displayScanHistory(history);
        } catch (error) {
            console.error('Error loading scan history:', error);
            this.showNotification('Failed to load scan history', 'error');
        }
    }

    displayScanHistory(history) {
        const historyList = document.getElementById('historyList');
        if (!historyList) return;
        
        if (history.length === 0) {
            historyList.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-history" style="font-size: 3rem; color: var(--text-muted); margin-bottom: 1rem;"></i>
                    <h4>No Scan History</h4>
                    <p>Your scan history will appear here once you start scanning websites.</p>
                </div>
            `;
            return;
        }
        
        historyList.innerHTML = history.map(scan => `
            <div class="history-item">
                <div class="history-header">
                    <h4>${this.escapeHtml(scan.url)}</h4>
                    <span class="history-date">${new Date(scan.created_at).toLocaleString()}</span>
                </div>
                <div class="history-meta">
                    <span class="status-badge ${scan.status}">${scan.status}</span>
                    <span class="risk-score">Risk Score: ${scan.risk_score || 0}</span>
                </div>
            </div>
        `).join('');
    }

    addToScanHistory(progress) {
        this.scanHistory.unshift({
            id: this.currentScanId,
            url: progress.url,
            created_at: new Date().toISOString(),
            status: 'completed',
            risk_score: progress.details?.risk_score || 0
        });
        
        // Keep only last 10 items
        this.scanHistory = this.scanHistory.slice(0, 10);
    }

    // Dark mode toggle
    toggleDarkMode() {
        this.darkMode = !this.darkMode;
        localStorage.setItem('darkMode', this.darkMode);
        
        const themeIcon = document.getElementById('theme-icon');
        
        if (this.darkMode) {
            document.documentElement.setAttribute('data-theme', 'dark');
            if (themeIcon) themeIcon.className = 'fas fa-sun';
        } else {
            document.documentElement.removeAttribute('data-theme');
            if (themeIcon) themeIcon.className = 'fas fa-moon';
        }
    }

    // Detailed report toggle
    toggleDetailedReport() {
        const detailedReport = document.getElementById('detailedReport');
        const expandBtn = document.querySelector('.expand-btn');
        const icon = expandBtn?.querySelector('i');
        
        if (detailedReport) {
            const isVisible = detailedReport.style.display === 'block';
            detailedReport.style.display = isVisible ? 'none' : 'block';
            
            if (icon) {
                icon.className = isVisible ? 'fas fa-chevron-down' : 'fas fa-chevron-up';
            }
            
            if (expandBtn) {
                const text = expandBtn.childNodes[1];
                if (text) {
                    text.textContent = isVisible ? 
                        ' View Detailed Technical Report' : 
                        ' Hide Detailed Technical Report';
                }
            }
        }
    }

    // Reports functionality
    loadReports() {
        // This would integrate with charting library
        console.log('Loading security reports and analytics...');
    }

    // API Key generation
    async generateApiKey() {
        try {
            const response = await fetch('/api/generate-key', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            
            const data = await response.json();
            
            const apiKeyInput = document.getElementById('apiKey');
            if (apiKeyInput) {
                apiKeyInput.value = data.api_key;
            }
            
            this.showNotification('API key generated successfully', 'success');
            
        } catch (error) {
            console.error('API key generation error:', error);
            this.showNotification('Failed to generate API key', 'error');
        }
    }

    // Logout functionality
    async logout() {
        try {
            const response = await fetch('/logout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            
            if (response.ok) {
                window.location.href = '/';
            } else {
                throw new Error('Logout failed');
            }
            
        } catch (error) {
            console.error('Logout error:', error);
            this.showNotification('Logout failed', 'error');
        }
    }

    // Utility functions
    isScanRunning() {
        return document.getElementById('scanBtn')?.disabled || false;
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <i class="fas fa-${this.getNotificationIcon(type)}"></i>
            <span>${this.escapeHtml(message)}</span>
            <button onclick="this.parentElement.remove()" class="notification-close">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        // Add to page
        document.body.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    getNotificationIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    updateProgress(percent, step, details) {
        this.updateProgressUI({
            progress: percent,
            current_step: step,
            details: details
        });
    }
}

// Global functions for HTML onclick handlers
function showTab(tabName) {
    if (window.scanner) {
        window.scanner.showTab(tabName);
    }
}

function toggleDarkMode() {
    if (window.scanner) {
        window.scanner.toggleDarkMode();
    }
}

function toggleDetailedReport() {
    if (window.scanner) {
        window.scanner.toggleDetailedReport();
    }
}

function exportReport(format) {
    if (window.scanner) {
        window.scanner.exportReport(format);
    }
}

function generateApiKey() {
    if (window.scanner) {
        window.scanner.generateApiKey();
    }
}

function logout() {
    if (window.scanner) {
        window.scanner.logout();
    }
}

function loadScanHistory() {
    if (window.scanner) {
        window.scanner.loadScanHistory();
    }
}

// Initialize scanner when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.scanner = new SecurityScanner();
});

// Add notification styles
const notificationStyles = `
    .notification {
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 0.5rem;
        padding: 1rem;
        display: flex;
        align-items: center;
        gap: 0.75rem;
        box-shadow: var(--shadow-lg);
        z-index: 10000;
        max-width: 400px;
        animation: slideInRight 0.3s ease;
    }
    
    .notification.success { border-left: 4px solid var(--success-color); }
    .notification.error { border-left: 4px solid var(--danger-color); }
    .notification.warning { border-left: 4px solid var(--warning-color); }
    .notification.info { border-left: 4px solid var(--info-color); }
    
    .notification-close {
        background: none;
        border: none;
        color: var(--text-muted);
        cursor: pointer;
        margin-left: auto;
        padding: 0.25rem;
        border-radius: 0.25rem;
    }
    
    .notification-close:hover {
        background: var(--bg-tertiary);
    }
    
    @keyframes slideInRight {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    .empty-state {
        text-align: center;
        padding: 4rem 2rem;
        color: var(--text-muted);
    }
    
    .empty-state h4 {
        color: var(--text-secondary);
        margin-bottom: 0.5rem;
    }
    
    .history-item {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 0.5rem;
        padding: 1.5rem;
        margin-bottom: 1rem;
    }
    
    .history-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        margin-bottom: 1rem;
    }
    
    .history-header h4 {
        color: var(--text-primary);
        margin: 0;
    }
    
    .history-date {
        color: var(--text-muted);
        font-size: 0.875rem;
    }
    
    .history-meta {
        display: flex;
        gap: 1rem;
        align-items: center;
    }
    
    .status-badge {
        padding: 0.25rem 0.5rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
    }
    
    .status-badge.completed {
        background: rgb(34 197 94 / 0.1);
        color: var(--success-color);
    }
    
    .risk-score {
        font-size: 0.875rem;
        color: var(--text-secondary);
    }
    
    .no-vulnerabilities {
        text-align: center;
        padding: 4rem 2rem;
    }
    
    .no-vulnerabilities h4 {
        color: var(--success-color);
        margin-bottom: 0.5rem;
    }
    
    .vuln-remediation {
        margin-top: 1rem;
        padding: 1rem;
        background: var(--bg-secondary);
        border-radius: 0.5rem;
        border-left: 4px solid var(--info-color);
        font-size: 0.875rem;
        color: var(--text-secondary);
    }
`;

// Inject notification styles
const style = document.createElement('style');
style.textContent = notificationStyles;
document.head.appendChild(style);