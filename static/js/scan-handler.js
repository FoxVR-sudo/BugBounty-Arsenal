/**
 * Scan Form Handler for BugBounty Arsenal
 * Handles scan form submissions and real-time status updates
 */

// Initialize API client
const api = new BugBountyAPI();

// Store active scans
let activeScans = new Map();
let statusPollInterval = null;

/**
 * Start scan from form submission
 */
async function startScan(event) {
    event.preventDefault();
    
    const form = event.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    
    try {
        // Disable button
        submitBtn.disabled = true;
        submitBtn.textContent = '🔄 Starting scan...';
        
        // Get form data
        const target = form.querySelector('#target').value.trim();
        const scanType = getScanType();
        
        if (!target) {
            throw new Error('Please enter a target URL');
        }
        
        // Get scan options based on page
        const options = getScanOptions(form);
        
        // Start scan via API
        const result = await api.startScan(target, scanType, options);
        
        // Show success message
        showNotification('✅ Scan started successfully!', 'success');
        
        // Show scan results section
        const resultsSection = document.getElementById('scanResults');
        if (resultsSection) {
            resultsSection.classList.add('active');
        }
        
        // Add to active scans
        activeScans.set(result.id, {
            id: result.id,
            target: result.target,
            scan_type: result.scan_type,
            status: result.status,
            started_at: result.started_at,
            progress: 0
        });
        
        // Store current scan ID for progress tracking
        window.currentScanId = result.id;
        
        // Clear form
        form.reset();
        
        // Start polling for status updates and progress
        startStatusPolling();
        startProgressPolling(result.id);
        
        // Update scan list
        await updateScanList();
        
    } catch (error) {
        console.error('Scan start error:', error);
        showNotification('❌ ' + error.message, 'error');
    } finally {
        // Re-enable button
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
    }
}

/**
 * Get scan type based on current page
 */
function getScanType() {
    const path = window.location.pathname;
    
    // New 5 main scanner URLs
    if (path.includes('/scan/reconnaissance')) return 'reconnaissance';
    if (path.includes('/scan/web')) return 'web_security';
    if (path.includes('/scan/api')) return 'api_security';
    if (path.includes('/scan/mobile')) return 'mobile_security';
    if (path.includes('/scan/comprehensive')) return 'comprehensive';
    
    // Old dashboard URLs (backward compatibility)
    if (path.includes('/api-scan/')) return 'api_security';
    if (path.includes('/vulnerability-scan/')) return 'vulnerability';
    if (path.includes('/mobile-scan/')) return 'mobile';
    if (path.includes('/custom-scan/')) return 'custom';
    if (path.includes('/passive-scan/')) return 'passive';
    
    return 'web_security'; // Default
}

/**
 * Get scan options from form
 */
function getScanOptions(form) {
    const options = {};
    
    // Get scan mode
    const scanModeEl = form.querySelector('#scanMode');
    if (scanModeEl) {
        options.scan_mode = scanModeEl.value;
    }
    
    // Get authentication if present
    const authTypeEl = form.querySelector('#authType');
    if (authTypeEl && authTypeEl.value !== 'none') {
        options.auth_type = authTypeEl.value;
        
        const authValueEl = form.querySelector('#authValue');
        if (authValueEl) {
            options.auth_value = authValueEl.value;
        }
    }
    
    // Get custom headers if present
    const customHeadersEl = form.querySelector('#customHeaders');
    if (customHeadersEl && customHeadersEl.value) {
        try {
            options.custom_headers = JSON.parse(customHeadersEl.value);
        } catch (e) {
            console.warn('Invalid JSON in custom headers');
        }
    }
    
    // Get detectors
    const detectors = [];
    form.querySelectorAll('input[type="checkbox"][data-detector]').forEach(checkbox => {
        if (checkbox.checked) {
            detectors.push(checkbox.dataset.detector);
        }
    });
    if (detectors.length > 0) {
        options.detectors = detectors;
    }
    
    // Get concurrency
    const concurrencyEl = form.querySelector('#concurrency');
    if (concurrencyEl) {
        options.concurrency = parseInt(concurrencyEl.value, 10);
    }
    
    // Get timeout
    const timeoutEl = form.querySelector('#timeout');
    if (timeoutEl) {
        options.timeout = parseInt(timeoutEl.value, 10);
    }
    
    return options;
}

/**
 * Update scan list table
 */
async function updateScanList() {
    try {
        const scans = await api.getScanStatus();
        
        const tbody = document.querySelector('table tbody');
        if (!tbody) return;
        
        if (scans.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4" style="text-align: center; padding: 2rem; color: #6c757d;">
                        No scans yet. Start your first scan above.
                    </td>
                </tr>
            `;
            return;
        }
        
        // Show only recent 10 scans
        const recentScans = scans.slice(0, 10);
        
        tbody.innerHTML = recentScans.map(scan => {
            const statusEmoji = getStatusEmoji(scan.status);
            const statusClass = getStatusClass(scan.status);
            const timeAgo = getTimeAgo(scan.started_at);
            
            return `
                <tr>
                    <td>
                        <a href="/dashboard/results/?scan=${scan.id}" style="color: var(--primary); text-decoration: none;">
                            ${escapeHtml(scan.target)}
                        </a>
                    </td>
                    <td>
                        <span class="status-badge ${statusClass}">
                            ${statusEmoji} ${capitalize(scan.status)}
                        </span>
                    </td>
                    <td>
                        ${scan.vulnerabilities_found !== null ? 
                            `<strong>${scan.vulnerabilities_found}</strong> found` : 
                            '<span style="color: #6c757d;">Pending</span>'}
                    </td>
                    <td style="color: #6c757d; font-size: 0.875rem;">
                        ${timeAgo}
                    </td>
                </tr>
            `;
        }).join('');
        
    } catch (error) {
        console.error('Failed to update scan list:', error);
    }
}

/**
 * Start polling for scan status
 */
function startStatusPolling() {
    if (statusPollInterval) return;
    
    // Poll every 5 seconds
    statusPollInterval = setInterval(async () => {
        await updateScanList();
    }, 5000);
}

/**
 * Stop polling for scan status
 */
function stopStatusPolling() {
    if (statusPollInterval) {
        clearInterval(statusPollInterval);
        statusPollInterval = null;
    }
}

/**
 * Get status emoji
 */
function getStatusEmoji(status) {
    const emojis = {
        'pending': '⏳',
        'running': '🔄',
        'completed': '✅',
        'failed': '❌',
        'cancelled': '⛔'
    };
    return emojis[status] || '❓';
}

/**
 * Get status CSS class
 */
function getStatusClass(status) {
    const classes = {
        'pending': 'status-pending',
        'running': 'status-running',
        'completed': 'status-completed',
        'failed': 'status-failed',
        'cancelled': 'status-cancelled'
    };
    return classes[status] || '';
}

/**
 * Get time ago string
 */
function getTimeAgo(timestamp) {
    const now = new Date();
    const past = new Date(timestamp);
    const diffMs = now - past;
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} min ago`;
    
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    // Check if notification container exists
    let container = document.getElementById('notification-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notification-container';
        container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 10000; max-width: 400px;';
        document.body.appendChild(container);
    }
    
    // Create notification
    const notification = document.createElement('div');
    notification.style.cssText = `
        background: ${type === 'error' ? '#dc3545' : type === 'success' ? '#28a745' : '#007bff'};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        margin-bottom: 10px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        animation: slideInRight 0.3s ease-out;
    `;
    notification.textContent = message;
    
    container.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-in';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

/**
 * Capitalize first letter
 */
function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Escape HTML
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Attach form handler
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', startScan);
    }
    
    // Load initial scan list
    updateScanList();
    
    // Start polling
    startStatusPolling();
    
    // Stop polling when page is hidden
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            stopStatusPolling();
        } else {
            startStatusPolling();
        }
    });
});

// Add CSS animation styles
const style = document.createElement('style');
style.textContent = `
@keyframes slideInRight {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

@keyframes slideOutRight {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(100%); opacity: 0; }
}

.status-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.875rem;
    font-weight: 500;
}

.status-pending {
    background: #fff3cd;
    color: #856404;
}

.status-running {
    background: #d1ecf1;
    color: #0c5460;
}

.status-completed {
    background: #d4edda;
    color: #155724;
}

.status-failed {
    background: #f8d7da;
    color: #721c24;
}

.status-cancelled {
    background: #e2e3e5;
    color: #383d41;
}
`;
document.head.appendChild(style);

// Progress polling variables
let progressPollInterval = null;

/**
 * Start polling for scan progress
 */
function startProgressPolling(scanId) {
    if (progressPollInterval) return;
    
    // Poll every 2 seconds for real-time updates
    progressPollInterval = setInterval(async () => {
        await updateScanProgress(scanId);
    }, 2000);
    
    // Initial update
    updateScanProgress(scanId);
}

/**
 * Stop progress polling
 */
function stopProgressPolling() {
    if (progressPollInterval) {
        clearInterval(progressPollInterval);
        progressPollInterval = null;
    }
}

/**
 * Update scan progress UI
 */
async function updateScanProgress(scanId) {
    try {
        // Get scan status from API
        const response = await api.getScanDetails(scanId);
        
        if (!response) return;
        
        // Update progress bar
        const progress = response.progress || 0;
        const progressBar = document.getElementById('progressBar');
        const progressPercentage = document.getElementById('progressPercentage');
        
        if (progressBar && progressPercentage) {
            progressBar.style.width = progress + '%';
            progressPercentage.textContent = Math.round(progress) + '%';
            
            if (progress > 5) {
                progressBar.textContent = Math.round(progress) + '%';
            }
        }
        
        // Update current detector
        const currentDetector = document.getElementById('currentDetector');
        if (currentDetector && response.current_detector) {
            currentDetector.innerHTML = `<span style="color: var(--primary-blue);">🔍</span> Running: <strong>${formatDetectorName(response.current_detector)}</strong>`;
        }
        
        // Update active processes
        const processList = document.getElementById('processList');
        if (processList && response.active_detectors && response.active_detectors.length > 0) {
            processList.innerHTML = response.active_detectors.map(detector => `
                <div style="background: var(--card-bg); padding: 0.5rem 0.75rem; border-radius: 6px; border: 1px solid var(--border-color); font-size: 0.85rem;">
                    <span style="color: var(--primary-blue);">⚡</span> ${formatDetectorName(detector)}
                </div>
            `).join('');
        } else if (processList && progress > 0 && progress < 100) {
            processList.innerHTML = '<div style="color: var(--text-secondary);">Initializing...</div>';
        }
        
        // Update status indicator
        const statusIndicator = document.getElementById('statusIndicator');
        const statusText = document.getElementById('statusText');
        
        if (response.status === 'completed') {
            if (statusIndicator) {
                statusIndicator.className = 'status-indicator completed';
            }
            if (statusText) {
                statusText.textContent = '✅ Scan Completed';
            }
            stopProgressPolling();
            
            // Load final results
            await loadScanResults(scanId);
            
        } else if (response.status === 'failed') {
            if (statusIndicator) {
                statusIndicator.className = 'status-indicator failed';
            }
            if (statusText) {
                statusText.textContent = '❌ Scan Failed';
            }
            stopProgressPolling();
            
        } else if (response.status === 'running') {
            if (statusText) {
                statusText.textContent = '🔄 Scanning... (' + Math.round(progress) + '%)';
            }
        }
        
        // Update vulnerability counts if available
        if (response.vulnerabilities_found !== undefined) {
            updateVulnerabilityCounts(response.vulnerabilities);
        }
        
    } catch (error) {
        console.error('Failed to update progress:', error);
    }
}

/**
 * Format detector name for display
 */
function formatDetectorName(detector) {
    return detector
        .replace(/_/g, ' ')
        .replace(/\b\w/g, l => l.toUpperCase());
}

/**
 * Update vulnerability counts in info boxes
 */
function updateVulnerabilityCounts(vulnerabilities) {
    if (!vulnerabilities || vulnerabilities.length === 0) return;
    
    const infoBoxes = document.getElementById('infoBoxes');
    if (infoBoxes) {
        infoBoxes.style.display = 'flex';
    }
    
    const counts = {
        total: vulnerabilities.length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length
    };
    
    const totalVulns = document.getElementById('totalVulns');
    const highSeverity = document.getElementById('highSeverity');
    const mediumSeverity = document.getElementById('mediumSeverity');
    const lowSeverity = document.getElementById('lowSeverity');
    
    if (totalVulns) totalVulns.textContent = counts.total;
    if (highSeverity) highSeverity.textContent = counts.high;
    if (mediumSeverity) mediumSeverity.textContent = counts.medium;
    if (lowSeverity) lowSeverity.textContent = counts.low;
}

/**
 * Load and display final scan results
 */
async function loadScanResults(scanId) {
    try {
        const response = await api.getScanDetails(scanId);
        
        if (!response || !response.vulnerabilities) return;
        
        const resultsContent = document.getElementById('resultsContent');
        if (!resultsContent) return;
        
        if (response.vulnerabilities.length === 0) {
            resultsContent.innerHTML = `
                <div style="text-align: center; padding: 3rem; color: var(--text-secondary);">
                    <div style="font-size: 3rem; margin-bottom: 1rem;">✅</div>
                    <h3>No Vulnerabilities Found</h3>
                    <p>The target appears to be secure.</p>
                </div>
            `;
        } else {
            resultsContent.innerHTML = `
                <h3 style="margin-bottom: 1.5rem;">Detected Vulnerabilities (${response.vulnerabilities.length})</h3>
                ${response.vulnerabilities.map(vuln => `
                    <div class="vulnerability-item ${vuln.severity}">
                        <div class="vulnerability-header">
                            <h4>${escapeHtml(vuln.title || vuln.type)}</h4>
                            <span class="severity-badge ${vuln.severity}">${vuln.severity.toUpperCase()}</span>
                        </div>
                        <p style="color: var(--text-secondary); margin-bottom: 0.5rem;">${escapeHtml(vuln.description || 'No description')}</p>
                        ${vuln.url ? `<p style="font-size: 0.875rem; color: var(--text-secondary);"><strong>URL:</strong> ${escapeHtml(vuln.url)}</p>` : ''}
                        ${vuln.payload ? `<p style="font-size: 0.875rem; color: var(--text-secondary);"><strong>Payload:</strong> <code>${escapeHtml(vuln.payload)}</code></p>` : ''}
                    </div>
                `).join('')}
            `;
        }
    } catch (error) {
        console.error('Failed to load results:', error);
    }
}

