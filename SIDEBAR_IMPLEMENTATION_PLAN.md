# Dashboard Sidebar Navigation - Implementation Plan

## Goal
Add sidebar navigation with 5 scan categories:
1. **Reconnaissance** - Domain enumeration, subdomain scanning
2. **Web Security** - XSS, SQLi, CSRF, security headers
3. **Vulnerability Scan** - CVE scanning, Nuclei templates
4. **API Security** - GraphQL, REST API, JWT testing
5. **Mobile Security** - Mobile app scanning (future)

## Current State
- Dashboard uses single form with mode dropdown
- All scan options in one place
- No visual categorization

## Implementation Steps

### 1. Add Sidebar HTML Structure
```html
<div class="dashboard-container">
    <aside class="scan-sidebar">
        <nav class="scan-categories">
            <div class="category active" data-category="recon">
                🔍 Reconnaissance
            </div>
            <div class="category" data-category="web">
                🌐 Web Security
            </div>
            <div class="category" data-category="vuln">
                ⚠️ Vulnerability Scan
            </div>
            <div class="category" data-category="api">
                🔌 API Security
            </div>
            <div class="category" data-category="mobile">
                📱 Mobile Security
            </div>
        </nav>
    </aside>
    <main class="scan-content">
        <!-- Existing dashboard content -->
    </main>
</div>
```

### 2. Add CSS for Sidebar
```css
.dashboard-container {
    display: flex;
    height: calc(100vh - 80px);
}

.scan-sidebar {
    width: 250px;
    background: #0b1120;
    border-right: 1px solid #1f2937;
    padding: 20px 0;
}

.category {
    padding: 15px 25px;
    cursor: pointer;
    transition: all 0.3s;
    border-left: 3px solid transparent;
}

.category:hover {
    background: rgba(56, 189, 248, 0.1);
}

.category.active {
    background: rgba(56, 189, 248, 0.15);
    border-left-color: #38bdf8;
    font-weight: 600;
}
```

### 3. Update Scan Form Logic
- Show/hide relevant form fields based on selected category
- Reconnaissance → Enable recon mode, show subdomain options
- Web Security → Show web vulnerability detectors
- Vulnerability Scan → Show CVE scanning options
- API Security → Show GraphQL/REST/JWT options
- Mobile Security → Show mobile app upload (future)

### 4. JavaScript for Category Switching
```javascript
document.querySelectorAll('.category').forEach(cat => {
    cat.addEventListener('click', () => {
        // Remove active from all
        document.querySelectorAll('.category').forEach(c => c.classList.remove('active'));
        // Add active to clicked
        cat.classList.add('active');
        
        const category = cat.dataset.category;
        updateScanForm(category);
    });
});

function updateScanForm(category) {
    // Show/hide form fields based on category
    // Update scan mode automatically
    // Show relevant detectors only
}
```

## Benefits
1. **Better UX** - Clear categorization of scan types
2. **Easier navigation** - Users know exactly what they want to scan
3. **Pro features** - Clear separation of FREE vs PRO features per category
4. **Extensibility** - Easy to add new scan types (Mobile, Cloud, etc.)

## Next Steps
1. Create sidebar HTML structure in dashboard.html
2. Add CSS styles for sidebar
3. Update JavaScript to handle category switching
4. Test with different user tiers (FREE vs PRO)
