#!/bin/bash

# Update navigation header in dashboard.html inside Docker container

sudo docker exec bugbounty-web bash -c 'cat > /tmp/nav_header.html << '\''EOF'\''
<nav>
    <a href="/landing/" class="logo">⚡ BugBounty Arsenal</a>
    <div class="nav-links">
        <a href="/dashboard/">Dashboard</a>
        <a href="/dashboard/results/">Results</a>
        <a href="/landing/#features">Features</a>
        <a href="/landing/#pricing">Pricing</a>
        <div class="user-menu">
            <button class="btn user-menu-btn" style="display: flex; align-items: center; gap: 0.5rem;">
                <span class="tag" style="margin: 0;">{{ tier_info.name }}</span>
                <span>👤</span>
            </button>
            <div class="user-menu-dropdown">
                {% if tier_info.name == "Free" %}
                    <a href="/landing/#pricing">⬆️ Upgrade Plan</a>
                {% endif %}
                {% if is_superuser %}
                    <a href="{{ URLS.adminPanel }}">🛡️ Admin Panel</a>
                {% endif %}
                <a href="#" onclick="handleLogout(); return false;">👋 Logout</a>
            </div>
        </div>
    </div>
</nav>

<style>
nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.5rem 5%;
    background: linear-gradient(135deg, #ff6b9d, #ffd93d, #6eb5ff);
    border-bottom: 6px solid #2d2d2d;
    box-shadow: 0 8px 0 #2d2d2d, 0 12px 24px rgba(0, 0, 0, 0.3);
    position: sticky;
    top: 0;
    z-index: 100;
    flex-shrink: 0;
}

nav::before {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(45deg, transparent, transparent 10px, rgba(255, 255, 255, 0.1) 10px, rgba(255, 255, 255, 0.1) 20px);
    pointer-events: none;
}

.logo {
    font-size: 2rem;
    font-weight: 900;
    font-family: "Bangers", cursive;
    color: #fff;
    text-shadow: 4px 4px 0 #2d2d2d;
    letter-spacing: 2px;
    transform: rotate(-2deg);
    text-decoration: none;
    position: relative;
    z-index: 2;
}

.nav-links {
    display: flex;
    gap: 2rem;
    align-items: center;
    position: relative;
    z-index: 2;
}

.nav-links a {
    color: #2d2d2d;
    text-decoration: none;
    font-size: 1.1rem;
    transition: all 0.2s;
    font-weight: 700;
    text-shadow: 1px 1px 0 #fff;
}

.nav-links a:hover {
    color: #fff;
    text-shadow: 2px 2px 0 #2d2d2d;
    transform: translateY(-2px);
}

.user-menu {
    position: relative;
}

.user-menu-btn {
    background: #fff;
    color: #2d2d2d;
    padding: 0.6rem 1.5rem;
    cursor: pointer;
    border-radius: 12px;
    font-weight: 900;
    font-size: 1.1rem;
    border: 4px solid #2d2d2d;
    font-family: "Bangers", cursive;
    letter-spacing: 2px;
    text-transform: uppercase;
    box-shadow: 6px 6px 0 #2d2d2d;
}

.user-menu-dropdown {
    display: none;
    position: absolute;
    top: calc(100% + 10px);
    right: 0;
    background: #fff;
    border: 4px solid #2d2d2d;
    box-shadow: 6px 6px 0 #2d2d2d;
    min-width: 200px;
    z-index: 1000;
}

.user-menu:hover .user-menu-dropdown {
    display: block;
}

.user-menu-dropdown a {
    display: block;
    padding: 1rem 1.5rem;
    color: #2d2d2d;
    text-decoration: none;
    font-weight: 700;
    transition: all 0.2s;
    border-bottom: 2px dashed #ff6b9d;
    text-shadow: none;
    font-size: 1rem;
}

.user-menu-dropdown a:last-child {
    border-bottom: none;
}

.user-menu-dropdown a:hover {
    background: linear-gradient(135deg, #fff9e5, #ffe5f9);
    transform: translateX(5px);
}

body {
    display: flex;
    flex-direction: column;
    height: 100vh;
}
</style>
EOF'

echo "Navigation header created successfully!"
echo "Now you need to manually replace the <header> section in dashboard.html with the content from /tmp/nav_header.html"
