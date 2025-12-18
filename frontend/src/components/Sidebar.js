import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  FiHome, FiActivity, FiShield, FiDatabase, FiLock, 
  FiGlobe, FiCode, FiAlertTriangle, FiList, FiBarChart2, 
  FiUser, FiLogOut 
} from 'react-icons/fi';

const scanners = [
  { id: 'xss', name: 'XSS Scanner', icon: <FiCode />, path: '/scanner/xss' },
  { id: 'sql', name: 'SQL Injection', icon: <FiDatabase />, path: '/scanner/sql' },
  { id: 'ssrf', name: 'SSRF Scanner', icon: <FiGlobe />, path: '/scanner/ssrf' },
  { id: 'lfi', name: 'LFI Scanner', icon: <FiAlertTriangle />, path: '/scanner/lfi' },
  { id: 'auth', name: 'Auth Bypass', icon: <FiLock />, path: '/scanner/auth' },
  { id: 'jwt', name: 'JWT Scanner', icon: <FiShield />, path: '/scanner/jwt' },
  { id: 'cors', name: 'CORS Scanner', icon: <FiActivity />, path: '/scanner/cors' },
  { id: 'csrf', name: 'CSRF Scanner', icon: <FiShield />, path: '/scanner/csrf' },
  { id: 'xxe', name: 'XXE Scanner', icon: <FiCode />, path: '/scanner/xxe' },
  { id: 'idor', name: 'IDOR Scanner', icon: <FiAlertTriangle />, path: '/scanner/idor' },
  { id: 'graphql', name: 'GraphQL Scanner', icon: <FiDatabase />, path: '/scanner/graphql' },
  { id: 'api', name: 'API Security', icon: <FiActivity />, path: '/scanner/api' },
];

const Sidebar = () => {
  const location = useLocation();

  const isActive = (path) => location.pathname === path;

  const handleLogout = () => {
    localStorage.clear();
    window.location.href = '/';
  };

  return (
    <div className="h-screen w-64 bg-gray-900 text-white flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-gray-800">
        <h1 className="text-2xl font-bold text-white">BugBounty Arsenal</h1>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4">
        {/* Main Navigation */}
        <div className="px-4 mb-6">
          <Link
            to="/dashboard"
            className={`flex items-center gap-3 px-4 py-3 rounded-lg transition ${
              isActive('/dashboard')
                ? 'bg-primary text-white'
                : 'text-gray-300 hover:bg-gray-800'
            }`}
          >
            <FiHome size={20} />
            <span>Dashboard</span>
          </Link>
        </div>

        {/* Scanners Section */}
        <div className="px-4 mb-6">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
            Scanners
          </h3>
          <div className="space-y-1">
            {scanners.map((scanner) => (
              <Link
                key={scanner.id}
                to={scanner.path}
                className={`flex items-center gap-3 px-4 py-2 rounded-lg transition ${
                  isActive(scanner.path)
                    ? 'bg-primary text-white'
                    : 'text-gray-300 hover:bg-gray-800'
                }`}
              >
                {scanner.icon}
                <span className="text-sm">{scanner.name}</span>
              </Link>
            ))}
          </div>
        </div>

        {/* Results & Analytics */}
        <div className="px-4 mb-6">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
            Analysis
          </h3>
          <div className="space-y-1">
            <Link
              to="/results"
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition ${
                isActive('/results')
                  ? 'bg-primary text-white'
                  : 'text-gray-300 hover:bg-gray-800'
              }`}
            >
              <FiList size={20} />
              <span>All Results</span>
            </Link>
            <Link
              to="/analytics"
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition ${
                isActive('/analytics')
                  ? 'bg-primary text-white'
                  : 'text-gray-300 hover:bg-gray-800'
              }`}
            >
              <FiBarChart2 size={20} />
              <span>Analytics</span>
            </Link>
          </div>
        </div>

        {/* User Section */}
        <div className="px-4">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
            Account
          </h3>
          <div className="space-y-1">
            <Link
              to="/profile"
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition ${
                isActive('/profile')
                  ? 'bg-primary text-white'
                  : 'text-gray-300 hover:bg-gray-800'
              }`}
            >
              <FiUser size={20} />
              <span>Profile</span>
            </Link>
          </div>
        </div>
      </nav>

      {/* Logout */}
      <div className="p-4 border-t border-gray-800">
        <button
          onClick={handleLogout}
          className="flex items-center gap-3 px-4 py-3 rounded-lg text-gray-300 hover:bg-red-600 hover:text-white transition w-full"
        >
          <FiLogOut size={20} />
          <span>Logout</span>
        </button>
      </div>
    </div>
  );
};

export default Sidebar;
