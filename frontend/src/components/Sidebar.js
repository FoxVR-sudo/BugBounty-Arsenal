import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import axios from 'axios';
import { 
  FiHome, FiList, FiBarChart2, 
  FiUser, FiLogOut, FiUsers, FiZap, FiLock, FiCreditCard, FiMoon, FiSun
} from 'react-icons/fi';
import { useTheme } from '../contexts/ThemeContext';

const Sidebar = () => {
  const location = useLocation();
  const [categories, setCategories] = useState([]);
  const [userPlan, setUserPlan] = useState('free');
  const { theme, toggleTheme, isDark } = useTheme();

  useEffect(() => {
    fetchCategories();
    fetchUserPlan();
  }, []);

  const fetchCategories = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8001/api/scan-categories/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      // Sort categories by plan level: free -> pro -> enterprise
      const planOrder = { 'free': 0, 'pro': 1, 'enterprise': 2 };
      const sorted = response.data.sort((a, b) => {
        const aLevel = planOrder[a.required_plan] || 0;
        const bLevel = planOrder[b.required_plan] || 0;
        return aLevel - bLevel;
      });
      
      setCategories(sorted);
    } catch (err) {
      console.error('Failed to fetch categories:', err);
    }
  };

  const fetchUserPlan = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8001/api/auth/me/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setUserPlan(response.data.current_plan?.toLowerCase() || 'free');
    } catch (err) {
      console.error('Failed to fetch user plan:', err);
    }
  };

  const isActive = (path) => location.pathname === path;

  const handleLogout = () => {
    localStorage.clear();
    window.location.href = '/';
  };

  return (
    <div className={`h-screen w-64 flex flex-col ${
      isDark ? 'bg-gray-900 text-white' : 'bg-white text-gray-900 border-r border-gray-200'
    }`}>
      {/* Logo */}
      <div className={`p-6 ${
        isDark ? 'border-b border-gray-800' : 'border-b border-gray-200'
      }`}>
        <h1 className={`text-2xl font-bold ${isDark ? 'text-white' : 'text-gray-900'}`}>BugBounty Arsenal</h1>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4">
        {/* Main Navigation */}
        <div className="px-4 mb-6">
          <Link
            to="/dashboard"
            className={`block px-4 py-3 rounded-lg transition font-medium ${
              isActive('/dashboard')
                ? 'bg-primary text-white'
                : isDark
                ? 'text-gray-300 hover:bg-gray-800 hover:text-white'
                : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
            }`}
          >
            Dashboard
          </Link>
        </div>

        {/* V3.0: Category-based Scanners */}
        <div className="px-4 mb-6">
          <h3 className={`text-xs font-semibold uppercase tracking-wider mb-2 ${
            isDark ? 'text-gray-500' : 'text-gray-400'
          }`}>
            Scan Categories
          </h3>
          <div className="space-y-1">
            {categories.map((category) => {
              const hasAccess = category.has_access;
              const isLocked = !hasAccess;
              
              return (
                <Link
                  key={category.id}
                  to={`/scan/${category.name}`}
                  className={`flex items-center justify-between px-4 py-2.5 rounded-lg transition font-medium ${
                    isActive(`/scan/${category.name}`)
                      ? 'bg-primary text-white'
                      : isLocked
                      ? isDark
                        ? 'text-gray-500 hover:bg-gray-800 cursor-pointer'
                        : 'text-gray-400 hover:bg-gray-100 cursor-pointer'
                      : isDark
                      ? 'text-gray-300 hover:bg-gray-800 hover:text-white'
                      : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
                  }`}
                >
                  <span className="text-sm">{category.display_name}</span>
                  <div className="flex items-center gap-2">
                    {isLocked && (
                      <span className="text-xs px-2 py-1 rounded bg-gray-700 text-gray-400 uppercase font-semibold">Locked</span>
                    )}
                    {!isLocked && category.required_plan !== 'free' && (
                      <span className="text-xs px-2 py-1 rounded bg-yellow-600 text-white uppercase font-semibold">
                        {category.required_plan === 'enterprise' ? 'ENT' : 'PRO'}
                      </span>
                    )}
                  </div>
                </Link>
              );
            })}
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
              className={`block px-4 py-3 rounded-lg transition font-medium ${
                isActive('/results')
                  ? 'bg-primary text-white'
                  : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              }`}
            >
              All Results
            </Link>
            <Link
              to="/analytics"
              className={`block px-4 py-3 rounded-lg transition font-medium ${
                isActive('/analytics')
                  ? 'bg-primary text-white'
                  : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              }`}
            >
              Analytics
            </Link>
          </div>
        </div>

        {/* User Section */}
        <div className="px-4">
          <h3 className={`text-xs font-semibold uppercase tracking-wider mb-2 ${
            isDark ? 'text-gray-500' : 'text-gray-400'
          }`}>
            Account
          </h3>
          <div className="space-y-1">
            <Link
              to="/subscription"
              className={`block px-4 py-3 rounded-lg transition font-medium ${
                isActive('/subscription')
                  ? 'bg-primary text-white'
                  : isDark
                  ? 'text-gray-300 hover:bg-gray-800 hover:text-white'
                  : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
              }`}
            >
              Subscription
            </Link>
            <Link
              to="/profile"
              className={`block px-4 py-3 rounded-lg transition font-medium ${
                isActive('/profile')
                  ? 'bg-primary text-white'
                  : isDark
                  ? 'text-gray-300 hover:bg-gray-800 hover:text-white'
                  : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
              }`}
            >
              Profile
            </Link>
            <Link
              to="/team"
              className={`flex items-center justify-between px-4 py-3 rounded-lg transition font-medium ${
                isActive('/team')
                  ? 'bg-primary text-white'
                  : isDark
                  ? 'text-gray-300 hover:bg-gray-800 hover:text-white'
                  : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
              }`}
            >
              <span>Team</span>
              <span className="text-xs px-2 py-1 rounded bg-blue-600 text-white uppercase font-semibold">Pro</span>
            </Link>
            <Link
              to="/integrations"
              className={`flex items-center justify-between px-4 py-3 rounded-lg transition font-medium ${
                isActive('/integrations')
                  ? 'bg-primary text-white'
                  : isDark
                  ? 'text-gray-300 hover:bg-gray-800 hover:text-white'
                  : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
              }`}
            >
              <span>Integrations</span>
              <span className="text-xs px-2 py-1 rounded bg-blue-600 text-white uppercase font-semibold">Pro</span>
            </Link>
          </div>
        </div>
      </nav>

      {/* Logout */}
      <div className={`p-4 space-y-2 ${
        isDark ? 'border-t border-gray-800' : 'border-t border-gray-200'
      }`}>
        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className={`flex items-center justify-center gap-2 px-4 py-3 rounded-lg transition w-full font-medium ${
            isDark
              ? 'text-gray-300 hover:bg-gray-800 hover:text-white'
              : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
          }`}
        >
          {isDark ? <FiSun size={20} /> : <FiMoon size={20} />}
          <span>{isDark ? 'Light Mode' : 'Dark Mode'}</span>
        </button>
        
        {/* Logout Button */}
        <button
          onClick={handleLogout}
          className="px-4 py-3 rounded-lg text-red-600 hover:bg-red-600 hover:text-white transition w-full text-center font-medium"
        >
          Logout
        </button>
      </div>
    </div>
  );
};

export default Sidebar;
