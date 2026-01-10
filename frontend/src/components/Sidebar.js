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
  const [subscription, setSubscription] = useState(null);
  const { theme, toggleTheme, isDark } = useTheme();

  useEffect(() => {
    fetchCategories();
    fetchSubscription();
  }, []);

  const fetchCategories = async () => {
    try {
      const token = localStorage.getItem('token');
      // Use NEW detector-categories API with plan-based access
      const response = await axios.get(process.env.REACT_APP_API_URL + '/detector-categories/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      setUserPlan(response.data.current_plan || 'free');
      setCategories(response.data.categories || []);
    } catch (err) {
      console.error('Failed to fetch categories:', err);
    }
  };

  const fetchSubscription = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(process.env.REACT_APP_API_URL + '/subscriptions/current/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setSubscription(response.data);
    } catch (err) {
      console.error('Failed to fetch subscription:', err);
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

        {/* V3.0: Detector Categories with Icons */}
        <div className="px-4 mb-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className={`text-xs font-semibold uppercase tracking-wider ${
              isDark ? 'text-gray-500' : 'text-gray-400'
            }`}>
              Detector Categories
            </h3>
            {subscription && (
              <span className={`text-xs ${isDark ? 'text-gray-400' : 'text-gray-500'}`}>
                {subscription.scans_used_today || 0}/{subscription.plan.scans_per_day === -1 ? '∞' : subscription.plan.scans_per_day}
              </span>
            )}
          </div>
          <div className="space-y-1">
            {categories.map((category) => {
              const isLocked = !category.is_allowed;
              
              return (
                <Link
                  key={category.key}
                  to={isLocked ? '/subscription' : `/scan/${category.key}`}
                  className={`flex items-center justify-between px-3 py-2.5 rounded-lg transition font-medium ${
                    isActive(`/scan/${category.key}`)
                      ? 'bg-primary text-white'
                      : isLocked
                      ? isDark
                        ? 'text-gray-500 hover:bg-gray-800'
                        : 'text-gray-400 hover:bg-gray-100'
                      : isDark
                      ? 'text-gray-300 hover:bg-gray-800 hover:text-white'
                      : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-lg">{category.icon}</span>
                    <span className="text-sm">{category.name}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    {isLocked && (
                      <FiLock className="w-3.5 h-3.5" />
                    )}
                    {!isLocked && category.required_plan !== 'free' && (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-600 text-white uppercase font-semibold">
                        {category.required_plan === 'enterprise' ? 'ENT' : 'PRO'}
                      </span>
                    )}
                  </div>
                </Link>
              );
            })}
          </div>
          
          {/* Upgrade prompt for locked categories */}
          {userPlan === 'free' && categories.some(c => !c.is_allowed) && (
            <div className={`mt-3 p-3 rounded-lg ${
              isDark ? 'bg-gradient-to-r from-purple-900/30 to-blue-900/30 border border-purple-700/50' : 'bg-gradient-to-r from-purple-50 to-blue-50 border border-purple-200'
            }`}>
              <p className={`text-xs mb-2 ${isDark ? 'text-gray-300' : 'text-gray-700'}`}>
                Unlock {categories.filter(c => !c.is_allowed).length} more categories
              </p>
              <Link
                to="/subscription"
                className="block w-full text-center px-3 py-2 bg-gradient-to-r from-purple-600 to-blue-600 text-white text-xs font-semibold rounded-lg hover:from-purple-700 hover:to-blue-700 transition"
              >
                Upgrade to Pro
              </Link>
            </div>
          )}
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
