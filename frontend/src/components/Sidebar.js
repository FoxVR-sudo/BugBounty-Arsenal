import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import axios from 'axios';
import { 
  FiHome, FiList, FiBarChart2, 
  FiUser, FiLogOut, FiUsers, FiZap, FiLock, FiCreditCard
} from 'react-icons/fi';

const Sidebar = () => {
  const location = useLocation();
  const [categories, setCategories] = useState([]);
  const [userPlan, setUserPlan] = useState('free');

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

        {/* V3.0: Category-based Scanners */}
        <div className="px-4 mb-6">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
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
                  className={`flex items-center gap-3 px-4 py-2 rounded-lg transition ${
                    isActive(`/scan/${category.name}`)
                      ? 'bg-primary text-white'
                      : isLocked
                      ? 'text-gray-500 hover:bg-gray-800 cursor-pointer'
                      : 'text-gray-300 hover:bg-gray-800'
                  }`}
                >
                  <span className="text-lg">{category.icon_emoji || category.icon || '🔍'}</span>
                  <span className="text-sm flex-1">{category.display_name}</span>
                  {isLocked && (
                    <FiLock size={14} className="text-gray-500" />
                  )}
                  {!isLocked && category.required_plan !== 'free' && (
                    <span className="text-xs px-2 py-0.5 rounded bg-yellow-600 text-white uppercase">
                      {category.required_plan === 'enterprise' ? 'ENT' : category.required_plan}
                    </span>
                  )}
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
              to="/subscription"
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition ${
                isActive('/subscription')
                  ? 'bg-primary text-white'
                  : 'text-gray-300 hover:bg-gray-800'
              }`}
            >
              <FiCreditCard size={20} />
              <span>Subscription</span>
            </Link>
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
            <Link
              to="/team"
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition ${
                isActive('/team')
                  ? 'bg-primary text-white'
                  : 'text-gray-300 hover:bg-gray-800'
              }`}
            >
              <FiUsers size={20} />
              <span>Team</span>
              <span className="text-xs px-2 py-0.5 rounded bg-blue-600 text-white uppercase">Pro</span>
            </Link>
            <Link
              to="/integrations"
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition ${
                isActive('/integrations')
                  ? 'bg-primary text-white'
                  : 'text-gray-300 hover:bg-gray-800'
              }`}
            >
              <FiZap size={20} />
              <span>Integrations</span>
              <span className="text-xs px-2 py-0.5 rounded bg-blue-600 text-white uppercase">Pro</span>
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
