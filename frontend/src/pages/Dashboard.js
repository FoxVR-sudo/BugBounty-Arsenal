import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from 'react-query';
import { scanService, statsService } from '../services/api';
import axios from 'axios';
import { FiPlus, FiDownload, FiEye, FiActivity, FiCheckCircle, FiClock, FiAlertTriangle, FiTrendingUp, FiPlay, FiCreditCard, FiArrowRight } from 'react-icons/fi';
import { format } from 'date-fns';
import DashboardLayout from '../components/DashboardLayout';
import CategoryScanForm from '../components/CategoryScanForm';
import { useTheme } from '../contexts/ThemeContext';

const Dashboard = () => {
  const { isDark } = useTheme();
  const [showNewScan, setShowNewScan] = useState(false);
  const [subscription, setSubscription] = useState(null);
  const [categoryStats, setCategoryStats] = useState([]);
  const [userInfo, setUserInfo] = useState(null);

  // Fetch scans
  const { data: scans, isLoading, refetch } = useQuery('scans', () =>
    scanService.getAll().then((res) => res.data.results)
  );

  // Fetch stats
  const { data: stats } = useQuery('stats', () =>
    statsService.getOverview().then((res) => res.data)
  );

  // Fetch subscription info
  useEffect(() => {
    fetchSubscription();
    fetchCategoryStats();
    fetchUserInfo();
  }, []);

  const fetchUserInfo = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8001/api/auth/me/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setUserInfo(response.data);
    } catch (err) {
      console.error('Failed to fetch user info:', err);
    }
  };

  const fetchSubscription = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8001/api/subscriptions/current/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setSubscription(response.data);
    } catch (err) {
      console.error('Failed to fetch subscription:', err);
    }
  };

  const fetchCategoryStats = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8001/api/scan-categories/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setCategoryStats(response.data);
    } catch (err) {
      console.error('Failed to fetch category stats:', err);
    }
  };

  const handleScanCreated = () => {
    setShowNewScan(false);
    refetch();
  };

  return (
    <DashboardLayout>
      <div className="p-8">
        {/* User Info Card - Tree Format */}
        {userInfo && (
          <div className={`rounded-xl shadow-xl p-6 mb-8 transition-all duration-300 ${
            isDark 
              ? 'bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 hover:bg-gray-700/50 hover:shadow-2xl'
              : 'bg-white/90 backdrop-blur-lg border border-gray-200/50 hover:bg-white hover:shadow-2xl'
          }`}>
            <div className="flex items-center justify-between">
              <div className="font-mono text-sm space-y-1">
                <div className="flex items-center">
                  <span className={isDark ? 'text-gray-400 w-32' : 'text-gray-600 w-32'}>├─ username:</span>
                  <span className={`font-semibold ${isDark ? 'text-white' : 'text-gray-900'}`}>
                    {(userInfo.full_name && userInfo.full_name.trim()) ? userInfo.full_name : userInfo.email.split('@')[0].toUpperCase()}
                  </span>
                </div>
                <div className="flex items-center">
                  <span className={isDark ? 'text-gray-400 w-32' : 'text-gray-600 w-32'}>├─ Plan:</span>
                  <span className={`font-semibold ${isDark ? 'text-white' : 'text-gray-900'}`}>{userInfo.current_plan || 'Loading...'}</span>
                </div>
                <div className="flex items-center">
                  <span className={isDark ? 'text-gray-400 w-32' : 'text-gray-600 w-32'}>├─ email:</span>
                  <span className={`font-semibold ${isDark ? 'text-white' : 'text-gray-900'}`}>{userInfo.email}</span>
                </div>
                {userInfo.phone && userInfo.phone.trim() && (
                  <div className="flex items-center">
                    <span className={isDark ? 'text-gray-400 w-32' : 'text-gray-600 w-32'}>├─ phone:</span>
                    <span className={`font-semibold ${isDark ? 'text-white' : 'text-gray-900'}`}>{userInfo.phone}</span>
                  </div>
                )}
                {userInfo.company_name && userInfo.company_name.trim() && (
                  <div className="flex items-center">
                    <span className={isDark ? 'text-gray-400 w-32' : 'text-gray-600 w-32'}>├─ company:</span>
                    <span className={`font-semibold ${isDark ? 'text-white' : 'text-gray-900'}`}>{userInfo.company_name}</span>
                  </div>
                )}
                <div className="flex items-center">
                  <span className={isDark ? 'text-gray-400 w-32' : 'text-gray-600 w-32'}>└─ IP:</span>
                  <span className={`font-semibold ${isDark ? 'text-white' : 'text-gray-900'}`}>{userInfo.client_ip || 'N/A'}</span>
                </div>
              </div>
              
              {subscription && (
                <div className="flex flex-col items-end gap-2">
                  <Link
                    to="/subscription"
                    className="inline-flex items-center gap-2 px-6 py-3 bg-primary text-white rounded-lg font-semibold hover:bg-opacity-90 transition"
                  >
                    <FiCreditCard size={18} />
                    Manage Subscription
                    <FiArrowRight size={16} />
                  </Link>
                  {subscription.plan?.price === 0 && (
                    <p className="text-xs text-gray-600 text-right max-w-xs">
                      🚀 Upgrade for unlimited scans
                    </p>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <StatCard
            title="Total Scans"
            value={stats?.total_scans || 0}
            icon={<FiActivity />}
            color="blue"
          />
          <StatCard
            title="Active"
            value={stats?.running_scans || 0}
            icon={<FiClock />}
            color="yellow"
          />
          <StatCard
            title="Completed"
            value={stats?.completed_scans || 0}
            icon={<FiCheckCircle />}
            color="green"
          />
          <StatCard
            title="Vulnerabilities"
            value={stats?.total_vulnerabilities || 0}
            icon={<FiAlertTriangle />}
            color="red"
          />
        </div>

        {/* V3.0: Subscription Usage */}
        {subscription && subscription.plan && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            {/* Daily Usage */}
            <div className={`rounded-xl shadow-xl p-6 border hover:shadow-2xl transition-all duration-300 ${
              isDark
                ? 'bg-gradient-to-r from-gray-700 to-gray-800 text-white border-gray-600/50'
                : 'bg-gradient-to-r from-blue-50 to-blue-100 text-gray-900 border-blue-200/50'
            }`}>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className={`text-lg font-semibold mb-2 ${isDark ? 'text-white' : 'text-gray-900'}`}>Daily Scan Usage</h3>
                  <p className={`text-3xl font-bold ${isDark ? 'text-white' : 'text-gray-900'}`}>
                    {subscription.scans_used_today || 0} / {subscription.plan?.daily_scan_limit || 3}
                  </p>
                  <p className={`text-sm mt-1 ${isDark ? 'opacity-90' : 'text-gray-700'}`}>
                    {(subscription.plan?.daily_scan_limit || 3) - (subscription.scans_used_today || 0)} scans remaining today
                  </p>
                </div>
                <div className={`rounded-full p-4 ${
                  isDark ? 'bg-white bg-opacity-20' : 'bg-blue-500 bg-opacity-20'
                }`}>
                  <FiActivity size={40} className={isDark ? 'text-white' : 'text-blue-600'} />
                </div>
              </div>
              <div className={`w-full rounded-full h-3 ${
                isDark ? 'bg-white bg-opacity-30' : 'bg-blue-200'
              }`}>
                <div
                  className="bg-primary h-3 rounded-full transition-all duration-500"
                  style={{ 
                    width: `${Math.min((subscription.scans_used_today || 0) / (subscription.plan?.daily_scan_limit || 3) * 100, 100)}%` 
                  }}
                ></div>
              </div>
            </div>

            {/* Monthly Usage */}
            <div className={`rounded-xl shadow-xl p-6 border hover:shadow-2xl transition-all duration-300 ${
              isDark
                ? 'bg-gradient-to-r from-gray-800 to-gray-900 text-white border-gray-600/50'
                : 'bg-gradient-to-r from-purple-50 to-purple-100 text-gray-900 border-purple-200/50'
            }`}>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className={`text-lg font-semibold mb-2 ${isDark ? 'text-white' : 'text-gray-900'}`}>Monthly Scan Usage</h3>
                  <p className={`text-3xl font-bold ${isDark ? 'text-white' : 'text-gray-900'}`}>
                    {subscription.scans_used_this_month || 0} / {subscription.plan?.monthly_scan_limit || 30}
                  </p>
                  <p className={`text-sm mt-1 ${isDark ? 'opacity-90' : 'text-gray-700'}`}>
                    {(subscription.plan?.monthly_scan_limit || 30) - (subscription.scans_used_this_month || 0)} scans remaining this month
                  </p>
                </div>
                <div className={`rounded-full p-4 ${
                  isDark ? 'bg-white bg-opacity-20' : 'bg-purple-500 bg-opacity-20'
                }`}>
                  <FiTrendingUp size={40} className={isDark ? 'text-white' : 'text-purple-600'} />
                </div>
              </div>
              <div className={`w-full rounded-full h-3 ${
                isDark ? 'bg-white bg-opacity-30' : 'bg-purple-200'
              }`}>
                <div
                  className="bg-primary h-3 rounded-full transition-all duration-500"
                  style={{ 
                    width: `${Math.min((subscription.scans_used_this_month || 0) / (subscription.plan?.monthly_scan_limit || 30) * 100, 100)}%` 
                  }}
                ></div>
              </div>
            </div>
          </div>
        )}

        {/* Scanner Detector Information */}
        {categoryStats && categoryStats.length > 0 && (
          <div className="mb-8">
            <h3 className={`text-xl font-bold mb-4 ${isDark ? 'text-white' : 'text-gray-900'}`}>Scanner Capabilities</h3>
            <div className={`rounded-xl shadow-xl p-6 transition-all duration-300 ${
              isDark
                ? 'bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 hover:bg-gray-700/50 hover:shadow-2xl'
                : 'bg-white/90 backdrop-blur-lg border border-gray-200/50 hover:bg-white hover:shadow-2xl'
            }`}>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {categoryStats.map((category) => (
                  <div key={category.id} className="border-l-4 border-primary pl-4">
                    <div className="flex items-center gap-2 mb-2">
                      <h4 className={`font-bold ${isDark ? 'text-white' : 'text-gray-900'}`}>{category.display_name}</h4>
                      {category.required_plan && category.required_plan !== 'free' && (
                        <span className="text-xs px-2 py-0.5 bg-purple-100 text-purple-700 rounded-full uppercase">
                          {category.required_plan}
                        </span>
                      )}
                    </div>
                    <p className={`text-sm mb-2 ${isDark ? 'text-gray-300' : 'text-gray-600'}`}>{category.description}</p>
                    <div className={`text-xs ${isDark ? 'text-gray-400' : 'text-gray-500'}`}>
                      📦 {category.detector_count || 'Multiple'} detectors
                      {category.dangerous_detector_count > 0 && (
                        <span className="ml-2 text-red-600">
                          🔴 {category.dangerous_detector_count} dangerous
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Recent Scans */}
        <div className="flex justify-between items-center mb-6">
          <h2 className={`text-2xl font-bold ${isDark ? 'text-white' : 'text-gray-900'}`}>Recent Scans</h2>
          {subscription && subscription.scans_used_today >= (subscription.plan?.daily_scan_limit || 3) ? (
            <div className="flex items-center gap-3">
              <span className={`text-sm font-medium ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>
                Daily limit reached
              </span>
              <Link
                to="/subscription"
                className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-primary to-blue-600 text-white rounded-lg hover:opacity-90 transition font-semibold"
              >
                <FiCreditCard /> Upgrade to Pro
              </Link>
            </div>
          ) : (
            <button
              onClick={() => setShowNewScan(true)}
              className="flex items-center gap-2 px-6 py-3 bg-primary text-white rounded-lg hover:bg-primary-600 transition"
            >
              <FiPlus /> New Scan
            </button>
          )}
        </div>

        {/* V3.0: New Scan Modal with Category Selection */}
        {showNewScan && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            {subscription && subscription.scans_used_today >= (subscription.plan?.daily_scan_limit || 3) ? (
              <div className={`rounded-2xl shadow-2xl border max-w-lg w-full p-8 text-center ${
                isDark
                  ? 'bg-gray-800/95 backdrop-blur-xl border-gray-700/50'
                  : 'bg-white/95 backdrop-blur-xl border-gray-200/50'
              }`}>
                <div className="mb-6">
                  <div className="mx-auto w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mb-4">
                    <FiAlertTriangle className="text-red-600" size={32} />
                  </div>
                  <h3 className={`text-2xl font-bold mb-2 ${isDark ? 'text-white' : 'text-gray-900'}`}>
                    Daily Scan Limit Reached
                  </h3>
                  <p className={`text-sm ${isDark ? 'text-gray-300' : 'text-gray-600'}`}>
                    You've used all {subscription.plan?.daily_scan_limit || 3} scans for today on the {subscription.plan?.display_name || 'Free'} plan.
                  </p>
                </div>
                <div className={`rounded-lg p-4 mb-6 ${
                  isDark ? 'bg-blue-900/30 border border-blue-700/50' : 'bg-blue-50 border border-blue-200'
                }`}>
                  <p className={`text-sm font-semibold mb-2 ${isDark ? 'text-blue-300' : 'text-blue-900'}`}>
                    Upgrade to Pro Plan and get:
                  </p>
                  <ul className={`text-sm text-left space-y-1 ${isDark ? 'text-blue-200' : 'text-blue-800'}`}>
                    <li>✓ 50 scans per day</li>
                    <li>✓ 1,000 scans per month</li>
                    <li>✓ Advanced scanners</li>
                    <li>✓ Priority support</li>
                  </ul>
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={() => setShowNewScan(false)}
                    className={`flex-1 px-6 py-3 rounded-lg font-semibold transition ${
                      isDark
                        ? 'bg-gray-700 text-white hover:bg-gray-600'
                        : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                    }`}
                  >
                    Close
                  </button>
                  <Link
                    to="/subscription"
                    className="flex-1 px-6 py-3 bg-gradient-to-r from-primary to-blue-600 text-white rounded-lg font-semibold hover:opacity-90 transition text-center"
                  >
                    Upgrade Now
                  </Link>
                </div>
              </div>
            ) : (
              <div className={`rounded-2xl shadow-2xl border max-w-4xl w-full max-h-[90vh] overflow-y-auto ${
                isDark
                  ? 'bg-gray-800/95 backdrop-blur-xl border-gray-700/50'
                  : 'bg-white/95 backdrop-blur-xl border-gray-200/50'
              }`}>
                <div className={`sticky top-0 border-b p-6 flex items-center justify-between ${
                  isDark
                    ? 'bg-gray-800 border-gray-700'
                    : 'bg-white border-gray-200'
                }`}>
                  <h3 className={`text-2xl font-bold ${isDark ? 'text-white' : 'text-gray-900'}`}>Create New Scan</h3>
                  <button
                    onClick={() => setShowNewScan(false)}
                    className={`text-2xl font-bold transition ${
                      isDark ? 'text-gray-400 hover:text-gray-300' : 'text-gray-400 hover:text-gray-600'
                    }`}
                  >
                    ×
                  </button>
                </div>
                <div className="p-6">
                  <CategoryScanForm onScanCreated={handleScanCreated} />
                </div>
              </div>
            )}
          </div>
        )}

        {/* Scans Table */}
        <div className={`rounded-xl shadow-xl overflow-hidden transition-all duration-300 ${
          isDark
            ? 'bg-gray-800/50 backdrop-blur-lg border border-gray-700/50'
            : 'bg-white/90 backdrop-blur-lg border border-gray-200/50'
        }`}>
          {isLoading ? (
            <div className={`p-12 text-center ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>Loading scans...</div>
          ) : scans && scans.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className={isDark ? 'bg-gray-900/50 border-b border-gray-700' : 'bg-gray-100/80 border-b border-gray-200'}>
                  <tr>
                    <th className={`px-6 py-4 text-left text-sm font-semibold ${isDark ? 'text-white' : 'text-gray-900'}`}>
                      Target
                    </th>
                    <th className={`px-6 py-4 text-left text-sm font-semibold ${isDark ? 'text-white' : 'text-gray-900'}`}>
                      Type
                    </th>
                    <th className={`px-6 py-4 text-left text-sm font-semibold ${isDark ? 'text-white' : 'text-gray-900'}`}>
                      Status
                    </th>
                    <th className={`px-6 py-4 text-left text-sm font-semibold ${isDark ? 'text-white' : 'text-gray-900'}`}>
                      Findings
                    </th>
                    <th className={`px-6 py-4 text-left text-sm font-semibold ${isDark ? 'text-white' : 'text-gray-900'}`}>
                      Created
                    </th>
                    <th className={`px-6 py-4 text-left text-sm font-semibold ${isDark ? 'text-white' : 'text-gray-900'}`}>
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className={isDark ? 'divide-y divide-gray-700' : 'divide-y divide-gray-200'}>
                  {scans.map((scan) => (
                    <tr key={scan.id} className={`transition-all duration-200 ${
                      isDark ? 'hover:bg-gray-700/50' : 'hover:bg-gray-50'
                    }`}>
                      <td className="px-6 py-4">
                        <div className={`text-sm font-medium ${isDark ? 'text-white' : 'text-gray-900'}`}>
                          {scan.target}
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`text-sm ${isDark ? 'text-gray-300' : 'text-gray-600'}`}>
                          {scan.scan_category || scan.scan_type || 'General'}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <StatusBadge status={scan.status} />
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          {scan.vulnerabilities_found > 0 ? (
                            <>
                              <FiAlertTriangle className="text-red-400" />
                              <span className="text-sm font-semibold text-red-400">
                                {scan.vulnerabilities_found}
                              </span>
                            </>
                          ) : (
                            <span className={`text-sm ${isDark ? 'text-gray-400' : 'text-gray-500'}`}>0</span>
                          )}
                        </div>
                      </td>
                      <td className={`px-6 py-4 text-sm ${isDark ? 'text-gray-300' : 'text-gray-600'}`}>
                        {format(new Date(scan.created_at), 'MMM dd, yyyy HH:mm')}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex gap-2">
                          <Link
                            to={`/scan/details/${scan.id}`}
                            className={`p-2 rounded transition ${
                              isDark
                                ? 'text-blue-400 hover:bg-blue-900/50'
                                : 'text-blue-600 hover:bg-blue-50'
                            }`}
                            title="View Details"
                          >
                            <FiEye />
                          </Link>
                          {scan.status === 'completed' && (
                            <button
                              onClick={async () => {
                                try {
                                  const res = await scanService.downloadJSON(scan.id);
                                  const url = window.URL.createObjectURL(new Blob([res.data]));
                                  const link = document.createElement('a');
                                  link.href = url;
                                  link.setAttribute('download', `scan-${scan.id}-report.json`);
                                  document.body.appendChild(link);
                                  link.click();
                                  link.remove();
                                } catch (error) {
                                  alert('Failed to download report');
                                }
                              }}
                              className={`p-2 rounded transition ${
                                isDark
                                  ? 'text-green-400 hover:bg-green-900/50'
                                  : 'text-green-600 hover:bg-green-50'
                              }`}
                              title="Download Report"
                            >
                              <FiDownload />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-12 text-center">
              <p className={`mb-4 ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>No scans yet</p>
              <button
                onClick={() => setShowNewScan(true)}
                className="px-6 py-3 bg-primary text-white rounded-lg hover:bg-primary-600 transition"
              >
                Create Your First Scan
              </button>
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
};

const StatCard = ({ title, value, icon, color }) => {
  const { isDark } = useTheme();
  
  const darkColors = {
    blue: 'bg-blue-900/50 text-blue-400',
    yellow: 'bg-yellow-900/50 text-yellow-400',
    green: 'bg-green-900/50 text-green-400',
    red: 'bg-red-900/50 text-red-400',
  };
  
  const lightColors = {
    blue: 'bg-blue-100 text-blue-600',
    yellow: 'bg-yellow-100 text-yellow-600',
    green: 'bg-green-100 text-green-600',
    red: 'bg-red-100 text-red-600',
  };
  
  const colors = isDark ? darkColors : lightColors;

  return (
    <div className={`p-6 rounded-xl shadow-xl transition-all duration-300 ${
      isDark
        ? 'bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 hover:bg-gray-700/50 hover:shadow-2xl'
        : 'bg-white/90 backdrop-blur-lg border border-gray-200/50 hover:bg-white hover:shadow-2xl'
    }`}>
      <div className="flex items-center justify-between">
        <div>
          <p className={`text-sm mb-1 ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>{title}</p>
          <p className={`text-3xl font-bold ${isDark ? 'text-white' : 'text-gray-900'}`}>{value}</p>
        </div>
        <div className={`p-4 rounded-lg ${colors[color]}`}>{icon}</div>
      </div>
    </div>
  );
};

const StatusBadge = ({ status }) => {
  const styles = {
    pending: 'bg-gray-100 text-gray-700',
    running: 'bg-yellow-100 text-yellow-700',
    completed: 'bg-green-100 text-green-700',
    failed: 'bg-red-100 text-red-700',
  };

  return (
    <span className={`px-3 py-1 rounded-full text-xs font-semibold ${styles[status]}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
};

export default Dashboard;