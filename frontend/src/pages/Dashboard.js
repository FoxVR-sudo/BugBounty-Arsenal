import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from 'react-query';
import { scanService, statsService } from '../services/api';
import axios from 'axios';
import { FiPlus, FiDownload, FiEye, FiActivity, FiCheckCircle, FiClock, FiAlertTriangle, FiTrendingUp, FiPlay } from 'react-icons/fi';
import { format } from 'date-fns';
import DashboardLayout from '../components/DashboardLayout';
import CategoryScanForm from '../components/CategoryScanForm';

const Dashboard = () => {
  const [showNewScan, setShowNewScan] = useState(false);
  const [subscription, setSubscription] = useState(null);
  const [categoryStats, setCategoryStats] = useState([]);

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
  }, []);

  const fetchSubscription = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8001/api/subscriptions/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.data.results && response.data.results[0]) {
        setSubscription(response.data.results[0]);
      }
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
        {subscription && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            {/* Daily Usage */}
            <div className="bg-gradient-to-r from-primary to-blue-600 text-white rounded-lg shadow-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold mb-2">Daily Scan Usage</h3>
                  <p className="text-3xl font-bold">
                    {subscription.scans_used_today || 0} / {subscription.plan.daily_scan_limit}
                  </p>
                  <p className="text-sm opacity-90 mt-1">
                    {subscription.plan.daily_scan_limit - (subscription.scans_used_today || 0)} scans remaining today
                  </p>
                </div>
                <div className="bg-white bg-opacity-20 rounded-full p-4">
                  <FiActivity size={40} />
                </div>
              </div>
              <div className="w-full bg-white bg-opacity-30 rounded-full h-3">
                <div
                  className="bg-white h-3 rounded-full transition-all duration-500"
                  style={{ 
                    width: `${Math.min((subscription.scans_used_today || 0) / subscription.plan.daily_scan_limit * 100, 100)}%` 
                  }}
                ></div>
              </div>
            </div>

            {/* Monthly Usage */}
            <div className="bg-gradient-to-r from-purple-600 to-pink-600 text-white rounded-lg shadow-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold mb-2">Monthly Scan Usage</h3>
                  <p className="text-3xl font-bold">
                    {subscription.scans_used_this_month || 0} / {subscription.plan.monthly_scan_limit}
                  </p>
                  <p className="text-sm opacity-90 mt-1">
                    {subscription.plan.monthly_scan_limit - (subscription.scans_used_this_month || 0)} scans remaining this month
                  </p>
                </div>
                <div className="bg-white bg-opacity-20 rounded-full p-4">
                  <FiTrendingUp size={40} />
                </div>
              </div>
              <div className="w-full bg-white bg-opacity-30 rounded-full h-3">
                <div
                  className="bg-white h-3 rounded-full transition-all duration-500"
                  style={{ 
                    width: `${Math.min((subscription.scans_used_this_month || 0) / subscription.plan.monthly_scan_limit * 100, 100)}%` 
                  }}
                ></div>
              </div>
            </div>
          </div>
        )}

        {/* V3.0: Available Categories - Links to Real Scanner Pages */}
        {categoryStats && categoryStats.length > 0 && (
          <div className="mb-8">
            <h3 className="text-xl font-bold text-gray-900 mb-4">Available Scan Categories</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {categoryStats.map((category) => (
                <Link
                  key={category.id}
                  to={`/scan/${category.name}`}
                  className="bg-white rounded-lg shadow p-6 hover:shadow-lg transition border-2 border-transparent hover:border-primary cursor-pointer"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <h4 className="text-lg font-bold text-gray-900 mb-1">
                        {category.icon_emoji || category.icon} {category.display_name}
                      </h4>
                      <p className="text-sm text-gray-600">{category.description}</p>
                    </div>
                    {category.required_plan !== 'free' && (
                      <span className="text-xs px-2 py-1 rounded bg-blue-100 text-blue-700 uppercase font-semibold">
                        {category.required_plan}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-4 text-sm text-gray-500 mb-3">
                    <span>{category.detector_count} detectors</span>
                    {category.dangerous_detector_count > 0 && (
                      <span className="text-red-600">
                        🔴 {category.dangerous_detector_count} dangerous
                      </span>
                    )}
                  </div>
                  <div className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg text-sm font-semibold hover:bg-primary-600 transition">
                    <FiPlay /> Start {category.display_name} Scan
                  </div>
                </Link>
              ))}
            </div>
          </div>
        )}

        {/* Recent Scans */}
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold text-gray-900">Recent Scans</h2>
          <button
            onClick={() => setShowNewScan(true)}
            className="flex items-center gap-2 px-6 py-3 bg-primary text-white rounded-lg hover:bg-primary-600 transition"
          >
            <FiPlus /> New Scan
          </button>
        </div>

        {/* V3.0: New Scan Modal with Category Selection */}
        {showNewScan && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto">
              <div className="sticky top-0 bg-white border-b border-gray-200 p-6 flex items-center justify-between">
                <h3 className="text-2xl font-bold">Create New Scan</h3>
                <button
                  onClick={() => setShowNewScan(false)}
                  className="text-gray-400 hover:text-gray-600 text-2xl font-bold"
                >
                  ×
                </button>
              </div>
              <div className="p-6">
                <CategoryScanForm onScanCreated={handleScanCreated} />
              </div>
            </div>
          </div>
        )}

        {/* Scans Table */}
        <div className="bg-white rounded-lg shadow overflow-hidden">
          {isLoading ? (
            <div className="p-12 text-center text-gray-500">Loading scans...</div>
          ) : scans && scans.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 border-b">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900">
                      Target
                    </th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900">
                      Type
                    </th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900">
                      Status
                    </th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900">
                      Findings
                    </th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900">
                      Created
                    </th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {scans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4">
                        <div className="text-sm font-medium text-gray-900">
                          {scan.target}
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-sm text-gray-600">
                          {scan.scan_type}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <StatusBadge status={scan.status} />
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          {scan.vulnerabilities_found > 0 ? (
                            <>
                              <FiAlertTriangle className="text-red-500" />
                              <span className="text-sm font-semibold text-red-600">
                                {scan.vulnerabilities_found}
                              </span>
                            </>
                          ) : (
                            <span className="text-sm text-gray-500">0</span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600">
                        {format(new Date(scan.created_at), 'MMM dd, yyyy HH:mm')}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex gap-2">
                          <Link
                            to={`/scan/details/${scan.id}`}
                            className="p-2 text-blue-600 hover:bg-blue-50 rounded transition"
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
                              className="p-2 text-green-600 hover:bg-green-50 rounded transition"
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
              <p className="text-gray-500 mb-4">No scans yet</p>
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
  const colors = {
    blue: 'bg-blue-100 text-blue-600',
    yellow: 'bg-yellow-100 text-yellow-600',
    green: 'bg-green-100 text-green-600',
    red: 'bg-red-100 text-red-600',
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600 mb-1">{title}</p>
          <p className="text-3xl font-bold text-gray-900">{value}</p>
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