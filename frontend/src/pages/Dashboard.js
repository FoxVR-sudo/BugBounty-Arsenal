import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from 'react-query';
import { scanService, statsService } from '../services/api';
import { FiPlus, FiDownload, FiEye, FiActivity, FiCheckCircle, FiClock, FiAlertTriangle } from 'react-icons/fi';
import { format } from 'date-fns';
import DashboardLayout from '../components/DashboardLayout';

const Dashboard = () => {
  const [showNewScan, setShowNewScan] = useState(false);
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('reconnaissance');

  // Fetch scans
  const { data: scans, isLoading, refetch } = useQuery('scans', () =>
    scanService.getAll().then((res) => res.data.results)
  );

  // Fetch stats
  const { data: stats } = useQuery('stats', () =>
    statsService.getOverview().then((res) => res.data)
  );

  const handleCreateScan = async (e) => {
    e.preventDefault();
    try {
      await scanService.create({ target, scan_type: scanType });
      setTarget('');
      setShowNewScan(false);
      refetch();
    } catch (error) {
      alert('Failed to create scan: ' + error.message);
    }
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

        {/* Actions */}
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold text-gray-900">Recent Scans</h2>
          <button
            onClick={() => setShowNewScan(true)}
            className="flex items-center gap-2 px-6 py-3 bg-primary text-white rounded-lg hover:bg-primary-600 transition"
          >
            <FiPlus /> New Scan
          </button>
        </div>

        {/* Daily Scans Counter */}
        <div className="bg-gradient-to-r from-primary to-blue-600 text-white rounded-lg shadow-lg p-6 mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold mb-2">Daily Scan Usage</h3>
              <p className="text-3xl font-bold">{stats?.daily_scans || 0} / 10</p>
              <p className="text-sm opacity-90 mt-1">Scans completed today</p>
            </div>
            <div className="bg-white bg-opacity-20 rounded-full p-4">
              <FiActivity size={48} />
            </div>
          </div>
          <div className="mt-4">
            <div className="w-full bg-white bg-opacity-30 rounded-full h-3">
              <div
                className="bg-white h-3 rounded-full transition-all duration-500"
                style={{ width: `${Math.min((stats?.daily_scans || 0) / 10 * 100, 100)}%` }}
              ></div>
            </div>
          </div>
        </div>

        {/* New Scan Modal */}
        {showNewScan && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-8 max-w-md w-full">
              <h3 className="text-2xl font-bold mb-6">Create New Scan</h3>
              <form onSubmit={handleCreateScan}>
                <div className="mb-4">
                  <label className="block text-gray-700 font-semibold mb-2">
                    Target URL
                  </label>
                  <input
                    type="url"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    required
                  />
                </div>
                <div className="mb-6">
                  <label className="block text-gray-700 font-semibold mb-2">
                    Scan Type
                  </label>
                  <select
                    value={scanType}
                    onChange={(e) => setScanType(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                  >
                    <option value="reconnaissance">Reconnaissance</option>
                    <option value="web_security">Web Security</option>
                    <option value="api_security">API Security</option>
                    <option value="mobile">Mobile</option>
                    <option value="comprehensive">Comprehensive</option>
                  </select>
                </div>
                <div className="flex gap-4">
                  <button
                    type="submit"
                    className="flex-1 px-6 py-3 bg-primary text-white rounded-lg hover:bg-primary-600 transition"
                  >
                    Start Scan
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowNewScan(false)}
                    className="flex-1 px-6 py-3 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition"
                  >
                    Cancel
                  </button>
                </div>
              </form>
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
                            to={`/scan/${scan.id}`}
                            className="p-2 text-blue-600 hover:bg-blue-50 rounded transition"
                            title="View Details"
                          >
                            <FiEye />
                          </Link>
                          {scan.status === 'completed' && (
                            <button
                              onClick={async () => {
                                try {
                                  const res = await scanService.downloadReport(scan.id);
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