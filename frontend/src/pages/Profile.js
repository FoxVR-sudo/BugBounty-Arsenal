import React, { useState } from 'react';
import { useQuery } from 'react-query';
import { Link } from 'react-router-dom';
import axios from 'axios';
import { format } from 'date-fns';
import { statsService } from '../services/api';
import { FiUser, FiMail, FiCalendar, FiActivity, FiShield, FiAward, FiAlertTriangle, FiCheckCircle, FiDownload } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';

const Profile = () => {
  const [scanFilter, setScanFilter] = useState('all'); // all, completed, failed, running

  const { data: profile } = useQuery('profile', () =>
    statsService.getOverview().then(res => res.data)
  );

  const { data: scansData } = useQuery('profileScans', async () => {
    const token = localStorage.getItem('token');
    const response = await axios.get('http://localhost:8001/api/scans/', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.data;
  });

  const scans = scansData?.results || [];
  
  const filteredScans = scans.filter(scan => {
    if (scanFilter === 'all') return true;
    return scan.status === scanFilter;
  });

  const userEmail = localStorage.getItem('user') || 'admin@bugbountyarsenal.com';

  return (
    <DashboardLayout>
      <div className="p-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Profile</h1>
          <p className="text-gray-600 mt-2">Manage your account and view your statistics</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Profile Info */}
          <div className="lg:col-span-2 space-y-6">
            {/* Basic Info */}
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-6">Account Information</h2>
              <div className="space-y-4">
                <div className="flex items-center gap-4">
                  <div className="bg-primary text-white rounded-full w-20 h-20 flex items-center justify-center text-3xl font-bold">
                    {userEmail.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <h3 className="text-xl font-semibold text-gray-900">{userEmail.split('@')[0]}</h3>
                    <p className="text-gray-600 flex items-center gap-2">
                      <FiMail size={16} />
                      {userEmail}
                    </p>
                  </div>
                </div>

                <div className="border-t pt-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-600 flex items-center gap-2">
                      <FiCalendar size={16} />
                      Member Since
                    </span>
                    <span className="font-semibold">December 2025</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-600 flex items-center gap-2">
                      <FiShield size={16} />
                      Account Status
                    </span>
                    <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm font-semibold">
                      Active
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Monthly Stats */}
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-6">Monthly Statistics</h2>
              <div className="grid grid-cols-2 gap-6">
                <StatBox
                  label="Scans This Month"
                  value={profile?.monthly_scans || 0}
                  icon={<FiActivity />}
                  color="blue"
                />
                <StatBox
                  label="Vulnerabilities Found"
                  value={profile?.monthly_vulnerabilities || 0}
                  icon={<FiShield />}
                  color="red"
                />
                <StatBox
                  label="Critical Issues"
                  value={profile?.monthly_critical || 0}
                  icon={<FiAward />}
                  color="orange"
                />
                <StatBox
                  label="Scans Completed"
                  value={profile?.monthly_completed || 0}
                  icon={<FiActivity />}
                  color="green"
                />
              </div>
            </div>

            {/* Activity Log */}
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-4">Scan History</h2>
              
              {/* Filter Tabs */}
              <div className="flex gap-2 mb-4 border-b">
                <button
                  onClick={() => setScanFilter('all')}
                  className={`px-4 py-2 font-semibold transition ${
                    scanFilter === 'all'
                      ? 'text-primary border-b-2 border-primary'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  All ({scans.length})
                </button>
                <button
                  onClick={() => setScanFilter('completed')}
                  className={`px-4 py-2 font-semibold transition ${
                    scanFilter === 'completed'
                      ? 'text-primary border-b-2 border-primary'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  Completed ({scans.filter(s => s.status === 'completed').length})
                </button>
                <button
                  onClick={() => setScanFilter('running')}
                  className={`px-4 py-2 font-semibold transition ${
                    scanFilter === 'running'
                      ? 'text-primary border-b-2 border-primary'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  Running ({scans.filter(s => s.status === 'running').length})
                </button>
                <button
                  onClick={() => setScanFilter('failed')}
                  className={`px-4 py-2 font-semibold transition ${
                    scanFilter === 'failed'
                      ? 'text-primary border-b-2 border-primary'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  Failed ({scans.filter(s => s.status === 'failed').length})
                </button>
              </div>

              {/* Scans Table */}
              {filteredScans.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  No scans found
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left py-3 px-4 text-sm font-semibold text-gray-900">Target</th>
                        <th className="text-left py-3 px-4 text-sm font-semibold text-gray-900">Type</th>
                        <th className="text-left py-3 px-4 text-sm font-semibold text-gray-900">Status</th>
                        <th className="text-left py-3 px-4 text-sm font-semibold text-gray-900">Findings</th>
                        <th className="text-left py-3 px-4 text-sm font-semibold text-gray-900">Date</th>
                        <th className="text-left py-3 px-4 text-sm font-semibold text-gray-900">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredScans.map((scan) => (
                        <tr key={scan.id} className="border-b hover:bg-gray-50">
                          <td className="py-3 px-4 text-sm text-gray-900">{scan.target}</td>
                          <td className="py-3 px-4 text-sm text-gray-600">{scan.scan_category || scan.scan_type || 'General'}</td>
                          <td className="py-3 px-4">
                            <StatusBadge status={scan.status} />
                          </td>
                          <td className="py-3 px-4">
                            {scan.vulnerabilities_found > 0 ? (
                              <span className="flex items-center gap-1 text-red-600 font-semibold text-sm">
                                <FiAlertTriangle size={14} />
                                {scan.vulnerabilities_found}
                              </span>
                            ) : (
                              <span className="text-sm text-gray-500">0</span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-sm text-gray-600">
                            {format(new Date(scan.created_at), 'MMM dd, HH:mm')}
                          </td>
                          <td className="py-3 px-4">
                            <Link
                              to={`/scan/details/${scan.id}`}
                              className="text-primary hover:text-primary-600 text-sm font-semibold"
                            >
                              View
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              
              {/* Export Button */}
              {scans.length > 0 && (
                <div className="mt-4 flex justify-end">
                  <button className="flex items-center gap-2 px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg transition">
                    <FiDownload size={16} />
                    Export History
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Sidebar - Daily Stats */}
          <div className="lg:col-span-1">
            <div className="bg-white rounded-lg shadow p-6 sticky top-8">
              <h2 className="text-xl font-semibold mb-6">Today's Activity</h2>
              <div className="space-y-6">
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-gray-600">Daily Scans</span>
                    <span className="text-2xl font-bold text-primary">{profile?.daily_scans || 0}</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-primary h-2 rounded-full"
                      style={{ width: `${Math.min((profile?.daily_scans || 0) / 10 * 100, 100)}%` }}
                    ></div>
                  </div>
                  <p className="text-xs text-gray-500 mt-1">Limit: 10 per day</p>
                </div>

                <div className="border-t pt-4">
                  <h3 className="font-semibold mb-3">Quick Stats</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-gray-600 text-sm">Running Scans</span>
                      <span className="font-semibold">{profile?.running_scans || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600 text-sm">Queued</span>
                      <span className="font-semibold">{profile?.queued_scans || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600 text-sm">Completed Today</span>
                      <span className="font-semibold">{profile?.completed_today || 0}</span>
                    </div>
                  </div>
                </div>

                <div className="border-t pt-4">
                  <button className="w-full bg-primary text-white py-2 rounded-lg hover:bg-primary-600 transition">
                    Upgrade Plan
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

const StatusBadge = ({ status }) => {
  const styles = {
    pending: 'bg-yellow-100 text-yellow-800',
    running: 'bg-blue-100 text-blue-800',
    completed: 'bg-green-100 text-green-800',
    failed: 'bg-red-100 text-red-800',
  };

  return (
    <span className={`px-2 py-1 rounded-full text-xs font-semibold ${styles[status] || 'bg-gray-100 text-gray-800'}`}>
      {status}
    </span>
  );
};

const StatBox = ({ label, value, icon, color }) => {
  const colors = {
    blue: 'bg-blue-100 text-blue-600',
    red: 'bg-red-100 text-red-600',
    orange: 'bg-orange-100 text-orange-600',
    green: 'bg-green-100 text-green-600',
  };

  return (
    <div className="border border-gray-200 rounded-lg p-4">
      <div className={`inline-flex p-2 rounded-lg ${colors[color]} mb-3`}>
        {React.cloneElement(icon, { size: 20 })}
      </div>
      <p className="text-gray-600 text-sm mb-1">{label}</p>
      <p className="text-3xl font-bold text-gray-900">{value}</p>
    </div>
  );
};

export default Profile;
