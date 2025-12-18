import React from 'react';
import { useQuery } from 'react-query';
import { statsService } from '../services/api';
import { FiUser, FiMail, FiCalendar, FiActivity, FiShield, FiAward } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';

const Profile = () => {
  const { data: profile } = useQuery('profile', () =>
    statsService.getOverview().then(res => res.data)
  );

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
              <h2 className="text-xl font-semibold mb-4">Recent Activity</h2>
              <div className="space-y-3">
                {[1, 2, 3, 4, 5].map((i) => (
                  <div key={i} className="flex items-start gap-3 pb-3 border-b last:border-0">
                    <div className="bg-blue-100 text-blue-600 rounded-full p-2">
                      <FiActivity size={16} />
                    </div>
                    <div className="flex-1">
                      <p className="text-sm text-gray-900">Completed XSS scan on example.com</p>
                      <p className="text-xs text-gray-500 mt-1">2 hours ago</p>
                    </div>
                  </div>
                ))}
              </div>
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
