import React from 'react';
import { useQuery } from 'react-query';
import { statsService } from '../services/api';
import { FiTrendingUp, FiAlertTriangle, FiActivity, FiTarget } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';

const COLORS = ['#EF4444', '#F59E0B', '#10B981', '#3B82F6', '#8B5CF6'];

const Analytics = () => {
  const { data: stats } = useQuery('analytics', () =>
    statsService.getOverview().then(res => res.data)
  );

  // Mock data for charts - replace with real API data
  const vulnerabilityByType = [
    { name: 'XSS', count: stats?.vuln_by_type?.xss || 0 },
    { name: 'SQL Injection', count: stats?.vuln_by_type?.sql || 0 },
    { name: 'SSRF', count: stats?.vuln_by_type?.ssrf || 0 },
    { name: 'Auth Bypass', count: stats?.vuln_by_type?.auth || 0 },
    { name: 'Others', count: stats?.vuln_by_type?.others || 0 },
  ];

  const scanTrend = [
    { date: 'Mon', scans: 12 },
    { date: 'Tue', scans: 19 },
    { date: 'Wed', scans: 15 },
    { date: 'Thu', scans: 25 },
    { date: 'Fri', scans: 22 },
    { date: 'Sat', scans: 18 },
    { date: 'Sun', scans: 10 },
  ];

  const severityData = [
    { name: 'Critical', value: stats?.severity?.critical || 0 },
    { name: 'High', value: stats?.severity?.high || 0 },
    { name: 'Medium', value: stats?.severity?.medium || 0 },
    { name: 'Low', value: stats?.severity?.low || 0 },
  ];

  return (
    <DashboardLayout>
      <div className="p-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Analytics</h1>
          <p className="text-gray-600 mt-2">Detailed insights into your security scans</p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <StatCard
            title="Total Vulnerabilities"
            value={stats?.total_vulnerabilities || 0}
            icon={<FiAlertTriangle />}
            color="red"
            trend="+12%"
          />
          <StatCard
            title="Critical Issues"
            value={stats?.severity?.critical || 0}
            icon={<FiTarget />}
            color="orange"
            trend="+5%"
          />
          <StatCard
            title="Scans This Week"
            value={stats?.scans_this_week || 0}
            icon={<FiActivity />}
            color="blue"
            trend="+18%"
          />
          <StatCard
            title="Avg Scan Time"
            value={stats?.avg_scan_time || '2.5m'}
            icon={<FiTrendingUp />}
            color="green"
            trend="-8%"
          />
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          {/* Vulnerability by Type */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-xl font-semibold mb-4">Vulnerabilities by Type</h2>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={vulnerabilityByType}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#6366F1" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Severity Distribution */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-xl font-semibold mb-4">Severity Distribution</h2>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Scan Trend */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4">Weekly Scan Activity</h2>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={scanTrend}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="scans" stroke="#6366F1" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </DashboardLayout>
  );
};

const StatCard = ({ title, value, icon, color, trend }) => {
  const colors = {
    red: 'bg-red-100 text-red-600',
    orange: 'bg-orange-100 text-orange-600',
    blue: 'bg-blue-100 text-blue-600',
    green: 'bg-green-100 text-green-600',
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between">
        <div className={`p-3 rounded-lg ${colors[color]}`}>
          {React.cloneElement(icon, { size: 24 })}
        </div>
        {trend && (
          <span className={`text-sm font-semibold ${trend.startsWith('+') ? 'text-green-600' : 'text-red-600'}`}>
            {trend}
          </span>
        )}
      </div>
      <h3 className="text-gray-500 text-sm mt-4">{title}</h3>
      <p className="text-3xl font-bold text-gray-900 mt-2">{value}</p>
    </div>
  );
};

export default Analytics;
