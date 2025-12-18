import React from 'react';
import { useQuery } from 'react-query';
import { Link } from 'react-router-dom';
import { scanService } from '../services/api';
import { FiEye, FiDownload, FiClock, FiCheckCircle, FiAlertCircle } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import { format } from 'date-fns';

const AllResults = () => {
  const { data: scans, isLoading } = useQuery('all-scans', () =>
    scanService.getAll().then(res => res.data.results)
  );

  const getStatusBadge = (status) => {
    const badges = {
      completed: 'bg-green-100 text-green-800',
      running: 'bg-blue-100 text-blue-800',
      failed: 'bg-red-100 text-red-800',
      pending: 'bg-yellow-100 text-yellow-800'
    };
    return badges[status] || badges.pending;
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <FiCheckCircle className="text-green-500" />;
      case 'running':
        return <FiClock className="text-blue-500" />;
      case 'failed':
        return <FiAlertCircle className="text-red-500" />;
      default:
        return <FiClock className="text-gray-500" />;
    }
  };

  return (
    <DashboardLayout>
      <div className="p-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">All Scan Results</h1>
          <p className="text-gray-600 mt-2">View and manage all your security scans</p>
        </div>

        {isLoading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
            <p className="text-gray-500 mt-4">Loading scans...</p>
          </div>
        ) : (
          <div className="bg-white rounded-lg shadow overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Target
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Scan Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Vulnerabilities
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Date
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {scans?.map((scan) => (
                  <tr key={scan.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(scan.status)}
                        <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${getStatusBadge(scan.status)}`}>
                          {scan.status}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-sm text-gray-900 max-w-xs truncate">{scan.target}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="text-sm text-gray-700 capitalize">{scan.scan_type}</span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {scan.vulnerability_count > 0 ? (
                        <span className="text-red-600 font-semibold">{scan.vulnerability_count}</span>
                      ) : (
                        <span className="text-green-600">0</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {format(new Date(scan.created_at), 'MMM dd, yyyy HH:mm')}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex gap-2">
                        <Link
                          to={`/scan/${scan.id}`}
                          className="text-primary hover:text-primary-600 flex items-center gap-1"
                        >
                          <FiEye /> View
                        </Link>
                        {scan.status === 'completed' && (
                          <button
                            onClick={() => {
                              window.open(`http://127.0.0.1:8001/api/scans/${scan.id}/export/?format=json`, '_blank');
                            }}
                            className="text-green-600 hover:text-green-800 flex items-center gap-1"
                          >
                            <FiDownload /> Export
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {(!scans || scans.length === 0) && (
              <div className="text-center py-12">
                <p className="text-gray-500">No scans found. Start your first scan!</p>
              </div>
            )}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default AllResults;
