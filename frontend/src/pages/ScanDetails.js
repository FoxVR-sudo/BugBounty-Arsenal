import React from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from 'react-query';
import { scanService } from '../services/api';
import { FiArrowLeft, FiDownload, FiAlertTriangle, FiCheckCircle, FiInfo } from 'react-icons/fi';
import { format } from 'date-fns';

const ScanDetails = () => {
  const { id } = useParams();

  // Fetch scan details
  const { data: scan, isLoading: scanLoading, error: scanError } = useQuery(['scan', id], () =>
    scanService.getById(id).then((res) => res.data)
  );

  // Fetch vulnerabilities
  const { data: vulnsData, isLoading: vulnsLoading } = useQuery(
    ['vulnerabilities', id],
    () => scanService.getVulnerabilities(id).then((res) => res.data),
    { enabled: !!scan }
  );

  const handleDownload = async (format) => {
    try {
      let res;
      if (format === 'pdf') {
        res = await scanService.downloadPDF(id);
      } else if (format === 'csv') {
        res = await scanService.downloadCSV(id);
      } else {
        res = await scanService.downloadJSON(id);
        format = 'json';
      }
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `scan-${id}-report.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      alert('Failed to download report: ' + error.message);
    }
  };

  if (scanLoading || vulnsLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-gray-600">Loading scan details...</div>
      </div>
    );
  }

  if (scanError || !scan) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <FiAlertTriangle className="mx-auto text-red-500 mb-4" size={48} />
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Scan Not Found</h2>
          <p className="text-gray-600 mb-6">The scan you're looking for doesn't exist or you don't have access.</p>
          <Link to="/dashboard" className="px-6 py-3 bg-primary text-white rounded-lg hover:bg-primary-600 transition">
            Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  if (scanError || !scan) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <FiAlertTriangle className="mx-auto text-red-500 mb-4" size={48} />
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Scan Not Found</h2>
          <p className="text-gray-600 mb-6">The scan you're looking for doesn't exist or you don't have access.</p>
          <Link to="/dashboard" className="px-6 py-3 bg-primary text-white rounded-lg hover:bg-primary-600 transition">
            Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  const vulnerabilities = vulnsData?.results || [];
  const severityCounts = {
    critical: vulnerabilities.filter((v) => v.severity === 'critical').length,
    high: vulnerabilities.filter((v) => v.severity === 'high').length,
    medium: vulnerabilities.filter((v) => v.severity === 'medium').length,
    low: vulnerabilities.filter((v) => v.severity === 'low').length,
    info: vulnerabilities.filter((v) => v.severity === 'info').length,
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <nav className="bg-white shadow-sm border-b">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center gap-4">
            <Link
              to="/dashboard"
              className="p-2 hover:bg-gray-100 rounded transition"
              title="Back to Dashboard"
            >
              <FiArrowLeft size={20} />
            </Link>
            <h1 className="text-2xl font-bold text-gray-900">Scan Details</h1>
          </div>
        </div>
      </nav>

      <div className="container mx-auto px-6 py-8">
        {/* Scan Info Card */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Scan Information</h2>
              <div className="space-y-3">
                <InfoRow label="Target" value={scan.target} />
                <InfoRow label="Scan Type" value={scan.scan_type} />
                <InfoRow
                  label="Status"
                  value={
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-semibold ${
                        scan.status === 'completed'
                          ? 'bg-green-100 text-green-700'
                          : scan.status === 'failed'
                          ? 'bg-red-100 text-red-700'
                          : 'bg-yellow-100 text-yellow-700'
                      }`}
                    >
                      {scan.status}
                    </span>
                  }
                />
                <InfoRow
                  label="Created"
                  value={format(new Date(scan.created_at), 'MMM dd, yyyy HH:mm:ss')}
                />
                {scan.completed_at && (
                  <InfoRow
                    label="Completed"
                    value={format(new Date(scan.completed_at), 'MMM dd, yyyy HH:mm:ss')}
                  />
                )}
                <InfoRow label="Duration" value={`${scan.duration?.toFixed(2) || 0}s`} />
              </div>
            </div>
            <div>
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Severity Distribution</h2>
              <div className="space-y-3">
                <SeverityBar label="Critical" count={severityCounts.critical} color="red" />
                <SeverityBar label="High" count={severityCounts.high} color="orange" />
                <SeverityBar label="Medium" count={severityCounts.medium} color="yellow" />
                <SeverityBar label="Low" count={severityCounts.low} color="blue" />
                <SeverityBar label="Info" count={severityCounts.info} color="gray" />
              </div>
            </div>
          </div>

          {/* Export Buttons */}
          <div className="mt-6 pt-6 border-t flex gap-3">
            <button
              onClick={() => handleDownload('json')}
              className="flex items-center gap-2 px-6 py-3 bg-primary text-white rounded-lg hover:bg-primary-600 transition"
            >
              <FiDownload /> Download JSON
            </button>
            <button
              onClick={() => handleDownload('pdf')}
              className="flex items-center gap-2 px-6 py-3 bg-gray-700 text-white rounded-lg hover:bg-gray-800 transition"
            >
              <FiDownload /> Download PDF
            </button>
            <button
              onClick={() => handleDownload('csv')}
              className="flex items-center gap-2 px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 transition"
            >
              <FiDownload /> Download CSV
            </button>
          </div>
        </div>

        {/* Vulnerabilities List */}
        <div className="bg-white rounded-lg shadow">
          <div className="p-6 border-b">
            <h2 className="text-xl font-bold text-gray-900">
              Vulnerabilities Found ({vulnerabilities.length})
            </h2>
          </div>

          {vulnerabilities.length > 0 ? (
            <div className="divide-y">
              {vulnerabilities.map((vuln) => (
                <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
              ))}
            </div>
          ) : (
            <div className="p-12 text-center">
              <FiCheckCircle className="text-6xl text-green-500 mx-auto mb-4" />
              <p className="text-xl font-semibold text-gray-900 mb-2">No Vulnerabilities Found</p>
              <p className="text-gray-600">
                This target appears to be secure. No issues were detected during the scan.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const InfoRow = ({ label, value }) => (
  <div className="flex justify-between items-start">
    <span className="text-sm font-medium text-gray-600">{label}:</span>
    <span className="text-sm text-gray-900 text-right">{value}</span>
  </div>
);

const SeverityBar = ({ label, count, color }) => {
  const colors = {
    red: 'bg-red-500',
    orange: 'bg-orange-500',
    yellow: 'bg-yellow-500',
    blue: 'bg-blue-500',
    gray: 'bg-gray-400',
  };

  return (
    <div>
      <div className="flex justify-between text-sm mb-1">
        <span className="font-medium text-gray-700">{label}</span>
        <span className="text-gray-600">{count}</span>
      </div>
      <div className="w-full bg-gray-200 rounded-full h-2">
        <div
          className={`h-2 rounded-full ${colors[color]}`}
          style={{ width: count > 0 ? `${Math.min((count / 10) * 100, 100)}%` : '0%' }}
        />
      </div>
    </div>
  );
};

const VulnerabilityCard = ({ vulnerability }) => {
  const [expanded, setExpanded] = React.useState(false);

  const severityColors = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
    info: 'bg-gray-100 text-gray-800 border-gray-200',
  };

  const severityIcon = {
    critical: <FiAlertTriangle className="text-red-600" />,
    high: <FiAlertTriangle className="text-orange-600" />,
    medium: <FiAlertTriangle className="text-yellow-600" />,
    low: <FiInfo className="text-blue-600" />,
    info: <FiInfo className="text-gray-600" />,
  };

  return (
    <div className="p-6 hover:bg-gray-50 transition">
      <div className="flex items-start gap-4">
        <div className="text-2xl">{severityIcon[vulnerability.severity]}</div>
        <div className="flex-1">
          <div className="flex items-start justify-between mb-2">
            <h3 className="text-lg font-semibold text-gray-900">{vulnerability.title}</h3>
            <span
              className={`px-3 py-1 rounded-full text-xs font-semibold border ${
                severityColors[vulnerability.severity]
              }`}
            >
              {vulnerability.severity.toUpperCase()}
            </span>
          </div>

          <p className="text-gray-600 mb-3">{vulnerability.description}</p>

          <div className="flex flex-wrap gap-4 text-sm text-gray-600 mb-3">
            <div>
              <span className="font-medium">Detector:</span> {vulnerability.detector}
            </div>
            {vulnerability.url && (
              <div>
                <span className="font-medium">URL:</span>{' '}
                <a
                  href={vulnerability.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:underline"
                >
                  {vulnerability.url}
                </a>
              </div>
            )}
          </div>

          {expanded && (
            <div className="mt-4 pt-4 border-t space-y-3">
              {vulnerability.evidence && (
                <div>
                  <div className="font-semibold text-gray-900 mb-1">Evidence:</div>
                  <pre className="bg-gray-100 p-3 rounded text-xs overflow-x-auto">
                    {vulnerability.evidence}
                  </pre>
                </div>
              )}
              {vulnerability.payload && (
                <div>
                  <div className="font-semibold text-gray-900 mb-1">Payload:</div>
                  <pre className="bg-gray-100 p-3 rounded text-xs overflow-x-auto">
                    {vulnerability.payload}
                  </pre>
                </div>
              )}
              {vulnerability.status_code && (
                <div>
                  <span className="font-semibold">Status Code:</span> {vulnerability.status_code}
                </div>
              )}
              {vulnerability.response_time && (
                <div>
                  <span className="font-semibold">Response Time:</span>{' '}
                  {vulnerability.response_time}ms
                </div>
              )}
            </div>
          )}

          <button
            onClick={() => setExpanded(!expanded)}
            className="mt-3 text-sm text-primary hover:text-primary-600 font-semibold"
          >
            {expanded ? 'Show Less' : 'Show More'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ScanDetails;
