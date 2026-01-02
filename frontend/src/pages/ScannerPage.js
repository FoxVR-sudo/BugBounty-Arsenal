import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from 'react-query';
import { scanService } from '../services/api';
import { FiPlay, FiSettings, FiAlertCircle, FiCheckCircle, FiClock } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import { useTheme } from '../contexts/ThemeContext';

const scannerInfo = {
  xss: {
    name: 'XSS Scanner',
    description: 'Cross-Site Scripting (XSS) vulnerability detection. Tests for reflected, stored, and DOM-based XSS vulnerabilities.',
    whatItScans: [
      'Input fields and forms',
      'URL parameters',
      'HTTP headers',
      'Cookie values',
      'DOM manipulation points'
    ],
    riskLevel: 'High'
  },
  sql: {
    name: 'SQL Injection Scanner',
    description: 'Detects SQL injection vulnerabilities by testing various injection patterns and database error responses.',
    whatItScans: [
      'Query parameters',
      'Form inputs',
      'Authentication fields',
      'Search functionality',
      'Database error messages'
    ],
    riskLevel: 'Critical'
  },
  ssrf: {
    name: 'SSRF Scanner',
    description: 'Server-Side Request Forgery detection. Tests for unauthorized internal network access and port scanning.',
    whatItScans: [
      'URL parameters',
      'File upload functionality',
      'Webhook endpoints',
      'API integrations',
      'Import/export features'
    ],
    riskLevel: 'High'
  },
  lfi: {
    name: 'LFI Scanner',
    description: 'Local File Inclusion vulnerability scanner. Tests for unauthorized file system access.',
    whatItScans: [
      'File path parameters',
      'Include/require statements',
      'Template loading',
      'Configuration file access',
      'Log file exposure'
    ],
    riskLevel: 'High'
  },
  auth: {
    name: 'Auth Bypass Scanner',
    description: 'Tests for authentication and authorization bypass vulnerabilities.',
    whatItScans: [
      'Login mechanisms',
      'Session management',
      'Password reset flows',
      'Role-based access control',
      'API authentication'
    ],
    riskLevel: 'Critical'
  },
  jwt: {
    name: 'JWT Scanner',
    description: 'JSON Web Token security scanner. Tests for JWT vulnerabilities and misconfigurations.',
    whatItScans: [
      'JWT signature validation',
      'Algorithm confusion',
      'Token expiration',
      'Claim manipulation',
      'Key confusion attacks'
    ],
    riskLevel: 'High'
  },
  cors: {
    name: 'CORS Scanner',
    description: 'Cross-Origin Resource Sharing misconfiguration detection.',
    whatItScans: [
      'CORS headers',
      'Origin reflection',
      'Credential exposure',
      'Wildcard usage',
      'Pre-flight requests'
    ],
    riskLevel: 'Medium'
  },
  csrf: {
    name: 'CSRF Scanner',
    description: 'Cross-Site Request Forgery vulnerability detection.',
    whatItScans: [
      'Form submissions',
      'State-changing requests',
      'CSRF token validation',
      'SameSite cookie attributes',
      'Referer header checks'
    ],
    riskLevel: 'Medium'
  },
  xxe: {
    name: 'XXE Scanner',
    description: 'XML External Entity injection vulnerability scanner.',
    whatItScans: [
      'XML parsers',
      'File upload (XML)',
      'SOAP endpoints',
      'RSS/Atom feeds',
      'Configuration files'
    ],
    riskLevel: 'High'
  },
  idor: {
    name: 'IDOR Scanner',
    description: 'Insecure Direct Object Reference detection.',
    whatItScans: [
      'API endpoints',
      'Object IDs',
      'User resources',
      'File access',
      'Database records'
    ],
    riskLevel: 'High'
  },
  graphql: {
    name: 'GraphQL Scanner',
    description: 'GraphQL API security scanner.',
    whatItScans: [
      'Introspection queries',
      'Query depth limits',
      'Rate limiting',
      'Field suggestions',
      'Mutation security'
    ],
    riskLevel: 'Medium'
  },
  api: {
    name: 'API Security Scanner',
    description: 'Comprehensive API security testing.',
    whatItScans: [
      'REST endpoints',
      'Authentication',
      'Rate limiting',
      'Input validation',
      'Error handling'
    ],
    riskLevel: 'High'
  }
};

const ScannerPage = () => {
  const { isDark } = useTheme();
  const { type } = useParams();
  const [target, setTarget] = useState('');
  const [acceptDisclaimer, setAcceptDisclaimer] = useState(false);
  const [options, setOptions] = useState({
    depth: 'medium',
    timeout: 30,
    followRedirects: true,
  });

  const info = scannerInfo[type] || {};

  // Map scanner type to backend scan_type
  const getScanType = (scannerType) => {
    const typeMap = {
      'xss': 'web_security',
      'sql': 'web_security',
      'ssrf': 'web_security',
      'lfi': 'web_security',
      'auth': 'web_security',
      'jwt': 'web_security',
      'cors': 'web_security',
      'csrf': 'web_security',
      'xxe': 'web_security',
      'idor': 'web_security',
      'graphql': 'api_security',
      'api': 'api_security'
    };
    return typeMap[scannerType] || 'web_security';
  };

  // Map scanner type to detector name
  const getDetectorName = (scannerType) => {
    const detectorMap = {
      'xss': 'xss_pattern_detector',
      'sql': 'sql_pattern_detector',
      'ssrf': 'ssrf_detector',
      'lfi': 'lfi_detector',
      'auth': 'auth_bypass_detector',
      'jwt': 'jwt_detector',
      'cors': 'cors_detector',
      'csrf': 'csrf_detector',
      'xxe': 'xxe_detector',
      'idor': 'idor_detector',
      'graphql': 'graphql_detector',
      'api': 'api_security_detector'
    };
    return detectorMap[scannerType];
  };

  const backendScanType = getScanType(type);
  const detectorName = getDetectorName(type);

  // Fetch recent scans for this scanner type
  const { data: recentScans, refetch } = useQuery(
    ['scans', type],
    () => scanService.getAll({ scan_type: backendScanType }).then(res => res.data.results)
  );

  const handleScan = async (e) => {
    e.preventDefault();

    if (!acceptDisclaimer) {
      alert('You must confirm that you have authorization to scan this target');
      return;
    }

    try {
      const scanData = {
        target,
        scan_type: backendScanType,
        timeout: options.timeout
      };
      
      // Only add enabled_detectors if we have a specific detector
      if (detectorName) {
        scanData.enabled_detectors = [detectorName];
      }
      
      await scanService.create(scanData);
      setTarget('');
      refetch();
      alert('Scan started successfully!');
    } catch (error) {
      alert('Failed to start scan: ' + error.message);
    }
  };

  const getRiskColor = (risk) => {
    const colors = {
      Critical: 'text-red-600 bg-red-100',
      High: 'text-orange-600 bg-orange-100',
      Medium: 'text-yellow-600 bg-yellow-100',
      Low: 'text-blue-600 bg-blue-100'
    };
    return colors[risk] || colors.Medium;
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <FiCheckCircle className="text-green-500" />;
      case 'running':
        return <FiClock className="text-blue-500 animate-spin" />;
      case 'failed':
        return <FiAlertCircle className="text-red-500" />;
      default:
        return <FiClock className="text-gray-500" />;
    }
  };

  return (
    <DashboardLayout>
      <div className="p-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className={`text-3xl font-bold mb-2 ${isDark ? 'text-white' : 'text-gray-900'}`}>{info.name}</h1>
          <p className="text-gray-600">{info.description}</p>
          <div className="mt-4">
            <span className={`inline-block px-3 py-1 rounded-full text-sm font-semibold ${getRiskColor(info.riskLevel)}`}>
              {info.riskLevel} Risk
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Column - Scanner Info */}
          <div className="lg:col-span-2 space-y-6">
            {/* What it Scans */}
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                <FiSettings className="text-primary" />
                What This Scanner Checks
              </h2>
              <ul className="space-y-2">
                {info.whatItScans?.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <FiCheckCircle className="text-green-500 mt-1 flex-shrink-0" />
                    <span className="text-gray-700">{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* New Scan Form */}
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                <FiPlay className="text-primary" />
                Start New Scan
              </h2>
              <form onSubmit={handleScan} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
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

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Scan Depth
                    </label>
                    <select
                      value={options.depth}
                      onChange={(e) => setOptions({ ...options, depth: e.target.value })}
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    >
                      <option value="light">Light</option>
                      <option value="medium">Medium</option>
                      <option value="deep">Deep</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Timeout (seconds)
                    </label>
                    <input
                      type="number"
                      value={options.timeout}
                      onChange={(e) => setOptions({ ...options, timeout: parseInt(e.target.value) })}
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                      min="10"
                      max="300"
                    />
                  </div>
                </div>

                <div className="flex items-center">
                  <input
                    type="checkbox"
                    checked={options.followRedirects}
                    onChange={(e) => setOptions({ ...options, followRedirects: e.target.checked })}
                    className="w-4 h-4 text-primary border-gray-300 rounded focus:ring-primary"
                  />
                  <label className="ml-2 text-sm text-gray-700">
                    Follow Redirects
                  </label>
                </div>

                {/* Legal Disclaimer */}
                <div className="p-4 bg-yellow-50 border-l-4 border-yellow-400 rounded">
                  <div className="flex items-start gap-3">
                    <FiAlertCircle className="text-yellow-600 mt-1 flex-shrink-0" size={20} />
                    <div className="flex-1">
                      <h4 className="font-semibold text-yellow-800 text-sm mb-2">⚠️ Legal Warning</h4>
                      <p className="text-xs text-yellow-700 mb-2">
                        Scanning systems WITHOUT permission is illegal. 
                        You bear full responsibility for your actions.
                      </p>
                      <label className="flex items-start gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={acceptDisclaimer}
                          onChange={(e) => setAcceptDisclaimer(e.target.checked)}
                          className="mt-0.5 w-4 h-4 text-primary border-gray-300 rounded focus:ring-primary"
                          required
                        />
                        <span className="text-xs text-yellow-800 font-medium">
                          I confirm that I have explicit permission to scan this system. *
                        </span>
                      </label>
                    </div>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={!acceptDisclaimer}
                  className={`w-full py-3 rounded-lg font-semibold flex items-center justify-center gap-2 ${
                    acceptDisclaimer 
                      ? 'bg-primary text-white hover:bg-primary-600 transition' 
                      : 'bg-gray-400 text-white cursor-not-allowed'
                  }`}
                >
                  <FiPlay />
                  Start Scan
                </button>
              </form>
            </div>
          </div>

          {/* Right Column - Recent Scans */}
          <div className="lg:col-span-1">
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-4">Recent Scans</h2>
              <div className="space-y-3">
                {recentScans?.slice(0, 10).map((scan) => (
                  <div key={scan.id} className="border border-gray-200 rounded-lg p-3 hover:border-primary transition">
                    <div className="flex items-start justify-between mb-2">
                      {getStatusIcon(scan.status)}
                      <span className="text-xs text-gray-500">
                        {new Date(scan.created_at).toLocaleDateString()}
                      </span>
                    </div>
                    <p className="text-sm text-gray-700 truncate mb-1">{scan.target}</p>
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-gray-500">{scan.status}</span>
                      {scan.vulnerability_count > 0 && (
                        <span className="text-red-600 font-semibold">
                          {scan.vulnerability_count} issues
                        </span>
                      )}
                    </div>
                  </div>
                ))}
                {(!recentScans || recentScans.length === 0) && (
                  <p className="text-gray-500 text-sm text-center py-4">
                    No scans yet. Start your first scan!
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default ScannerPage;
