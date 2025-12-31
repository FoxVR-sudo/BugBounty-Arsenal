import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { FiPlay, FiLoader, FiCheckCircle, FiAlertTriangle, FiSettings } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';

const CategoryScan = () => {
  const { categoryId } = useParams();
  const navigate = useNavigate();
  
  const [category, setCategory] = useState(null);
  const [detectors, setDetectors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('');
  const [results, setResults] = useState(null);
  const [subscription, setSubscription] = useState(null);
  const [hasAccess, setHasAccess] = useState(null); // null = loading, true = access, false = no access
  const [plans, setPlans] = useState([]); // For upgrade page
  
  // Form state
  const [target, setTarget] = useState('');
  const [selectedDetectors, setSelectedDetectors] = useState([]);
  const [acceptDisclaimer, setAcceptDisclaimer] = useState(false);
  const [options, setOptions] = useState({
    depth: 3,
    timeout: 30,
    follow_redirects: true,
    verify_ssl: true,
  });

  useEffect(() => {
    fetchCategoryData();
    fetchSubscription();
    fetchPlans();
  }, [categoryId]);

  const fetchCategoryData = async () => {
    try {
      const token = localStorage.getItem('token');
      
      // Fetch all categories
      const categoriesResponse = await axios.get('http://localhost:8001/api/scan-categories/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      const foundCategory = categoriesResponse.data.find(c => c.name === categoryId);
      if (!foundCategory) {
        alert('Category not found');
        navigate('/dashboard');
        return;
      }
      
      setCategory(foundCategory);
      
      // Fetch detectors for this category
      const detectorsResponse = await axios.get(
        `http://localhost:8001/api/scan-categories/${foundCategory.id}/detectors/`,
        { headers: { 'Authorization': `Bearer ${token}` } }
      );
      
      setDetectors(detectorsResponse.data);
      // Select all detectors by default
      setSelectedDetectors(detectorsResponse.data.map(d => d.id));
      
    } catch (err) {
      console.error('Failed to load category:', err);
      alert('Failed to load scanner data');
    } finally {
      setLoading(false);
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

  const fetchPlans = async () => {
    try {
      const response = await axios.get('http://localhost:8001/api/plans/');
      setPlans(response.data);
    } catch (err) {
      console.error('Failed to fetch plans:', err);
    }
  };

  // Check access when both category and subscription are loaded
  useEffect(() => {
    if (category && subscription) {
      const planHierarchy = { 'free': 0, 'pro': 1, 'pro plan': 1, 'enterprise': 2 };
      // subscription has plan_name, not plan.name
      const userPlanName = (subscription.plan_name || subscription.plan?.name || 'free').toLowerCase();
      const userPlanLevel = planHierarchy[userPlanName] || 0;
      const requiredPlanLevel = planHierarchy[category.required_plan?.toLowerCase()] || 0;
      
      console.log('Access check:', {
        category: category.name,
        required: category.required_plan,
        userPlan: userPlanName,
        userLevel: userPlanLevel,
        requiredLevel: requiredPlanLevel,
        hasAccess: userPlanLevel >= requiredPlanLevel
      });
      
      setHasAccess(userPlanLevel >= requiredPlanLevel);
    } else if (category && !subscription) {
      // If subscription hasn't loaded yet, check if it's a free category
      const isFree = category.required_plan?.toLowerCase() === 'free';
      console.log('No subscription loaded, category:', category.name, 'is free?', isFree);
      setHasAccess(isFree);
    }
  }, [category, subscription]);

  const handleStartScan = async (e) => {
    e.preventDefault();
    
    if (!target) {
      alert('Please enter a target URL');
      return;
    }
    
    if (selectedDetectors.length === 0) {
      alert('Please select at least one detector');
      return;
    }

    if (!acceptDisclaimer) {
      alert('You must confirm that you have authorization to scan this target');
      return;
    }

    setScanning(true);
    setScanProgress(0);
    setScanStatus('Initializing scan...');
    setResults(null);

    try {
      const token = localStorage.getItem('token');
      
      // Convert detector IDs to names
      const detectorNames = detectors
        .filter(d => selectedDetectors.includes(d.id))
        .map(d => d.name);
      
      const response = await axios.post(
        'http://localhost:8001/api/scans/start-category-scan/',
        {
          category: category.id,
          target: target,
          detectors: detectorNames,
          options: options
        },
        { headers: { 'Authorization': `Bearer ${token}` } }
      );

      const scanId = response.data.id;
      
      // Start polling for progress
      pollScanProgress(scanId);
      
    } catch (err) {
      console.error('Scan failed:', err);
      alert(err.response?.data?.error || 'Failed to start scan');
      setScanning(false);
    }
  };

  const pollScanProgress = async (scanId) => {
    const token = localStorage.getItem('token');
    const interval = setInterval(async () => {
      try {
        const response = await axios.get(
          `http://localhost:8001/api/scans/${scanId}/`,
          { headers: { 'Authorization': `Bearer ${token}` } }
        );
        
        const scan = response.data;
        setScanStatus(scan.status);
        setScanProgress(scan.progress || 0);
        
        if (scan.status === 'completed' || scan.status === 'failed') {
          clearInterval(interval);
          setScanning(false);
          setResults(scan);
          
          if (scan.status === 'completed') {
            fetchVulnerabilities(scanId);
          }
        }
        
      } catch (err) {
        console.error('Failed to fetch scan progress:', err);
        clearInterval(interval);
        setScanning(false);
      }
    }, 2000);
  };

  const fetchVulnerabilities = async (scanId) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(
        `http://localhost:8001/api/scans/${scanId}/vulnerabilities/`,
        { headers: { 'Authorization': `Bearer ${token}` } }
      );
      
      setResults(prev => ({ ...prev, vulnerabilities: response.data.results || [] }));
    } catch (err) {
      console.error('Failed to fetch vulnerabilities:', err);
    }
  };

  const toggleDetector = (detectorId) => {
    setSelectedDetectors(prev =>
      prev.includes(detectorId)
        ? prev.filter(id => id !== detectorId)
        : [...prev, detectorId]
    );
  };

  const toggleAllDetectors = () => {
    if (selectedDetectors.length === detectors.length) {
      setSelectedDetectors([]);
    } else {
      setSelectedDetectors(detectors.map(d => d.id));
    }
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="p-8 flex items-center justify-center">
          <FiLoader className="animate-spin text-primary" size={48} />
        </div>
      </DashboardLayout>
    );
  }

  if (!category) {
    return (
      <DashboardLayout>
        <div className="p-8 text-center">
          <h2 className="text-2xl font-bold text-gray-900 mb-4">Category Not Found</h2>
          <button onClick={() => navigate('/dashboard')} className="px-6 py-3 bg-primary text-white rounded-lg">
            Back to Dashboard
          </button>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="p-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-4 mb-2">
            <span className="text-4xl">{category.icon_emoji || category.icon}</span>
            <h1 className="text-3xl font-bold text-gray-900">{category.display_name}</h1>
            {category.required_plan !== 'free' && (
              <span className="px-3 py-1 bg-yellow-100 text-yellow-700 rounded-full text-sm font-semibold uppercase">
                {category.required_plan}
              </span>
            )}
          </div>
          <p className="text-gray-600">{category.description}</p>
        </div>

        {/* Show Upgrade UI if no access */}
        {hasAccess === false ? (
          <div className="bg-gradient-to-r from-purple-600 to-pink-600 text-white rounded-lg shadow-xl p-12 text-center">
            <div className="mb-6">
              <div className="inline-block p-4 bg-white bg-opacity-20 rounded-full mb-4">
                <svg className="w-16 h-16" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
                </svg>
              </div>
              <h2 className="text-3xl font-bold mb-4">Upgrade Required</h2>
              <p className="text-xl mb-2">
                {category.display_name} scanner requires a <span className="font-bold">{category.required_plan.toUpperCase()}</span> plan
              </p>
              <p className="text-white text-opacity-90 mb-8">
                You are currently on the <span className="font-semibold">{subscription?.plan?.display_name || 'Free'}</span> plan
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8 text-left">
              {plans.map((plan, index) => {
                const isFree = plan.price === 0 || plan.price === '0.00';
                const isPro = plan.name === 'pro';
                const isPopular = plan.is_popular;
                
                return (
                  <div 
                    key={plan.id}
                    className={`rounded-lg p-6 ${
                      isPopular 
                        ? 'bg-white text-gray-900 shadow-2xl transform scale-105 border-4 border-yellow-400' 
                        : 'bg-white bg-opacity-10 backdrop-blur-sm'
                    }`}
                  >
                    {isPopular && (
                      <div className="text-center mb-2">
                        <span className="bg-yellow-400 text-yellow-900 px-3 py-1 rounded-full text-xs font-bold">RECOMMENDED</span>
                      </div>
                    )}
                    
                    <h3 className={`text-lg font-bold mb-2 ${isPopular ? 'text-gray-900' : ''}`}>
                      {plan.display_name}
                    </h3>
                    <div className={`text-2xl font-bold mb-4 ${isPopular ? 'text-gray-900' : ''}`}>
                      {isFree ? 'Free' : `$${plan.price}`}
                      <span className="text-sm">/month</span>
                    </div>
                    
                    <ul className={`space-y-2 text-sm ${isPopular ? 'text-gray-700' : ''}`}>
                      <li>✓ {plan.daily_scan_limit === -1 ? 'Unlimited' : plan.daily_scan_limit} scans per day</li>
                      {plan.features && plan.features.slice(0, 6).map((feature, idx) => (
                        <li key={idx}>✓ {feature}</li>
                      ))}
                    </ul>
                    
                    {!isFree && (
                      <button 
                        onClick={() => navigate('/pricing')}
                        className={`w-full mt-4 py-3 rounded-lg font-bold transition ${
                          isPopular
                            ? 'bg-gradient-to-r from-purple-600 to-pink-600 text-white hover:opacity-90'
                            : 'bg-white bg-opacity-20 hover:bg-opacity-30'
                        }`}
                      >
                        {plan.name === 'enterprise' ? 'Contact Sales' : `Upgrade to ${plan.display_name}`}
                      </button>
                    )}
                  </div>
                );
              })}
            </div>

            <button
              onClick={() => navigate('/dashboard')}
              className="px-6 py-3 bg-white bg-opacity-20 hover:bg-opacity-30 rounded-lg font-semibold transition"
            >
              Back to Dashboard
            </button>
          </div>
        ) : (
          /* Scanner Form - Show only if user has access */
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left: Configuration */}
          <div className="lg:col-span-2">
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h2 className="text-xl font-bold text-gray-900 mb-6 flex items-center gap-2">
                <FiSettings /> Scan Configuration
              </h2>

              <form onSubmit={handleStartScan}>
                {/* Target URL */}
                <div className="mb-6">
                  <label className="block text-gray-700 font-semibold mb-2">
                    Target URL <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="url"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    required
                    disabled={scanning}
                  />
                </div>

                {/* Advanced Options */}
                <div className="mb-6">
                  <h3 className="font-semibold text-gray-900 mb-4">Advanced Options</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-gray-700 text-sm mb-2">Scan Depth</label>
                      <input
                        type="number"
                        min="1"
                        max="10"
                        value={options.depth}
                        onChange={(e) => setOptions({ ...options, depth: parseInt(e.target.value) })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                        disabled={scanning}
                      />
                    </div>
                    <div>
                      <label className="block text-gray-700 text-sm mb-2">Timeout (seconds)</label>
                      <input
                        type="number"
                        min="10"
                        max="300"
                        value={options.timeout}
                        onChange={(e) => setOptions({ ...options, timeout: parseInt(e.target.value) })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                        disabled={scanning}
                      />
                    </div>
                  </div>
                  <div className="mt-4 space-y-2">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={options.follow_redirects}
                        onChange={(e) => setOptions({ ...options, follow_redirects: e.target.checked })}
                        className="w-4 h-4 text-primary rounded"
                        disabled={scanning}
                      />
                      <span className="text-sm text-gray-700">Follow Redirects</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={options.verify_ssl}
                        onChange={(e) => setOptions({ ...options, verify_ssl: e.target.checked })}
                        className="w-4 h-4 text-primary rounded"
                        disabled={scanning}
                      />
                      <span className="text-sm text-gray-700">Verify SSL Certificate</span>
                    </label>
                  </div>
                </div>

                {/* Detector Selection */}
                <div className="mb-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold text-gray-900">
                      Detectors ({selectedDetectors.length}/{detectors.length})
                    </h3>
                    <button
                      type="button"
                      onClick={toggleAllDetectors}
                      className="text-sm text-primary hover:underline"
                      disabled={scanning}
                    >
                      {selectedDetectors.length === detectors.length ? 'Deselect All' : 'Select All'}
                    </button>
                  </div>
                  
                  <div className="max-h-96 overflow-y-auto border border-gray-200 rounded-lg">
                    {detectors.map((detector) => (
                      <label
                        key={detector.id}
                        className={`flex items-start gap-3 p-4 border-b border-gray-100 hover:bg-gray-50 cursor-pointer ${
                          scanning ? 'opacity-50 cursor-not-allowed' : ''
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={selectedDetectors.includes(detector.id)}
                          onChange={() => toggleDetector(detector.id)}
                          className="mt-1 w-5 h-5 text-primary rounded"
                          disabled={scanning}
                        />
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-semibold text-gray-900">{detector.display_name}</span>
                            <span className={`text-xs px-2 py-0.5 rounded font-semibold ${
                              detector.severity === 'critical' ? 'bg-red-100 text-red-700' :
                              detector.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                              detector.severity === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                              detector.severity === 'low' ? 'bg-blue-100 text-blue-700' :
                              'bg-gray-100 text-gray-700'
                            }`}>
                              {detector.severity.toUpperCase()}
                            </span>
                            {detector.is_dangerous && (
                              <span className="text-xs px-2 py-0.5 rounded bg-red-600 text-white font-semibold">
                                🔴 DANGEROUS
                              </span>
                            )}
                          </div>
                          <p className="text-sm text-gray-600">{detector.description || 'No description'}</p>
                          {detector.tags && detector.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-2">
                              {detector.tags.map((tag, idx) => (
                                <span key={idx} className="text-xs px-2 py-0.5 bg-gray-100 text-gray-600 rounded">
                                  {tag}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </label>
                    ))}
                  </div>
                </div>

                {/* Legal Disclaimer */}
                <div className="mb-6 p-4 bg-yellow-50 border-l-4 border-yellow-400 rounded">
                  <div className="flex items-start gap-3">
                    <FiAlertTriangle className="text-yellow-600 mt-1 flex-shrink-0" size={20} />
                    <div className="flex-1">
                      <h4 className="font-semibold text-yellow-800 mb-2">⚠️ Legal Warning</h4>
                      <p className="text-sm text-yellow-700 mb-3">
                        Scanning systems WITHOUT permission is illegal and constitutes a crime. 
                        You bear full responsibility for your actions.
                      </p>
                      <label className="flex items-start gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={acceptDisclaimer}
                          onChange={(e) => setAcceptDisclaimer(e.target.checked)}
                          className="mt-1 w-4 h-4 text-primary border-gray-300 rounded focus:ring-primary"
                          disabled={scanning}
                          required
                        />
                        <span className="text-sm text-yellow-800 font-medium">
                          I confirm that I have explicit WRITTEN permission to scan this system 
                          and accept full responsibility for the consequences of this scan. *
                        </span>
                      </label>
                    </div>
                  </div>
                </div>

                {/* Submit Button */}
                <button
                  type="submit"
                  disabled={scanning || selectedDetectors.length === 0 || !acceptDisclaimer}
                  className={`w-full px-6 py-4 rounded-lg font-semibold text-white flex items-center justify-center gap-2 ${
                    scanning || selectedDetectors.length === 0 || !acceptDisclaimer
                      ? 'bg-gray-400 cursor-not-allowed'
                      : 'bg-primary hover:bg-primary-600 transition'
                  }`}
                >
                  {scanning ? (
                    <>
                      <FiLoader className="animate-spin" size={20} />
                      Scanning... {scanProgress}%
                    </>
                  ) : (
                    <>
                      <FiPlay size={20} />
                      Start {category.display_name} Scan
                    </>
                  )}
                </button>
              </form>
            </div>
          </div>

          {/* Right: Progress & Results */}
          <div className="lg:col-span-1">
            {/* Progress */}
            {scanning && (
              <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
                <h3 className="font-semibold text-gray-900 mb-4">Scan Progress</h3>
                <div className="mb-4">
                  <div className="w-full bg-gray-200 rounded-full h-4">
                    <div
                      className="bg-primary h-4 rounded-full transition-all duration-500"
                      style={{ width: `${scanProgress}%` }}
                    ></div>
                  </div>
                  <p className="text-sm text-gray-600 mt-2">{scanProgress}% complete</p>
                </div>
                <div className="flex items-center gap-2 text-sm text-gray-700">
                  <FiLoader className="animate-spin" />
                  <span>{scanStatus}</span>
                </div>
              </div>
            )}

            {/* Results Summary */}
            {results && (
              <div className="bg-white rounded-lg shadow-lg p-6">
                <h3 className="font-semibold text-gray-900 mb-4">Scan Results</h3>
                
                {results.status === 'completed' ? (
                  <>
                    <div className="flex items-center gap-2 text-green-600 mb-4">
                      <FiCheckCircle size={24} />
                      <span className="font-semibold">Scan Completed</span>
                    </div>
                    
                    <div className="space-y-3">
                      <div className="p-3 bg-gray-50 rounded-lg">
                        <div className="text-sm text-gray-600">Vulnerabilities Found</div>
                        <div className="text-2xl font-bold text-gray-900">
                          {results.vulnerabilities_found || results.vulnerabilities?.length || 0}
                        </div>
                      </div>
                      
                      {results.vulnerabilities && results.vulnerabilities.length > 0 && (
                        <div className="space-y-2">
                          {results.vulnerabilities.slice(0, 5).map((vuln, idx) => (
                            <div key={idx} className="p-3 border border-gray-200 rounded-lg">
                              <div className="flex items-start justify-between gap-2">
                                <span className="text-sm font-semibold text-gray-900">{vuln.title}</span>
                                <span className={`text-xs px-2 py-0.5 rounded font-semibold ${
                                  vuln.severity === 'critical' ? 'bg-red-100 text-red-700' :
                                  vuln.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                                  vuln.severity === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                                  'bg-blue-100 text-blue-700'
                                }`}>
                                  {vuln.severity}
                                </span>
                              </div>
                            </div>
                          ))}
                          {results.vulnerabilities.length > 5 && (
                            <p className="text-xs text-gray-500 text-center">
                              +{results.vulnerabilities.length - 5} more
                            </p>
                          )}
                        </div>
                      )}
                    </div>
                    
                    <button
                      onClick={() => navigate(`/scan/details/${results.id}`)}
                      className="w-full mt-4 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-600 transition"
                    >
                      View Full Report
                    </button>
                  </>
                ) : (
                  <div className="flex items-center gap-2 text-red-600">
                    <FiAlertTriangle size={24} />
                    <span className="font-semibold">Scan Failed</span>
                  </div>
                )}
              </div>
            )}

            {/* Info Card */}
            {!scanning && !results && (
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
                <h3 className="font-semibold text-blue-900 mb-2">About {category.display_name}</h3>
                <p className="text-sm text-blue-800 mb-4">{category.description}</p>
                <div className="text-sm text-blue-700">
                  <div className="mb-2">
                    <strong>Detectors:</strong> {category.detector_count}
                  </div>
                  {category.dangerous_detector_count > 0 && (
                    <div className="mb-2 text-red-600">
                      <strong>⚠️ Dangerous Tools:</strong> {category.dangerous_detector_count}
                    </div>
                  )}
                  <div>
                    <strong>Required Plan:</strong> {category.required_plan.toUpperCase()}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default CategoryScan;
