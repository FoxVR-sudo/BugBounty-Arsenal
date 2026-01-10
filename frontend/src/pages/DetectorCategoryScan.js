import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import { FiPlay, FiLoader, FiCheckCircle, FiAlertTriangle, FiLock, FiCreditCard, FiInfo } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import { useTheme } from '../contexts/ThemeContext';

const DetectorCategoryScan = () => {
  const { categoryKey } = useParams();
  const navigate = useNavigate();
  const { isDark } = useTheme();
  
  const [category, setCategory] = useState(null);
  const [detectors, setDetectors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [subscription, setSubscription] = useState(null);
  const [scanLimits, setScanLimits] = useState(null);
  
  // Form state
  const [target, setTarget] = useState('');
  const [selectedDetectors, setSelectedDetectors] = useState([]);
  const [acceptDisclaimer, setAcceptDisclaimer] = useState(false);

  useEffect(() => {
    fetchCategoryData();
    fetchSubscription();
  }, [categoryKey]);

  const fetchCategoryData = async () => {
    try {
      const token = localStorage.getItem('token');
      
      // Fetch detector categories with access info
      const response = await axios.get(
        process.env.REACT_APP_API_URL + '/detector-categories/',
        { headers: { 'Authorization': `Bearer ${token}` } }
      );
      
      const foundCategory = response.data.categories.find(c => c.key === categoryKey);
      if (!foundCategory) {
        alert('Category not found');
        navigate('/dashboard');
        return;
      }
      
      setCategory(foundCategory);
      setDetectors(foundCategory.detectors || []);
      
      // Select all allowed detectors by default
      const allowedDetectorNames = foundCategory.detectors
        .filter(d => d.is_allowed)
        .map(d => d.name);
      setSelectedDetectors(allowedDetectorNames);
      
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
      const response = await axios.get(
        process.env.REACT_APP_API_URL + '/subscriptions/current/',
        { headers: { 'Authorization': `Bearer ${token}` } }
      );
      setSubscription(response.data);
      
      // Calculate scan limits
      const daily = response.data.plan.scans_per_day;
      const monthly = response.data.plan.scans_per_month;
      setScanLimits({
        dailyUsed: response.data.scans_used_today || 0,
        dailyLimit: daily === -1 ? '∞' : daily,
        dailyRemaining: daily === -1 ? '∞' : Math.max(0, daily - (response.data.scans_used_today || 0)),
        monthlyUsed: response.data.scans_used_this_month || 0,
        monthlyLimit: monthly === -1 ? '∞' : monthly,
        monthlyRemaining: monthly === -1 ? '∞' : Math.max(0, monthly - (response.data.scans_used_this_month || 0)),
      });
    } catch (err) {
      console.error('Failed to fetch subscription:', err);
    }
  };

  const toggleDetector = (detectorName, isAllowed) => {
    if (!isAllowed) {
      // Show upgrade message
      alert(`This detector requires ${category.required_plan} plan. Upgrade to unlock it.`);
      return;
    }
    
    if (selectedDetectors.includes(detectorName)) {
      setSelectedDetectors(selectedDetectors.filter(d => d !== detectorName));
    } else {
      setSelectedDetectors([...selectedDetectors, detectorName]);
    }
  };

  const selectAll = () => {
    const allowedDetectors = detectors.filter(d => d.is_allowed).map(d => d.name);
    setSelectedDetectors(allowedDetectors);
  };

  const deselectAll = () => {
    setSelectedDetectors([]);
  };

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

    try {
      const token = localStorage.getItem('token');
      
      const response = await axios.post(
        process.env.REACT_APP_API_URL + '/scans/',
        {
          target: target,
          scan_type: 'web_security',
          enabled_detectors: selectedDetectors,
        },
        { headers: { 'Authorization': `Bearer ${token}` } }
      );

      const scanId = response.data.id;
      
      // Redirect to scan details
      navigate(`/results/${scanId}`);
      
    } catch (err) {
      console.error('Scan failed:', err);
      setScanning(false);
      
      if (err.response?.status === 403) {
        alert(err.response?.data?.detail || 'Permission denied. Please upgrade your plan.');
      } else if (err.response?.status === 402) {
        alert('Daily or monthly scan limit exceeded. Please upgrade your plan.');
      } else {
        alert(err.response?.data?.detail || err.response?.data?.error || 'Failed to start scan');
      }
    }
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-64">
          <FiLoader className="w-8 h-8 animate-spin text-primary" />
        </div>
      </DashboardLayout>
    );
  }

  if (!category.is_allowed) {
    return (
      <DashboardLayout>
        <div className="max-w-3xl mx-auto py-8">
          <div className={`p-8 rounded-lg border-2 ${
            isDark ? 'bg-gray-800 border-yellow-700' : 'bg-yellow-50 border-yellow-300'
          }`}>
            <div className="flex items-center gap-3 mb-4">
              <FiLock className="w-8 h-8 text-yellow-600" />
              <h2 className="text-2xl font-bold">Locked Category</h2>
            </div>
            <p className={`mb-4 ${isDark ? 'text-gray-300' : 'text-gray-700'}`}>
              The <strong>{category.name}</strong> category requires a <strong>{category.required_plan}</strong> plan.
            </p>
            <p className={`mb-6 ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>
              {category.description}
            </p>
            <div className="flex gap-3">
              <Link
                to="/subscription"
                className="px-6 py-3 bg-gradient-to-r from-purple-600 to-blue-600 text-white font-semibold rounded-lg hover:from-purple-700 hover:to-blue-700 transition"
              >
                Upgrade to {category.required_plan}
              </Link>
              <Link
                to="/dashboard"
                className={`px-6 py-3 rounded-lg font-semibold transition ${
                  isDark ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-200 hover:bg-gray-300'
                }`}
              >
                Back to Dashboard
              </Link>
            </div>
          </div>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="max-w-6xl mx-auto py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <span className="text-4xl">{category.icon}</span>
            <h1 className="text-3xl font-bold">{category.name}</h1>
          </div>
          <p className={isDark ? 'text-gray-400' : 'text-gray-600'}>
            {category.description}
          </p>
        </div>

        {/* Scan Limits */}
        {scanLimits && (
          <div className={`mb-6 p-4 rounded-lg ${
            isDark ? 'bg-gray-800' : 'bg-gray-50'
          }`}>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className={`text-sm ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>Daily Scans:</span>
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-bold text-primary">{scanLimits.dailyRemaining}</span>
                  <span className={`text-sm ${isDark ? 'text-gray-500' : 'text-gray-500'}`}>
                    / {scanLimits.dailyLimit} remaining
                  </span>
                </div>
              </div>
              <div>
                <span className={`text-sm ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>Monthly Scans:</span>
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-bold text-primary">{scanLimits.monthlyRemaining}</span>
                  <span className={`text-sm ${isDark ? 'text-gray-500' : 'text-gray-500'}`}>
                    / {scanLimits.monthlyLimit} remaining
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Detector Selection */}
          <div className="lg:col-span-1">
            <div className={`p-6 rounded-lg ${isDark ? 'bg-gray-800' : 'bg-white border border-gray-200'}`}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Detectors ({detectors.length})</h3>
                <div className="flex gap-2">
                  <button
                    onClick={selectAll}
                    className="text-xs px-2 py-1 text-primary hover:underline"
                  >
                    All
                  </button>
                  <button
                    onClick={deselectAll}
                    className="text-xs px-2 py-1 text-primary hover:underline"
                  >
                    None
                  </button>
                </div>
              </div>
              
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {detectors.map((detector) => {
                  const isSelected = selectedDetectors.includes(detector.name);
                  const isAllowed = detector.is_allowed;
                  
                  return (
                    <label
                      key={detector.name}
                      className={`flex items-start gap-3 p-3 rounded-lg cursor-pointer transition ${
                        isAllowed
                          ? isDark
                            ? 'hover:bg-gray-700'
                            : 'hover:bg-gray-50'
                          : isDark
                          ? 'bg-gray-900/50 opacity-60'
                          : 'bg-gray-100 opacity-60'
                      }`}
                      onClick={() => toggleDetector(detector.name, isAllowed)}
                    >
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => {}}
                        disabled={!isAllowed}
                        className="mt-1"
                      />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">
                            {detector.name.replace(/_/g, ' ').replace('detector', '').trim()}
                          </span>
                          {!isAllowed && <FiLock className="w-3 h-3 text-yellow-600" />}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Scan Form */}
          <div className="lg:col-span-2">
            <form onSubmit={handleStartScan} className={`p-6 rounded-lg ${
              isDark ? 'bg-gray-800' : 'bg-white border border-gray-200'
            }`}>
              <h3 className="text-lg font-semibold mb-4">Scan Configuration</h3>
              
              {/* Target URL */}
              <div className="mb-4">
                <label className={`block text-sm font-medium mb-2 ${
                  isDark ? 'text-gray-300' : 'text-gray-700'
                }`}>
                  Target URL *
                </label>
                <input
                  type="url"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://example.com"
                  className={`w-full px-4 py-3 rounded-lg border ${
                    isDark
                      ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400'
                      : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
                  } focus:ring-2 focus:ring-primary focus:border-transparent`}
                  required
                />
              </div>

              {/* Selected Detectors Summary */}
              <div className="mb-4">
                <label className={`block text-sm font-medium mb-2 ${
                  isDark ? 'text-gray-300' : 'text-gray-700'
                }`}>
                  Selected Detectors
                </label>
                <div className={`p-3 rounded-lg ${
                  isDark ? 'bg-gray-700' : 'bg-gray-50'
                }`}>
                  <span className="text-sm">
                    {selectedDetectors.length} of {detectors.filter(d => d.is_allowed).length} available detectors selected
                  </span>
                </div>
              </div>

              {/* Disclaimer */}
              <div className="mb-6">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={acceptDisclaimer}
                    onChange={(e) => setAcceptDisclaimer(e.target.checked)}
                    className="mt-1"
                  />
                  <span className="text-sm">
                    I confirm that I have authorization to scan this target and accept responsibility for this scan.
                  </span>
                </label>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={scanning || selectedDetectors.length === 0 || !acceptDisclaimer}
                className="w-full px-6 py-3 bg-gradient-to-r from-purple-600 to-blue-600 text-white font-semibold rounded-lg hover:from-purple-700 hover:to-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {scanning ? (
                  <>
                    <FiLoader className="w-5 h-5 animate-spin" />
                    Starting Scan...
                  </>
                ) : (
                  <>
                    <FiPlay className="w-5 h-5" />
                    Start Scan
                  </>
                )}
              </button>
            </form>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default DetectorCategoryScan;
