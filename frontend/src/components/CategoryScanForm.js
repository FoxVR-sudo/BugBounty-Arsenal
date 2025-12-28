import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { FiSearch, FiCheckCircle, FiAlertCircle, FiLoader } from 'react-icons/fi';

const CategoryScanForm = ({ onScanCreated }) => {
  const [categories, setCategories] = useState([]);
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [detectors, setDetectors] = useState([]);
  const [selectedDetectors, setSelectedDetectors] = useState([]);
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingCategories, setLoadingCategories] = useState(true);
  const [error, setError] = useState('');
  const [userPlan, setUserPlan] = useState('free');
  const navigate = useNavigate();

  useEffect(() => {
    fetchCategories();
    fetchUserPlan();
  }, []);

  useEffect(() => {
    if (selectedCategory) {
      fetchDetectors(selectedCategory.id);
    }
  }, [selectedCategory]);

  const fetchUserPlan = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8001/api/subscriptions/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.data.results && response.data.results[0]) {
        setUserPlan(response.data.results[0].plan.name);
      }
    } catch (err) {
      console.error('Failed to fetch user plan:', err);
    }
  };

  const fetchCategories = async () => {
    setLoadingCategories(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8001/api/scan-categories/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setCategories(response.data);
    } catch (err) {
      setError('Failed to load scan categories');
    } finally {
      setLoadingCategories(false);
    }
  };

  const fetchDetectors = async (categoryId) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(
        `http://localhost:8001/api/scan-categories/${categoryId}/detectors/`,
        {
          headers: { 'Authorization': `Bearer ${token}` }
        }
      );
      setDetectors(response.data);
      // Auto-select all detectors by default
      setSelectedDetectors(response.data.map(d => d.name));
    } catch (err) {
      setError('Failed to load detectors');
    }
  };

  const handleCategorySelect = (category) => {
    setSelectedCategory(category);
    setError('');
  };

  const handleDetectorToggle = (detectorName) => {
    setSelectedDetectors(prev => 
      prev.includes(detectorName)
        ? prev.filter(d => d !== detectorName)
        : [...prev, detectorName]
    );
  };

  const handleSelectAll = () => {
    setSelectedDetectors(detectors.map(d => d.name));
  };

  const handleDeselectAll = () => {
    setSelectedDetectors([]);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!selectedCategory) {
      setError('Please select a scan category');
      return;
    }

    if (!target) {
      setError('Please enter a target URL');
      return;
    }

    if (selectedDetectors.length === 0) {
      setError('Please select at least one detector');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const token = localStorage.getItem('token');
      const response = await axios.post(
        'http://localhost:8001/api/scans/start-category-scan/',
        {
          target: target,
          category: selectedCategory.id,
          detectors: selectedDetectors,
          options: {
            concurrency: 10,
            timeout: 30
          }
        },
        {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          }
        }
      );

      // Reset form
      setTarget('');
      setSelectedCategory(null);
      setSelectedDetectors([]);
      setDetectors([]);

      // Notify parent component
      if (onScanCreated) {
        onScanCreated(response.data);
      }

      // Navigate to scan details
      navigate(`/scan/details/${response.data.id}`);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-100 text-red-800 border-red-200',
      high: 'bg-orange-100 text-orange-800 border-orange-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      low: 'bg-green-100 text-green-800 border-green-200',
      info: 'bg-blue-100 text-blue-800 border-blue-200',
    };
    return colors[severity] || colors.info;
  };

  const getPlanBadgeColor = (requiredPlan) => {
    if (requiredPlan === 'free') return 'bg-gray-100 text-gray-700';
    if (requiredPlan === 'pro') return 'bg-blue-100 text-blue-700';
    return 'bg-purple-100 text-purple-700';
  };

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <h3 className="text-2xl font-bold mb-6 text-gray-900">Create Category-Based Scan</h3>

      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
          <FiAlertCircle className="text-red-600 mt-0.5 flex-shrink-0" />
          <p className="text-red-700 text-sm">{error}</p>
        </div>
      )}

      <form onSubmit={handleSubmit}>
        {/* Target URL */}
        <div className="mb-6">
          <label className="block text-gray-700 font-semibold mb-2">Target URL</label>
          <input
            type="url"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://example.com"
            className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
            required
          />
        </div>

        {/* Category Selection */}
        <div className="mb-6">
          <label className="block text-gray-700 font-semibold mb-3">Select Scan Category</label>
          
          {loadingCategories ? (
            <div className="flex justify-center py-8">
              <FiLoader className="animate-spin text-primary" size={32} />
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {categories.map((category) => (
                <button
                  key={category.id}
                  type="button"
                  onClick={() => handleCategorySelect(category)}
                  className={`p-4 border-2 rounded-lg text-left transition ${
                    selectedCategory?.id === category.id
                      ? 'border-primary bg-primary bg-opacity-5'
                      : 'border-gray-200 hover:border-primary hover:bg-gray-50'
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <span className="text-2xl">{category.icon}</span>
                    {category.is_enterprise_only && (
                      <span className="text-xs px-2 py-0.5 rounded bg-purple-100 text-purple-700 font-semibold">
                        ENT
                      </span>
                    )}
                    {category.required_plan === 'pro' && (
                      <span className="text-xs px-2 py-0.5 rounded bg-blue-100 text-blue-700 font-semibold">
                        PRO
                      </span>
                    )}
                  </div>
                  <h4 className="font-bold text-gray-900 mb-1">{category.display_name}</h4>
                  <p className="text-xs text-gray-600 mb-2">{category.description}</p>
                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <span>{category.detector_count} detectors</span>
                    {category.dangerous_detector_count > 0 && (
                      <span className="text-red-600 font-semibold">
                        {category.dangerous_detector_count} dangerous
                      </span>
                    )}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Detector Selection */}
        {selectedCategory && detectors.length > 0 && (
          <div className="mb-6">
            <div className="flex items-center justify-between mb-3">
              <label className="block text-gray-700 font-semibold">
                Select Detectors ({selectedDetectors.length}/{detectors.length})
              </label>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={handleSelectAll}
                  className="text-xs px-3 py-1 bg-primary text-white rounded hover:bg-primary-600"
                >
                  Select All
                </button>
                <button
                  type="button"
                  onClick={handleDeselectAll}
                  className="text-xs px-3 py-1 bg-gray-200 text-gray-700 rounded hover:bg-gray-300"
                >
                  Deselect All
                </button>
              </div>
            </div>

            <div className="max-h-96 overflow-y-auto border border-gray-200 rounded-lg p-4">
              <div className="space-y-2">
                {detectors.map((detector) => (
                  <label
                    key={detector.id}
                    className="flex items-start gap-3 p-3 hover:bg-gray-50 rounded cursor-pointer transition"
                  >
                    <input
                      type="checkbox"
                      checked={selectedDetectors.includes(detector.name)}
                      onChange={() => handleDetectorToggle(detector.name)}
                      className="mt-1 w-4 h-4 text-primary focus:ring-primary border-gray-300 rounded"
                    />
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-semibold text-gray-900">{detector.display_name}</span>
                        <span className={`text-xs px-2 py-0.5 rounded border ${getSeverityColor(detector.severity)}`}>
                          {detector.severity.toUpperCase()}
                        </span>
                        {detector.is_dangerous && (
                          <span className="text-xs px-2 py-0.5 rounded bg-red-100 text-red-700 border border-red-200 font-semibold">
                            🔴 DANGEROUS
                          </span>
                        )}
                        {detector.is_beta && (
                          <span className="text-xs px-2 py-0.5 rounded bg-yellow-100 text-yellow-700 border border-yellow-200">
                            ⚠️ BETA
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-gray-600">{detector.description}</p>
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
          </div>
        )}

        {/* Submit Button */}
        <button
          type="submit"
          disabled={loading || !selectedCategory || selectedDetectors.length === 0}
          className="w-full px-6 py-3 bg-primary text-white rounded-lg font-semibold hover:bg-primary-600 transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <FiLoader className="animate-spin" />
              <span>Starting Scan...</span>
            </>
          ) : (
            <>
              <FiSearch />
              <span>Start Scan</span>
            </>
          )}
        </button>
      </form>
    </div>
  );
};

export default CategoryScanForm;
