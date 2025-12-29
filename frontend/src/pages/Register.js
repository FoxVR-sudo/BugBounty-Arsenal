import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { authService } from '../services/api';
import { FiMail, FiLock, FiShield, FiUser, FiPhone, FiMapPin, FiCheck } from 'react-icons/fi';
import axios from 'axios';

const Register = () => {
  // V3.0: Extended user fields + plan selection
  const [formData, setFormData] = useState({
    first_name: '',
    middle_name: '',
    last_name: '',
    email: '',
    phone: '',
    address: '',
    password: '',
    confirmPassword: '',
    plan_id: '', // Selected plan
  });
  const [plans, setPlans] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  // Fetch available plans on mount (Free and Pro only)
  useEffect(() => {
    const fetchPlans = async () => {
      try {
        const API_URL = process.env.REACT_APP_API_URL || 'http://127.0.0.1:8001/api';
        const response = await axios.get(`${API_URL}/plans/`);
        // Filter out Enterprise plan - it has separate registration
        const individualPlans = response.data.filter(p => p.name.toLowerCase() !== 'enterprise');
        setPlans(individualPlans);
        // Pre-select Free plan by default
        const freePlan = individualPlans.find(p => p.name.toLowerCase() === 'free');
        if (freePlan) {
          setFormData(prev => ({ ...prev, plan_id: freePlan.id }));
        }
      } catch (err) {
        console.error('Failed to fetch plans:', err);
      }
    };
    fetchPlans();
  }, []);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    // Validation
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    if (!formData.first_name || !formData.last_name) {
      setError('First name and last name are required');
      return;
    }

    if (!formData.phone) {
      setError('Phone number is required');
      return;
    }

    setLoading(true);

    try {
      // V3.0: Send extended registration data with plan selection
      const registrationData = {
        email: formData.email,
        password: formData.password,
        password_confirm: formData.confirmPassword, // Backend requires this
        first_name: formData.first_name,
        middle_name: formData.middle_name,
        last_name: formData.last_name,
        phone: formData.phone,
        address: formData.address,
        plan_id: formData.plan_id, // Include selected plan
      };
      
      const registerResponse = await authService.register(registrationData);
      
      // Store tokens
      localStorage.setItem('token', registerResponse.data.access);
      localStorage.setItem('user', formData.email);
      
      // Check if payment is required (Pro/Enterprise plan)
      if (registerResponse.data.requires_payment && registerResponse.data.checkout_url) {
        // Redirect to Stripe checkout
        window.location.href = registerResponse.data.checkout_url;
      } else {
        // Free plan or payment not required - proceed to phone verification
        navigate('/verify-phone');
      }
    } catch (err) {
      setError(err.response?.data?.detail || err.response?.data?.error || 'Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center px-4">
      <div className="max-w-md w-full">
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2 text-3xl font-bold text-white mb-4">
            <FiShield className="text-primary" />
            BugBounty Arsenal
          </Link>
          <h2 className="text-2xl font-bold text-white">Create Account</h2>
          <p className="text-gray-400 mt-2">Start scanning for vulnerabilities</p>
        </div>

        <div className="bg-white rounded-lg shadow-xl p-8">
          {error && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit}>
            {/* Plan Selection */}
            <div className="mb-6">
              <label className="block text-gray-700 font-semibold mb-3">Choose Your Plan *</label>
              <div className="grid grid-cols-1 gap-3">
                {plans.map((plan) => (
                  <div
                    key={plan.id}
                    onClick={() => setFormData({ ...formData, plan_id: plan.id })}
                    className={`relative cursor-pointer p-4 border-2 rounded-lg transition ${
                      formData.plan_id === plan.id
                        ? 'border-primary bg-primary bg-opacity-5'
                        : 'border-gray-200 hover:border-gray-300'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${
                          formData.plan_id === plan.id ? 'border-primary bg-primary' : 'border-gray-300'
                        }`}>
                          {formData.plan_id === plan.id && (
                            <FiCheck className="text-white" size={14} />
                          )}
                        </div>
                        <div>
                          <div className="font-bold text-gray-900">
                            {plan.name}
                            {plan.is_popular && (
                              <span className="ml-2 text-xs bg-primary text-white px-2 py-0.5 rounded-full">
                                Popular
                              </span>
                            )}
                          </div>
                          <div className="text-sm text-gray-600 mt-0.5">{plan.description}</div>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-2xl font-bold text-gray-900">
                          {plan.price === 0 ? 'Free' : `$${plan.price}`}
                        </div>
                        {plan.price > 0 && (
                          <div className="text-xs text-gray-500">/month</div>
                        )}
                      </div>
                    </div>
                    {/* Show key features */}
                    <div className="mt-2 ml-8 text-xs text-gray-500">
                      {plan.features?.slice(0, 3).map((feature, idx) => (
                        <div key={idx} className="flex items-center gap-1">
                          <FiCheck size={12} className="text-primary" />
                          <span>{feature.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              <p className="text-xs text-gray-500 mt-2">
                {plans.find(p => p.id === formData.plan_id)?.price > 0
                  ? '💳 You will be redirected to secure payment after registration'
                  : '✓ No payment required'}
              </p>
              <div className="mt-3 text-center">
                <span className="text-sm text-gray-600">Enterprise plan? </span>
                <Link to="/register-enterprise" className="text-sm text-primary font-semibold hover:text-primary-600">
                  Register as company →
                </Link>
              </div>
            </div>

            {/* V3.0: Three names required */}
            <div className="grid grid-cols-3 gap-4 mb-4">
              <div>
                <label className="block text-gray-700 font-semibold mb-2 text-sm">First Name *</label>
                <div className="relative">
                  <FiUser className="absolute left-3 top-3 text-gray-400" size={16} />
                  <input
                    type="text"
                    name="first_name"
                    value={formData.first_name}
                    onChange={handleChange}
                    className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                    placeholder="John"
                    required
                  />
                </div>
              </div>
              <div>
                <label className="block text-gray-700 font-semibold mb-2 text-sm">Middle Name</label>
                <input
                  type="text"
                  name="middle_name"
                  value={formData.middle_name}
                  onChange={handleChange}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="M."
                />
              </div>
              <div>
                <label className="block text-gray-700 font-semibold mb-2 text-sm">Last Name *</label>
                <input
                  type="text"
                  name="last_name"
                  value={formData.last_name}
                  onChange={handleChange}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="Doe"
                  required
                />
              </div>
            </div>

            {/* Email */}
            <div className="mb-4">
              <label className="block text-gray-700 font-semibold mb-2">Email *</label>
              <div className="relative">
                <FiMail className="absolute left-3 top-3 text-gray-400" />
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="your@email.com"
                  required
                />
              </div>
            </div>

            {/* Phone */}
            <div className="mb-4">
              <label className="block text-gray-700 font-semibold mb-2">Phone *</label>
              <div className="relative">
                <FiPhone className="absolute left-3 top-3 text-gray-400" />
                <input
                  type="tel"
                  name="phone"
                  value={formData.phone}
                  onChange={handleChange}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="+359888123456"
                  required
                />
              </div>
              <p className="text-xs text-gray-500 mt-1">Include country code (e.g., +359)</p>
            </div>

            {/* Address */}
            <div className="mb-4">
              <label className="block text-gray-700 font-semibold mb-2">Address *</label>
              <div className="relative">
                <FiMapPin className="absolute left-3 top-3 text-gray-400" />
                <input
                  type="text"
                  name="address"
                  value={formData.address}
                  onChange={handleChange}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="Street, City, Country"
                  required
                />
              </div>
            </div>

            {/* Password */}
            <div className="mb-4">
              <label className="block text-gray-700 font-semibold mb-2">Password *</label>
              <div className="relative">
                <FiLock className="absolute left-3 top-3 text-gray-400" />
                <input
                  type="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="••••••••"
                  required
                />
              </div>
            </div>

            {/* Confirm Password */}
            <div className="mb-6">
              <label className="block text-gray-700 font-semibold mb-2">Confirm Password *</label>
              <div className="relative">
                <FiLock className="absolute left-3 top-3 text-gray-400" />
                <input
                  type="password"
                  name="confirmPassword"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="••••••••"
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full px-6 py-3 bg-primary text-white rounded-lg font-semibold hover:bg-primary-600 transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Creating account...' : 'Create Account'}
            </button>
          </form>

          <div className="mt-6 text-center text-sm">
            <span className="text-gray-600">Already have an account? </span>
            <Link to="/login" className="text-primary font-semibold hover:text-primary-600">
              Sign in
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;
