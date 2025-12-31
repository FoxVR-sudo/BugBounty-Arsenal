import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { authService } from '../services/api';
import { FiMail, FiLock, FiShield, FiUser, FiPhone, FiMapPin } from 'react-icons/fi';

const Register = () => {
  const [formData, setFormData] = useState({
    first_name: '',
    middle_name: '',
    last_name: '',
    email: '',
    phone: '',
    address: '',
    password: '',
    confirmPassword: '',
    acceptTerms: false,
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

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

    if (!formData.acceptTerms) {
      setError('You must accept the Terms and Conditions and Privacy Policy');
      return;
    }

    setLoading(true);

    try {
      // All new registrations start with Free plan
      const registrationData = {
        email: formData.email,
        password: formData.password,
        password_confirm: formData.confirmPassword,
        first_name: formData.first_name,
        middle_name: formData.middle_name,
        last_name: formData.last_name,
        phone: formData.phone,
        address: formData.address,
      };
      
      const registerResponse = await authService.register(registrationData);
      
      // Store tokens
      localStorage.setItem('token', registerResponse.data.access);
      localStorage.setItem('user', formData.email);
      
      // Proceed to phone verification
      navigate('/verify-phone');
    } catch (err) {
      console.error('Registration error:', err.response?.data);
      const errorMsg = err.response?.data?.errors 
        ? Object.entries(err.response.data.errors).map(([field, msgs]) => `${field}: ${msgs.join(', ')}`).join(' | ')
        : (err.response?.data?.detail || err.response?.data?.error || 'Registration failed. Please try again.');
      setError(errorMsg);
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
          <h2 className="text-2xl font-bold text-white">Create Free Account</h2>
          <p className="text-gray-400 mt-2">Start scanning for vulnerabilities - upgrade anytime</p>
        </div>

        <div className="bg-white rounded-lg shadow-xl p-8">
          {error && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit}>

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

            {/* Terms and Conditions */}
            <div className="mb-6">
              <label className="flex items-start gap-2">
                <input
                  type="checkbox"
                  name="acceptTerms"
                  checked={formData.acceptTerms}
                  onChange={(e) => setFormData({ ...formData, acceptTerms: e.target.checked })}
                  className="mt-1 w-4 h-4 text-primary border-gray-300 rounded focus:ring-primary"
                  required
                />
                <span className="text-sm text-gray-700">
                  I accept the{' '}
                  <Link to="/terms" target="_blank" className="text-primary hover:underline font-semibold">
                    Terms of Service
                  </Link>
                  ,{' '}
                  <Link to="/privacy" target="_blank" className="text-primary hover:underline font-semibold">
                    Privacy Policy
                  </Link>
                  {' '}and{' '}
                  <Link to="/disclaimer" target="_blank" className="text-primary hover:underline font-semibold">
                    Disclaimer
                  </Link>
                  . I confirm that I will use BugBounty Arsenal for legal purposes only. *
                </span>
              </label>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full px-6 py-3 bg-primary text-white rounded-lg font-semibold hover:bg-primary-600 transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Creating account...' : 'Create Free Account'}
            </button>

            <p className="mt-4 text-center text-sm text-gray-600">
              🎉 Start with Free plan - upgrade to Pro anytime from your dashboard
            </p>
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
