import React from 'react';
import { useNavigate } from 'react-router-dom';
import DashboardLayout from '../components/DashboardLayout';
import { FiCheck, FiX } from 'react-icons/fi';

const Pricing = () => {
  const navigate = useNavigate();

  return (
    <DashboardLayout>
      <div className="p-8">
        <div className="mb-8 text-center">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">Choose Your Plan</h1>
          <p className="text-xl text-gray-600">Unlock powerful security scanning features</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-6xl mx-auto">
          {/* Free Plan */}
          <div className="bg-white rounded-lg shadow-lg p-8 border-2 border-gray-200">
            <div className="text-center mb-6">
              <h3 className="text-2xl font-bold text-gray-900 mb-2">Free</h3>
              <div className="text-4xl font-bold text-gray-900 mb-2">$0</div>
              <div className="text-gray-600">forever</div>
            </div>
            
            <ul className="space-y-3 mb-8">
              <li className="flex items-start gap-2">
                <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
                <span>5 scans per day</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
                <span>Recon scanner</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
                <span>Web security scanner</span>
              </li>
              <li className="flex items-start gap-2">
                <FiX className="text-gray-400 mt-1 flex-shrink-0" />
                <span className="text-gray-400">API scanner</span>
              </li>
              <li className="flex items-start gap-2">
                <FiX className="text-gray-400 mt-1 flex-shrink-0" />
                <span className="text-gray-400">Vulnerability scanner</span>
              </li>
              <li className="flex items-start gap-2">
                <FiX className="text-gray-400 mt-1 flex-shrink-0" />
                <span className="text-gray-400">Mobile scanner</span>
              </li>
            </ul>

            <button
              onClick={() => navigate('/dashboard')}
              className="w-full py-3 px-6 bg-gray-200 text-gray-700 rounded-lg font-semibold hover:bg-gray-300 transition"
            >
              Current Plan
            </button>
          </div>

          {/* Pro Plan */}
          <div className="bg-gradient-to-br from-purple-600 to-pink-600 rounded-lg shadow-2xl p-8 border-4 border-yellow-400 transform scale-105">
            <div className="text-center mb-2">
              <span className="bg-yellow-400 text-yellow-900 px-3 py-1 rounded-full text-sm font-bold">RECOMMENDED</span>
            </div>
            <div className="text-center mb-6 text-white">
              <h3 className="text-2xl font-bold mb-2">Pro</h3>
              <div className="text-4xl font-bold mb-2">$49</div>
              <div className="text-purple-100">per month</div>
            </div>
            
            <ul className="space-y-3 mb-8 text-white">
              <li className="flex items-start gap-2">
                <FiCheck className="mt-1 flex-shrink-0" />
                <span>50 scans per day</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="mt-1 flex-shrink-0" />
                <span>All Free features</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="mt-1 flex-shrink-0" />
                <span>API security scanner</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="mt-1 flex-shrink-0" />
                <span>Vulnerability scanner</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="mt-1 flex-shrink-0" />
                <span>Mobile scanner</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="mt-1 flex-shrink-0" />
                <span>Team collaboration</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="mt-1 flex-shrink-0" />
                <span>Priority support</span>
              </li>
            </ul>

            <button
              onClick={() => alert('Contact admin@bugbountyarsenal.com to upgrade')}
              className="w-full py-3 px-6 bg-white text-purple-600 rounded-lg font-bold hover:bg-gray-100 transition shadow-lg"
            >
              Upgrade to Pro
            </button>
          </div>

          {/* Enterprise Plan */}
          <div className="bg-white rounded-lg shadow-lg p-8 border-2 border-gray-200">
            <div className="text-center mb-6">
              <h3 className="text-2xl font-bold text-gray-900 mb-2">Enterprise</h3>
              <div className="text-4xl font-bold text-gray-900 mb-2">Custom</div>
              <div className="text-gray-600">contact us</div>
            </div>
            
            <ul className="space-y-3 mb-8">
              <li className="flex items-start gap-2">
                <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
                <span>Unlimited scans</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
                <span>All Pro features</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
                <span>Custom scanners</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
                <span>Dangerous detectors</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
                <span>API access</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
                <span>Dedicated support</span>
              </li>
              <li className="flex items-start gap-2">
                <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
                <span>Custom integrations</span>
              </li>
            </ul>

            <button
              onClick={() => alert('Contact sales@bugbountyarsenal.com for Enterprise plan')}
              className="w-full py-3 px-6 bg-gray-900 text-white rounded-lg font-semibold hover:bg-gray-800 transition"
            >
              Contact Sales
            </button>
          </div>
        </div>

        <div className="text-center mt-12">
          <button
            onClick={() => navigate('/dashboard')}
            className="px-6 py-3 text-gray-600 hover:text-gray-900 font-semibold"
          >
            ← Back to Dashboard
          </button>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Pricing;
