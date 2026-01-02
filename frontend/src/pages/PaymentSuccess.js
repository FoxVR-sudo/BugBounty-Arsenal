import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FiCheckCircle, FiArrowRight } from 'react-icons/fi';
import { useTheme } from '../contexts/ThemeContext';

const PaymentSuccess = () => {
  const { isDark } = useTheme();
  const [countdown, setCountdown] = useState(5);
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          navigate('/verify-phone');
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [navigate]);

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center px-4">
      <div className="max-w-md w-full">
        <div className="bg-white rounded-lg shadow-xl p-8 text-center">
          <div className="mb-6">
            <div className="inline-flex items-center justify-center w-20 h-20 bg-green-100 rounded-full">
              <FiCheckCircle className="text-green-600" size={48} />
            </div>
          </div>
          <h1 className={`text-3xl font-bold mb-4 ${isDark ? 'text-white' : 'text-gray-900'}`}>Payment Successful!</h1>
          <p className="text-gray-600 mb-6">Thank you for your purchase. Your subscription has been activated successfully.</p>
          <div className="bg-gray-50 rounded-lg p-6 mb-6">
            <p className="text-sm text-gray-600 mb-2">Redirecting to phone verification in</p>
            <div className="text-4xl font-bold text-primary mb-2">{countdown}</div>
            <p className="text-xs text-gray-500">seconds</p>
          </div>
          <button onClick={() => navigate('/verify-phone')} className="w-full px-6 py-3 bg-primary text-white rounded-lg font-semibold hover:bg-primary-600 transition flex items-center justify-center gap-2">
            Continue Now <FiArrowRight />
          </button>
          <p className="text-xs text-gray-500 mt-4">You can view your subscription details in your dashboard</p>
        </div>
      </div>
    </div>
  );
};

export default PaymentSuccess;
