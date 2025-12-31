import React, { useState, useEffect } from 'react';
import { FiX, FiCookie } from 'react-icons/fi';
import { Link } from 'react-router-dom';

const CookieConsent = () => {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    // Check if user has already accepted cookies
    const hasAccepted = localStorage.getItem('cookieConsent');
    if (!hasAccepted) {
      setIsVisible(true);
    }
  }, []);

  const handleAccept = () => {
    localStorage.setItem('cookieConsent', 'accepted');
    setIsVisible(false);
  };

  const handleDecline = () => {
    localStorage.setItem('cookieConsent', 'declined');
    setIsVisible(false);
  };

  if (!isVisible) return null;

  return (
    <div className="fixed bottom-0 left-0 right-0 z-50 bg-gray-900 border-t border-gray-700 shadow-lg">
      <div className="max-w-7xl mx-auto px-4 py-4">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-start gap-3 flex-1">
            <FiCookie className="text-primary text-2xl mt-1 flex-shrink-0" />
            <div className="text-sm text-gray-300">
              <p className="font-semibold text-white mb-1">
                Този сайт използва бисквитки (cookies)
              </p>
              <p>
                Използваме бисквитки за подобряване на вашето изживяване, анализ на трафика и 
                персонализация на съдържанието. Продължавайки да използвате сайта, вие се съгласявате 
                с нашата{' '}
                <Link to="/privacy" className="text-primary hover:underline">
                  Политика за поверителност
                </Link>
                {' '}и{' '}
                <Link to="/terms" className="text-primary hover:underline">
                  Общи условия
                </Link>
                .
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 flex-shrink-0">
            <button
              onClick={handleDecline}
              className="px-4 py-2 text-sm text-gray-400 hover:text-white transition"
            >
              Отказ
            </button>
            <button
              onClick={handleAccept}
              className="px-6 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition text-sm font-medium"
            >
              Приемам
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CookieConsent;
