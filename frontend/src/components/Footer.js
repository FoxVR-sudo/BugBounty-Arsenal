import React from 'react';
import { Link } from 'react-router-dom';
import { FiShield, FiMail, FiGithub } from 'react-icons/fi';

const Footer = () => {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="bg-gray-900 text-gray-300 border-t border-gray-800">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand */}
          <div className="col-span-1">
            <div className="flex items-center gap-2 text-white font-bold text-lg mb-4">
              <FiShield className="text-primary" />
              BugBounty Arsenal
            </div>
            <p className="text-sm text-gray-400">
              Автоматизиран скенер за уязвимости за ethical hackers и security researchers.
            </p>
          </div>

          {/* Legal */}
          <div>
            <h3 className="text-white font-semibold mb-4">Правна информация</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <Link to="/terms" className="hover:text-primary transition">
                  Общи условия
                </Link>
              </li>
              <li>
                <Link to="/privacy" className="hover:text-primary transition">
                  Политика за поверителност
                </Link>
              </li>
              <li>
                <Link to="/disclaimer" className="hover:text-primary transition">
                  Отказ от отговорност
                </Link>
              </li>
              <li>
                <Link to="/responsible-disclosure" className="hover:text-primary transition">
                  Responsible Disclosure
                </Link>
              </li>
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h3 className="text-white font-semibold mb-4">Ресурси</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <Link to="/docs" className="hover:text-primary transition">
                  Документация
                </Link>
              </li>
              <li>
                <Link to="/usage-guide" className="hover:text-primary transition">
                  Ръководство за употреба
                </Link>
              </li>
              <li>
                <Link to="/faq" className="hover:text-primary transition">
                  Често задавани въпроси
                </Link>
              </li>
              <li>
                <a 
                  href="https://github.com/yourusername/bugbounty-arsenal" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="hover:text-primary transition inline-flex items-center gap-1"
                >
                  <FiGithub className="w-4 h-4" />
                  GitHub
                </a>
              </li>
            </ul>
          </div>

          {/* Contact */}
          <div>
            <h3 className="text-white font-semibold mb-4">Контакти</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <Link to="/contact" className="hover:text-primary transition">
                  Свържете се с нас
                </Link>
              </li>
              <li>
                <a 
                  href="mailto:support@bugbountyarsenal.com" 
                  className="hover:text-primary transition inline-flex items-center gap-1"
                >
                  <FiMail className="w-4 h-4" />
                  support@bugbountyarsenal.com
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="border-t border-gray-800 mt-8 pt-6 text-sm text-gray-400 text-center">
          <p>
            © {currentYear} BugBounty Arsenal. Всички права запазени.
          </p>
          <p className="mt-2 text-xs">
            Този инструмент е предназначен само за легално тестване на собствени или упълномощени системи.
            Неразрешеното сканиране на чужди системи е незаконно.
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
