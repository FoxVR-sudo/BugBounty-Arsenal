import React from 'react';
import { Link } from 'react-router-dom';
import { FiShield, FiMail } from 'react-icons/fi';

const Footer = () => {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="bg-gray-900/80 backdrop-blur-xl text-gray-300 border-t border-gray-800/50 shadow-2xl">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand */}
          <div className="col-span-1">
            <div className="flex items-center gap-2 text-white font-bold text-lg mb-4">
              <FiShield className="text-primary" />
              BugBounty Arsenal
            </div>
            <p className="text-sm text-gray-400">
              Automated vulnerability scanner for ethical hackers and security researchers.
            </p>
          </div>

          {/* Legal */}
          <div>
            <h3 className="text-white font-semibold mb-4">Legal</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <Link to="/terms" className="hover:text-primary transition">
                  Terms of Service
                </Link>
              </li>
              <li>
                <Link to="/privacy" className="hover:text-primary transition">
                  Privacy Policy
                </Link>
              </li>
              <li>
                <Link to="/disclaimer" className="hover:text-primary transition">
                  Disclaimer
                </Link>
              </li>
            </ul>
          </div>

          {/* Quick Links */}
          <div>
            <h3 className="text-white font-semibold mb-4">Quick Links</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <Link to="/pricing" className="hover:text-primary transition">
                  Pricing
                </Link>
              </li>
              <li>
                <Link to="/dashboard" className="hover:text-primary transition">
                  Dashboard
                </Link>
              </li>
            </ul>
          </div>

          {/* Contact */}
          <div>
            <h3 className="text-white font-semibold mb-4">Contact</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <Link to="/contact" className="hover:text-primary transition">
                  Contact Us
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
            © {currentYear} BugBounty Arsenal. All rights reserved.
          </p>
          <p className="mt-2 text-xs">
            This tool is designed for legal security testing only. Unauthorized scanning is illegal.
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
