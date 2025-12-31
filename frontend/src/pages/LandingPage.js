import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FiShield, FiZap, FiTarget, FiLock, FiDollarSign, FiCheck, FiCode, FiActivity } from 'react-icons/fi';
import axios from 'axios';

const LandingPage = () => {
  const [plans, setPlans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchPlans = async () => {
      try {
        const response = await axios.get('http://localhost:8001/api/plans/');
        setPlans(response.data);
      } catch (error) {
        console.error('Failed to fetch plans:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchPlans();
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-800 to-gray-900">
      {/* Header/Nav */}
      <nav className="container mx-auto px-6 py-4">
        <div className="flex justify-between items-center">
          <div className="text-2xl font-bold text-white flex items-center gap-2">
            <FiShield className="text-primary" />
            BugBounty Arsenal
          </div>
          <div className="flex gap-4">
            <Link to="/login" className="px-6 py-2 text-white hover:text-primary transition">
              Login
            </Link>
            <Link
              to="/register"
              className="px-6 py-2 bg-primary text-white rounded-lg hover:bg-primary-600 transition"
            >
              Get Started
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="container mx-auto px-6 py-20 text-center">
        <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
          Professional <span className="text-primary">Bug Bounty</span> Platform
        </h1>
        <p className="text-xl text-gray-300 mb-8 max-w-3xl mx-auto">
          Automated vulnerability scanning with 40+ detectors. Real-time results. No fake data.
          100% transparent security testing for modern applications.
        </p>
        <div className="flex gap-4 justify-center">
          <Link
            to="/register"
            className="px-8 py-4 bg-primary text-white rounded-lg text-lg font-semibold hover:bg-primary-600 transition flex items-center gap-2"
          >
            <FiZap /> Start Free Trial
          </Link>
          <a
            href="#features"
            className="px-8 py-4 border-2 border-primary text-primary rounded-lg text-lg font-semibold hover:bg-primary hover:text-white transition"
          >
            Learn More
          </a>
        </div>
        
        {/* Stats */}
        <div className="grid grid-cols-3 gap-8 mt-16 max-w-3xl mx-auto">
          <div className="text-center">
            <div className="text-4xl font-bold text-primary">40+</div>
            <div className="text-gray-400 mt-2">Security Detectors</div>
          </div>
          <div className="text-center">
            <div className="text-4xl font-bold text-primary">100%</div>
            <div className="text-gray-400 mt-2">Real Scanning</div>
          </div>
          <div className="text-center">
            <div className="text-4xl font-bold text-primary">24/7</div>
            <div className="text-gray-400 mt-2">Automated Monitoring</div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="bg-gray-800 py-20">
        <div className="container mx-auto px-6">
          <h2 className="text-4xl font-bold text-white text-center mb-12">
            Comprehensive Security Testing
          </h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
            <FeatureCard
              icon={<FiTarget />}
              title="Reconnaissance"
              items={[
                'Subdomain Takeover',
                'Directory Listing',
                'Security Headers',
                'Secret Detection',
                'CORS Analysis',
                'GraphQL Discovery',
              ]}
            />
            <FeatureCard
              icon={<FiCode />}
              title="Web Security"
              items={[
                'XSS Detection',
                'SQL Injection',
                'LFI/RFI',
                'CSRF',
                'XXE',
                'SSTI',
                'Command Injection',
              ]}
            />
            <FeatureCard
              icon={<FiLock />}
              title="API Security"
              items={[
                'JWT Vulnerabilities',
                'OAuth Flaws',
                'Rate Limit Bypass',
                'IDOR',
                'NoSQL Injection',
                'GraphQL Injection',
              ]}
            />
            <FeatureCard
              icon={<FiActivity />}
              title="Advanced"
              items={[
                'SSRF (+ OOB)',
                'Race Conditions',
                'Cache Poisoning',
                'Prototype Pollution',
                'CVE Database',
                'Brute Force',
              ]}
            />
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className="py-20">
        <div className="container mx-auto px-6">
          <h2 className="text-4xl font-bold text-white text-center mb-12">
            Transparent Pricing
          </h2>
          {loading ? (
            <div className="text-center text-white">Loading plans...</div>
          ) : (
            <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
              {plans.map((plan) => (
                <PricingCard
                  key={plan.id}
                  plan={plan}
                  highlighted={plan.is_popular}
                />
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Security & Privacy */}
      <section className="bg-gray-800 py-20">
        <div className="container mx-auto px-6">
          <h2 className="text-4xl font-bold text-white text-center mb-12">
            Security & Privacy First
          </h2>
          <div className="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
            <div className="bg-gray-900 p-6 rounded-lg">
              <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <FiShield className="text-primary" /> Data Protection
              </h3>
              <ul className="text-gray-300 space-y-2">
                <li>• End-to-end encryption</li>
                <li>• No data retention policy</li>
                <li>• Scan results deleted after 30 days</li>
                <li>• GDPR compliant</li>
                <li>• ISO 27001 certified infrastructure</li>
              </ul>
            </div>
            <div className="bg-gray-900 p-6 rounded-lg">
              <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <FiLock className="text-primary" /> Responsible Scanning
              </h3>
              <ul className="text-gray-300 space-y-2">
                <li>• Rate limiting to prevent service disruption</li>
                <li>• Non-destructive testing only</li>
                <li>• Respects robots.txt</li>
                <li>• Scope validation</li>
                <li>• Legal compliance checks</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Payment Methods */}
      <section className="py-20">
        <div className="container mx-auto px-6">
          <h2 className="text-4xl font-bold text-white text-center mb-12">
            Flexible Payment Options
          </h2>
          <div className="grid md:grid-cols-4 gap-6 max-w-4xl mx-auto">
            <div className="bg-gray-800 p-6 rounded-lg text-center">
              <FiDollarSign className="text-4xl text-primary mx-auto mb-2" />
              <div className="text-white font-semibold">Credit Card</div>
              <div className="text-gray-400 text-sm">Visa, Mastercard, Amex</div>
            </div>
            <div className="bg-gray-800 p-6 rounded-lg text-center">
              <FiDollarSign className="text-4xl text-primary mx-auto mb-2" />
              <div className="text-white font-semibold">PayPal</div>
              <div className="text-gray-400 text-sm">Secure payments</div>
            </div>
            <div className="bg-gray-800 p-6 rounded-lg text-center">
              <FiDollarSign className="text-4xl text-primary mx-auto mb-2" />
              <div className="text-white font-semibold">Crypto</div>
              <div className="text-gray-400 text-sm">BTC, ETH, USDT</div>
            </div>
            <div className="bg-gray-800 p-6 rounded-lg text-center">
              <FiDollarSign className="text-4xl text-primary mx-auto mb-2" />
              <div className="text-white font-semibold">Invoice</div>
              <div className="text-gray-400 text-sm">Enterprise only</div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

const FeatureCard = ({ icon, title, items }) => (
  <div className="bg-gray-900 p-6 rounded-lg">
    <div className="text-3xl text-primary mb-4">{icon}</div>
    <h3 className="text-xl font-bold text-white mb-4">{title}</h3>
    <ul className="text-gray-400 space-y-2 text-sm">
      {items.map((item, i) => (
        <li key={i} className="flex items-start gap-2">
          <FiCheck className="text-primary mt-1 flex-shrink-0" />
          {item}
        </li>
      ))}
    </ul>
  </div>
);

const PricingCard = ({ plan, highlighted }) => {
  const isFree = plan.price === 0 || plan.price === '0.00';
  const isEnterprise = plan.name === 'enterprise';
  
  return (
    <div
      className={`p-8 rounded-lg ${
        highlighted
          ? 'bg-primary border-2 border-primary transform scale-105'
          : 'bg-gray-800 border-2 border-gray-700'
      }`}
    >
      <h3 className="text-2xl font-bold text-white mb-2">{plan.display_name}</h3>
      <div className="mb-6">
        <span className="text-4xl font-bold text-white">
          {isFree ? 'Free' : `$${plan.price}`}
        </span>
        <span className="text-gray-400 ml-2">
          / {isFree ? 'forever' : 'per month'}
        </span>
      </div>
      <ul className="space-y-3 mb-8">
        <li className="flex items-start gap-2 text-gray-300">
          <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
          {plan.daily_scan_limit === -1 ? 'Unlimited' : plan.daily_scan_limit} scans per day
        </li>
        <li className="flex items-start gap-2 text-gray-300">
          <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
          {plan.monthly_scan_limit === -1 ? 'Unlimited' : plan.monthly_scan_limit} scans per month
        </li>
        {plan.features && plan.features.length > 0 ? (
          plan.features.map((feature, i) => (
            <li key={i} className="flex items-start gap-2 text-gray-300">
              <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
              {feature}
            </li>
          ))
        ) : (
          <>
            {plan.allow_teams && (
              <li className="flex items-start gap-2 text-gray-300">
                <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
                Team collaboration ({plan.max_team_members} members)
              </li>
            )}
            {plan.allow_integrations && (
              <li className="flex items-start gap-2 text-gray-300">
                <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
                Integrations ({plan.max_integrations} max)
              </li>
            )}
            {plan.allow_dangerous_tools && (
              <li className="flex items-start gap-2 text-gray-300">
                <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
                Dangerous tools & custom payloads
              </li>
            )}
          </>
        )}
      </ul>
      <Link
        to="/register"
        className={`block text-center px-6 py-3 rounded-lg font-semibold transition ${
          highlighted
            ? 'bg-white text-primary hover:bg-gray-100'
            : 'bg-primary text-white hover:bg-primary-600'
        }`}
      >
        {isFree ? 'Start Free' : isEnterprise ? 'Contact Sales' : `Get ${plan.display_name}`}
      </Link>
    </div>
  );
};

export default LandingPage;
