import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FiShield, FiZap, FiTarget, FiLock, FiCheck, FiCode, FiActivity, FiCreditCard, FiFileText } from 'react-icons/fi';
import axios from 'axios';

const LandingPage = () => {
  const [plans, setPlans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchPlans = async () => {
      try {
        const response = await axios.get(process.env.REACT_APP_API_URL + '/plans/');
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
          Professional <span className="text-primary">Security Testing</span> Platform
        </h1>
        <p className="text-xl text-gray-300 mb-8 max-w-3xl mx-auto">
          Comprehensive security scanning with 40+ detectors across 6 specialized categories.
          Real-time vulnerability detection. Enterprise-grade infrastructure. 100% transparent results.
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
        <div className="grid grid-cols-5 gap-8 mt-16 max-w-5xl mx-auto">
          <div className="text-center">
            <div className="text-4xl font-bold text-primary">40+</div>
            <div className="text-gray-400 mt-2">Security Detectors</div>
          </div>
          <div className="text-center">
            <div className="text-4xl font-bold text-primary">6</div>
            <div className="text-gray-400 mt-2">Scan Categories</div>
          </div>
          <div className="text-center">
            <div className="text-4xl font-bold text-primary">24/7</div>
            <div className="text-gray-400 mt-2">Availability</div>
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
          <h2 className="text-4xl font-bold text-white text-center mb-4">
            Complete Security Testing Platform
          </h2>
          <p className="text-center text-gray-400 mb-12 max-w-3xl mx-auto">
            BugBounty Arsenal provides comprehensive security testing across 6 specialized categories 
            with 40+ advanced detectors. From reconnaissance to advanced exploitation techniques.
          </p>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            <FeatureCard
              icon={<FiTarget />}
              title="Reconnaissance Scan"
              items={[
                'Subdomain Takeover Detection',
                'Directory Listing Discovery',
                'Security Headers Analysis',
                'Secret & API Key Detection',
                'CORS Misconfiguration',
                'GraphQL Endpoint Discovery',
              ]}
            />
            <FeatureCard
              icon={<FiCode />}
              title="Web Application Scan"
              items={[
                'XSS Detection (All Types)',
                'SQL Injection (Advanced)',
                'LFI/RFI Path Traversal',
                'CSRF Token Bypass',
                'XXE Vulnerability',
                'SSTI Detection',
                'Command Injection',
              ]}
            />
            <FeatureCard
              icon={<FiLock />}
              title="API Security Scan"
              items={[
                'JWT Security Testing',
                'OAuth 2.0 Flow Analysis',
                'Rate Limit Bypass',
                'IDOR Detection',
                'NoSQL Injection',
                'GraphQL Injection',
              ]}
            />
            <FeatureCard
              icon={<FiActivity />}
              title="Vulnerability Assessment"
              items={[
                'SSRF (+ Out-of-Band)',
                'Race Condition Testing',
                'Cache Poisoning',
                'Prototype Pollution',
                'CVE Database Matching',
                'File Upload Vulnerabilities',
              ]}
            />
            <FeatureCard
              icon={<FiShield />}
              title="Mobile Security (Pro+)"
              items={[
                'iOS Security Testing',
                'Android Analysis',
                'API Endpoint Discovery',
                'Certificate Pinning',
                'Dynamic Exploitation',
                'Binary Analysis',
              ]}
            />
            <FeatureCard
              icon={<FiZap />}
              title="Custom Scan (Enterprise)"
              items={[
                'All 40+ Detectors',
                'Nuclei Integration',
                'Custom Payloads',
                'Brute Force Testing',
                'Parameter Fuzzing',
                'Advanced Techniques',
              ]}
            />
          </div>
        </div>
      </section>

      {/* Platform Capabilities */}
      <section className="py-20">
        <div className="container mx-auto px-6">
          <h2 className="text-4xl font-bold text-white text-center mb-12">
            Why Choose BugBounty Arsenal
          </h2>
          <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl">
              <div className="text-3xl mb-4">🚀</div>
              <h3 className="text-xl font-bold text-white mb-3">Real-Time Scanning</h3>
              <p className="text-gray-400">
                Get instant results with our distributed scanning infrastructure. 
                No waiting, no queues - start testing in seconds.
              </p>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl">
              <div className="text-3xl mb-4">📊</div>
              <h3 className="text-xl font-bold text-white mb-3">Detailed Reports</h3>
              <p className="text-gray-400">
                Export comprehensive reports in PDF, JSON, or CSV formats. 
                Full evidence including HTTP requests, responses, and screenshots.
              </p>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl">
              <div className="text-3xl mb-4">🔌</div>
              <h3 className="text-xl font-bold text-white mb-3">REST API Access</h3>
              <p className="text-gray-400">
                Integrate scanning into your CI/CD pipeline. 
                Full API documentation with SDKs for popular languages.
              </p>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl">
              <div className="text-3xl mb-4">👥</div>
              <h3 className="text-xl font-bold text-white mb-3">Team Collaboration</h3>
              <p className="text-gray-400">
                Share scans with your team members. 
                Role-based access control and audit logs for enterprise compliance.
              </p>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl">
              <div className="text-3xl mb-4">⚡</div>
              <h3 className="text-xl font-bold text-white mb-3">High Performance</h3>
              <p className="text-gray-400">
                Concurrent scanning with intelligent rate limiting. 
                Up to 20 parallel scans for Enterprise users.
              </p>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl">
              <div className="text-3xl mb-4">🛡️</div>
              <h3 className="text-xl font-bold text-white mb-3">Enterprise Security</h3>
              <p className="text-gray-400">
                SOC 2 Type II certified. PCI DSS compliant. 
                End-to-end encryption and zero-knowledge architecture.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className="bg-gray-800 py-20">
        <div className="container mx-auto px-6">
          <h2 className="text-4xl font-bold text-white text-center mb-4">
            Simple, Transparent Pricing
          </h2>
          <p className="text-center text-gray-400 mb-12">
            All plans include core features. Upgrade anytime as your needs grow.
          </p>
          {loading ? (
            <div className="text-center text-white">Loading plans...</div>
          ) : (
            <div className="grid md:grid-cols-3 gap-6 max-w-6xl mx-auto">
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
            Secure Payment Methods
          </h2>
          <div className="grid md:grid-cols-4 gap-6 max-w-4xl mx-auto">
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl text-center hover:bg-gray-700/50 transition">
              <FiCreditCard className="text-5xl text-primary mx-auto mb-3" />
              <div className="text-white font-semibold text-lg">Visa</div>
              <div className="text-gray-400 text-sm">Credit & Debit Cards</div>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl text-center hover:bg-gray-700/50 transition">
              <FiCreditCard className="text-5xl text-primary mx-auto mb-3" />
              <div className="text-white font-semibold text-lg">Mastercard</div>
              <div className="text-gray-400 text-sm">Credit & Debit Cards</div>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl text-center hover:bg-gray-700/50 transition">
              <FiCreditCard className="text-5xl text-primary mx-auto mb-3" />
              <div className="text-white font-semibold text-lg">Amex</div>
              <div className="text-gray-400 text-sm">American Express</div>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl text-center hover:bg-gray-700/50 transition">
              <FiFileText className="text-5xl text-blue-500 mx-auto mb-3" />
              <div className="text-white font-semibold text-lg">Bank Transfer</div>
              <div className="text-gray-400 text-sm">Enterprise only</div>
            </div>
          </div>
          <div className="text-center mt-8">
            <div className="inline-flex items-center gap-2 text-gray-400">
              <FiShield className="text-green-500" />
              <span>All payments processed securely via Stripe (PCI DSS Level 1)</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

const FeatureCard = ({ icon, title, items }) => (
  <div className="bg-gray-900/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl hover:bg-gray-800/50 hover:border-gray-600/50 hover:shadow-xl transition-all duration-300 cursor-pointer">
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
      className={`p-6 rounded-xl transition-all duration-300 flex flex-col ${
        highlighted
          ? 'bg-primary border-2 border-primary transform scale-105 hover:scale-110 hover:shadow-2xl'
          : 'bg-gray-800/50 backdrop-blur-lg border-2 border-gray-700/50 hover:bg-gray-700/50 hover:border-gray-600/50 hover:shadow-xl'
      }`}
    >
      {highlighted && (
        <div className="bg-white text-primary px-3 py-1 rounded-full text-xs font-bold inline-block mb-3">
          MOST POPULAR
        </div>
      )}
      <h3 className="text-xl font-bold text-white mb-2">{plan.display_name}</h3>
      <p className="text-gray-300 text-xs mb-3">{plan.description}</p>
      <div className="mb-4">
        <span className="text-3xl font-bold text-white">
          {isFree ? 'Free' : `$${plan.price}`}
        </span>
        <span className="text-gray-400 ml-2">
          / {isFree ? 'forever' : 'month'}
        </span>
      </div>
      
      <ul className="space-y-2 mb-6 text-sm flex-grow">
        {/* Scan Limits */}
        <li className="flex items-start gap-2 text-gray-300">
          <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
          <span>
            <strong>{plan.daily_scan_limit === -1 ? 'Unlimited' : plan.daily_scan_limit}</strong> scans/day,{' '}
            <strong>{plan.monthly_scan_limit === -1 ? 'Unlimited' : plan.monthly_scan_limit}</strong>/month
          </span>
        </li>
        
        {/* Concurrent Scans */}
        <li className="flex items-start gap-2 text-gray-300">
          <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
          {plan.concurrent_scans} concurrent scans
        </li>
        
        {/* Storage */}
        <li className="flex items-start gap-2 text-gray-300">
          <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
          {plan.storage_limit_mb >= 1000 ? `${(plan.storage_limit_mb / 1000).toFixed(0)} GB` : `${plan.storage_limit_mb} MB`} storage
        </li>
        
        {/* Retention */}
        <li className="flex items-start gap-2 text-gray-300">
          <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
          {plan.retention_days}-day result retention
        </li>
        
        {/* Features from database - filter out specific enterprise features */}
        {plan.features && plan.features.map((feature, i) => {
          // Skip these specific features for enterprise plan
          if (isEnterprise) {
            const skipFeatures = [
              'Company Verification',
              'Dedicated Support',
              'Custom SLA'
            ];
            if (skipFeatures.some(skip => feature.includes(skip))) {
              return null;
            }
          }
          return (
            <li key={i} className="flex items-start gap-2 text-gray-300">
              <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
              {feature}
            </li>
          );
        })}
        
        {/* Dynamic permissions - skip specific ones for enterprise */}
        {plan.allow_teams && !isEnterprise && (
          <li className="flex items-start gap-2 text-gray-300">
            <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
            Team collaboration ({plan.max_team_members === -1 ? 'unlimited' : plan.max_team_members} members)
          </li>
        )}
        
        {plan.allow_integrations && !isEnterprise && (
          <li className="flex items-start gap-2 text-gray-300">
            <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
            Integrations ({plan.max_integrations === -1 ? 'unlimited' : plan.max_integrations} max)
          </li>
        )}
        
        {plan.allow_dangerous_tools && !isEnterprise && (
          <li className="flex items-start gap-2 text-gray-300">
            <FiCheck className="text-green-500 mt-1 flex-shrink-0" />
            Dangerous tools & advanced testing
          </li>
        )}
      </ul>
      
      <Link
        to={`/register${isEnterprise ? '?plan=enterprise' : isFree ? '' : '?plan=pro'}`}
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
