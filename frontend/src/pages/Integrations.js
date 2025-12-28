import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { FiCheck, FiX, FiZap, FiSend, FiSettings } from 'react-icons/fi';
import { SiSlack, SiJira, SiDiscord, SiTelegram, SiGithub, SiGitlab } from 'react-icons/si';
import { MdEmail } from 'react-icons/md';
import { FiGlobe } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';

const Integrations = () => {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [selectedIntegration, setSelectedIntegration] = useState(null);
  const [showConfigModal, setShowConfigModal] = useState(false);
  
  // Config form state
  const [config, setConfig] = useState({
    enabled: false,
    api_key: '',
    webhook_url: '',
    channel: '',
    events: {
      scan_started: true,
      scan_completed: true,
      vulnerability_found: true,
      scan_failed: false,
    }
  });

  const availableIntegrations = [
    {
      id: 'slack',
      name: 'Slack',
      icon: SiSlack,
      color: 'text-purple-600',
      bgColor: 'bg-purple-50',
      description: 'Send scan results to Slack channels',
      fields: ['webhook_url', 'channel'],
      placeholder: {
        webhook_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
        channel: '#security-alerts'
      }
    },
    {
      id: 'jira',
      name: 'Jira',
      icon: SiJira,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50',
      description: 'Create Jira tickets for vulnerabilities',
      fields: ['api_key', 'webhook_url'],
      placeholder: {
        api_key: 'your-jira-api-token',
        webhook_url: 'https://your-domain.atlassian.net'
      }
    },
    {
      id: 'discord',
      name: 'Discord',
      icon: SiDiscord,
      color: 'text-indigo-600',
      bgColor: 'bg-indigo-50',
      description: 'Post alerts to Discord channels',
      fields: ['webhook_url'],
      placeholder: {
        webhook_url: 'https://discord.com/api/webhooks/YOUR_WEBHOOK'
      }
    },
    {
      id: 'telegram',
      name: 'Telegram',
      icon: SiTelegram,
      color: 'text-sky-600',
      bgColor: 'bg-sky-50',
      description: 'Send notifications to Telegram',
      fields: ['api_key', 'channel'],
      placeholder: {
        api_key: 'bot-token-from-botfather',
        channel: '@your_channel or chat_id'
      }
    },
    {
      id: 'github',
      name: 'GitHub',
      icon: SiGithub,
      color: 'text-gray-900',
      bgColor: 'bg-gray-50',
      description: 'Create GitHub issues for findings',
      fields: ['api_key', 'webhook_url'],
      placeholder: {
        api_key: 'ghp_your_personal_access_token',
        webhook_url: 'owner/repository'
      }
    },
    {
      id: 'gitlab',
      name: 'GitLab',
      icon: SiGitlab,
      color: 'text-orange-600',
      bgColor: 'bg-orange-50',
      description: 'Create GitLab issues automatically',
      fields: ['api_key', 'webhook_url'],
      placeholder: {
        api_key: 'glpat-your_access_token',
        webhook_url: 'project_id or group/project'
      }
    },
    {
      id: 'webhook',
      name: 'Custom Webhook',
      icon: FiGlobe,
      color: 'text-green-600',
      bgColor: 'bg-green-50',
      description: 'Send events to custom endpoints',
      fields: ['webhook_url', 'api_key'],
      placeholder: {
        webhook_url: 'https://your-api.com/webhook',
        api_key: 'optional-auth-token'
      }
    },
    {
      id: 'email',
      name: 'Email',
      icon: MdEmail,
      color: 'text-red-600',
      bgColor: 'bg-red-50',
      description: 'Email notifications for scan results',
      fields: ['channel'],
      placeholder: {
        channel: 'security-team@company.com'
      }
    }
  ];

  useEffect(() => {
    fetchIntegrations();
  }, []);

  const fetchIntegrations = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8001/api/integrations/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setIntegrations(response.data.results || response.data);
    } catch (err) {
      setError('Failed to load integrations');
    } finally {
      setLoading(false);
    }
  };

  const handleOpenConfig = (integrationType) => {
    const existing = integrations.find(i => i.integration_type === integrationType);
    
    if (existing) {
      setConfig({
        enabled: existing.enabled,
        api_key: existing.config.api_key || '',
        webhook_url: existing.config.webhook_url || '',
        channel: existing.config.channel || '',
        events: existing.events || {
          scan_started: true,
          scan_completed: true,
          vulnerability_found: true,
          scan_failed: false,
        }
      });
      setSelectedIntegration({ ...availableIntegrations.find(i => i.id === integrationType), existing: true, id: existing.id });
    } else {
      setConfig({
        enabled: true,
        api_key: '',
        webhook_url: '',
        channel: '',
        events: {
          scan_started: true,
          scan_completed: true,
          vulnerability_found: true,
          scan_failed: false,
        }
      });
      setSelectedIntegration({ ...availableIntegrations.find(i => i.id === integrationType), existing: false });
    }
    
    setShowConfigModal(true);
  };

  const handleSaveIntegration = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    try {
      const token = localStorage.getItem('token');
      const payload = {
        integration_type: selectedIntegration.id,
        enabled: config.enabled,
        config: {
          api_key: config.api_key,
          webhook_url: config.webhook_url,
          channel: config.channel,
        },
        events: config.events
      };

      if (selectedIntegration.existing) {
        // Update existing
        await axios.put(
          `http://localhost:8001/api/integrations/${selectedIntegration.id}/`,
          payload,
          { headers: { 'Authorization': `Bearer ${token}` } }
        );
        setSuccess('Integration updated successfully!');
      } else {
        // Create new
        await axios.post(
          'http://localhost:8001/api/integrations/',
          payload,
          { headers: { 'Authorization': `Bearer ${token}` } }
        );
        setSuccess('Integration created successfully!');
      }

      setShowConfigModal(false);
      fetchIntegrations();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to save integration');
    }
  };

  const handleTestIntegration = async () => {
    setError('');
    setSuccess('');
    
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `http://localhost:8001/api/integrations/${selectedIntegration.id}/test/`,
        {},
        { headers: { 'Authorization': `Bearer ${token}` } }
      );
      setSuccess('Test notification sent successfully!');
    } catch (err) {
      setError('Failed to send test notification');
    }
  };

  const handleToggleIntegration = async (integrationId, enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.patch(
        `http://localhost:8001/api/integrations/${integrationId}/`,
        { enabled: !enabled },
        { headers: { 'Authorization': `Bearer ${token}` } }
      );
      fetchIntegrations();
    } catch (err) {
      setError('Failed to toggle integration');
    }
  };

  const getIntegrationIcon = (type) => {
    const integration = availableIntegrations.find(i => i.id === type);
    if (!integration) return null;
    const Icon = integration.icon;
    return <Icon className={integration.color} size={24} />;
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="p-8 flex items-center justify-center">
          <div className="text-gray-500">Loading integrations...</div>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="p-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Integrations</h1>
          <p className="text-gray-600">Connect BugBounty Arsenal with your favorite tools</p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700 flex items-center justify-between">
            {error}
            <button onClick={() => setError('')} className="text-red-700 hover:text-red-900">
              <FiX />
            </button>
          </div>
        )}

        {success && (
          <div className="mb-6 p-4 bg-green-50 border border-green-200 rounded-lg text-green-700 flex items-center justify-between">
            {success}
            <button onClick={() => setSuccess('')} className="text-green-700 hover:text-green-900">
              <FiX />
            </button>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {availableIntegrations.map((integration) => {
            const Icon = integration.icon;
            const existing = integrations.find(i => i.integration_type === integration.id);
            const isEnabled = existing?.enabled || false;

            return (
              <div key={integration.id} className="bg-white rounded-lg shadow hover:shadow-lg transition">
                <div className="p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className={`p-3 rounded-lg ${integration.bgColor}`}>
                      <Icon className={integration.color} size={28} />
                    </div>
                    {existing && (
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={isEnabled}
                          onChange={() => handleToggleIntegration(existing.id, isEnabled)}
                          className="sr-only peer"
                        />
                        <div className="w-11 h-6 bg-gray-200 peer-focus:ring-2 peer-focus:ring-primary rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                      </label>
                    )}
                  </div>

                  <h3 className="text-lg font-bold text-gray-900 mb-2">{integration.name}</h3>
                  <p className="text-sm text-gray-600 mb-4">{integration.description}</p>

                  {existing && (
                    <div className="mb-4 p-3 bg-gray-50 rounded border border-gray-200">
                      <div className="text-xs text-gray-500 mb-1">Events Configured:</div>
                      <div className="flex flex-wrap gap-1">
                        {Object.entries(existing.events).filter(([_, v]) => v).map(([event]) => (
                          <span key={event} className="text-xs px-2 py-1 bg-white border border-gray-300 rounded">
                            {event.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <button
                    onClick={() => handleOpenConfig(integration.id)}
                    className="w-full px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition font-semibold flex items-center justify-center gap-2"
                  >
                    <FiSettings size={16} />
                    {existing ? 'Configure' : 'Setup'}
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {/* Configuration Modal */}
        {showConfigModal && selectedIntegration && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto">
              <div className="sticky top-0 bg-white border-b border-gray-200 p-6">
                <div className="flex items-center gap-4">
                  <div className={`p-3 rounded-lg ${selectedIntegration.bgColor}`}>
                    {React.createElement(selectedIntegration.icon, { className: selectedIntegration.color, size: 32 })}
                  </div>
                  <div>
                    <h3 className="text-2xl font-bold text-gray-900">{selectedIntegration.name} Integration</h3>
                    <p className="text-sm text-gray-600">{selectedIntegration.description}</p>
                  </div>
                </div>
              </div>

              <form onSubmit={handleSaveIntegration} className="p-6">
                {/* Enable/Disable */}
                <div className="mb-6 flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                  <div>
                    <h4 className="font-semibold text-gray-900">Enable Integration</h4>
                    <p className="text-sm text-gray-600">Activate this integration to receive notifications</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={config.enabled}
                      onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
                      className="sr-only peer"
                    />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:ring-2 peer-focus:ring-primary rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                  </label>
                </div>

                {/* Configuration Fields */}
                <div className="space-y-4 mb-6">
                  {selectedIntegration.fields.includes('webhook_url') && (
                    <div>
                      <label className="block text-gray-700 font-semibold mb-2">
                        Webhook URL {selectedIntegration.id !== 'webhook' && selectedIntegration.id !== 'github' && selectedIntegration.id !== 'gitlab' && <span className="text-red-500">*</span>}
                      </label>
                      <input
                        type="text"
                        value={config.webhook_url}
                        onChange={(e) => setConfig({ ...config, webhook_url: e.target.value })}
                        placeholder={selectedIntegration.placeholder.webhook_url}
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                      />
                    </div>
                  )}

                  {selectedIntegration.fields.includes('api_key') && (
                    <div>
                      <label className="block text-gray-700 font-semibold mb-2">
                        API Key / Token {selectedIntegration.id !== 'webhook' && <span className="text-red-500">*</span>}
                      </label>
                      <input
                        type="password"
                        value={config.api_key}
                        onChange={(e) => setConfig({ ...config, api_key: e.target.value })}
                        placeholder={selectedIntegration.placeholder.api_key}
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                      />
                    </div>
                  )}

                  {selectedIntegration.fields.includes('channel') && (
                    <div>
                      <label className="block text-gray-700 font-semibold mb-2">
                        Channel / Recipient
                      </label>
                      <input
                        type="text"
                        value={config.channel}
                        onChange={(e) => setConfig({ ...config, channel: e.target.value })}
                        placeholder={selectedIntegration.placeholder.channel}
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                      />
                    </div>
                  )}
                </div>

                {/* Event Triggers */}
                <div className="mb-6">
                  <h4 className="font-semibold text-gray-900 mb-3">Event Triggers</h4>
                  <div className="space-y-2">
                    {Object.keys(config.events).map((event) => (
                      <label key={event} className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg cursor-pointer hover:bg-gray-100">
                        <input
                          type="checkbox"
                          checked={config.events[event]}
                          onChange={(e) => setConfig({
                            ...config,
                            events: { ...config.events, [event]: e.target.checked }
                          })}
                          className="w-5 h-5 text-primary rounded focus:ring-2 focus:ring-primary"
                        />
                        <div className="flex-1">
                          <div className="font-semibold text-gray-900 capitalize">
                            {event.replace(/_/g, ' ')}
                          </div>
                          <div className="text-xs text-gray-600">
                            {event === 'scan_started' && 'Notify when a new scan begins'}
                            {event === 'scan_completed' && 'Notify when a scan finishes successfully'}
                            {event === 'vulnerability_found' && 'Notify when vulnerabilities are detected'}
                            {event === 'scan_failed' && 'Notify when a scan encounters errors'}
                          </div>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex gap-4">
                  <button
                    type="submit"
                    className="flex-1 px-6 py-3 bg-primary text-white rounded-lg hover:bg-primary-600 transition font-semibold flex items-center justify-center gap-2"
                  >
                    <FiCheck /> Save Configuration
                  </button>
                  {selectedIntegration.existing && (
                    <button
                      type="button"
                      onClick={handleTestIntegration}
                      className="px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 transition font-semibold flex items-center justify-center gap-2"
                    >
                      <FiSend /> Test
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setShowConfigModal(false)}
                    className="px-6 py-3 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default Integrations;
