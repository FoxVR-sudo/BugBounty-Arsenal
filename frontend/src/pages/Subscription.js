import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import axios from 'axios';
import {
  FiCheck, FiX, FiAlertCircle, FiCreditCard, FiCalendar, FiTrendingUp,
  FiLoader, FiCheckCircle, FiXCircle, FiArrowRight
} from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';

const Subscription = () => {
  const [subscription, setSubscription] = useState(null);
  const [plans, setPlans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showCancelDialog, setShowCancelDialog] = useState(false);
  const [showUpgradeDialog, setShowUpgradeDialog] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState(null);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const API_URL = process.env.REACT_APP_API_URL || 'http://127.0.0.1:8001/api';

  useEffect(() => {
    fetchSubscriptionData();
    // Check for upgrade success
    if (searchParams.get('upgraded') === 'true') {
      setSuccess('Plan upgraded successfully!');
    }
  }, []);

  const fetchSubscriptionData = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const [subRes, plansRes] = await Promise.all([
        axios.get(`${API_URL}/subscriptions/current/`, {
          headers: { Authorization: `Bearer ${token}` }
        }),
        axios.get(`${API_URL}/plans/`)
      ]);

      setSubscription(subRes.data);
      setPlans(plansRes.data);
    } catch (err) {
      setError('Failed to load subscription data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCancelSubscription = async (immediate = false) => {
    setActionLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('token');
      const response = await axios.post(
        `${API_URL}/subscriptions/cancel/`,
        { immediate },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      setSuccess(response.data.message);
      setShowCancelDialog(false);
      fetchSubscriptionData();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to cancel subscription');
    } finally {
      setActionLoading(false);
    }
  };

  const handleReactivate = async () => {
    setActionLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('token');
      const response = await axios.post(
        `${API_URL}/subscriptions/reactivate/`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );

      setSuccess(response.data.message);
      fetchSubscriptionData();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to reactivate subscription');
    } finally {
      setActionLoading(false);
    }
  };

  const handleChangePlan = async (newPlanId) => {
    setActionLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('token');
      const response = await axios.post(
        `${API_URL}/subscriptions/change-plan/`,
        { new_plan_id: newPlanId },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (response.data.checkout_url) {
        // Redirect to checkout
        window.location.href = response.data.checkout_url;
      } else {
        setSuccess(response.data.message);
        setShowUpgradeDialog(false);
        fetchSubscriptionData();
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to change plan');
    } finally {
      setActionLoading(false);
    }
  };

  const handleManageBilling = async () => {
    setActionLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.post(
        `${API_URL}/billing/portal/`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (response.data.url) {
        window.location.href = response.data.url;
      }
    } catch (err) {
      setError('Failed to open billing portal');
    } finally {
      setActionLoading(false);
    }
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-96">
          <FiLoader className="animate-spin text-primary" size={48} />
        </div>
      </DashboardLayout>
    );
  }

  const currentPlan = subscription?.plan;
  const isFreePlan = currentPlan?.name === 'free';
  const isCancelled = subscription?.cancel_at_period_end;

  return (
    <DashboardLayout>
      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Subscription Management</h1>
          <p className="text-gray-600 mt-2">Manage your plan and billing settings</p>
        </div>

        {/* Messages */}
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-center gap-2 text-red-700">
            <FiXCircle />
            {error}
          </div>
        )}

        {success && (
          <div className="mb-6 p-4 bg-green-50 border border-green-200 rounded-lg flex items-center gap-2 text-green-700">
            <FiCheckCircle />
            {success}
          </div>
        )}

        {/* Current Plan Card */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-8">
          <div className="flex items-start justify-between mb-6">
            <div>
              <h2 className="text-2xl font-bold text-gray-900">{currentPlan?.display_name || 'Free Plan'}</h2>
              <p className="text-gray-600 mt-1">{currentPlan?.description}</p>
              <div className="flex items-center gap-4 mt-4">
                <div className="text-4xl font-bold text-primary">
                  {currentPlan?.price === 0 ? 'Free' : `$${currentPlan?.price}`}
                </div>
                {currentPlan?.price > 0 && (
                  <span className="text-gray-500">/month</span>
                )}
              </div>
            </div>
            <div className={`px-4 py-2 rounded-full text-sm font-semibold ${
              subscription?.status === 'active' && !isCancelled
                ? 'bg-green-100 text-green-800'
                : isCancelled
                ? 'bg-yellow-100 text-yellow-800'
                : 'bg-gray-100 text-gray-800'
            }`}>
              {isCancelled ? 'Cancelling' : subscription?.status || 'Active'}
            </div>
          </div>

          {/* Billing Info */}
          {subscription?.current_period_end && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 bg-gray-50 rounded-lg mb-6">
              <div className="flex items-center gap-2">
                <FiCalendar className="text-gray-400" />
                <div>
                  <div className="text-sm text-gray-600">
                    {isCancelled ? 'Cancels on' : 'Renews on'}
                  </div>
                  <div className="font-semibold text-gray-900">
                    {new Date(subscription.current_period_end).toLocaleDateString()}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <FiCreditCard className="text-gray-400" />
                <div>
                  <div className="text-sm text-gray-600">Monthly Cost</div>
                  <div className="font-semibold text-gray-900">
                    ${currentPlan?.price || 0}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Usage Stats */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div className="p-4 bg-blue-50 rounded-lg">
              <div className="text-sm text-blue-600 font-semibold mb-1">Scans Today</div>
              <div className="text-2xl font-bold text-blue-900">
                {subscription?.scans_used_today || 0} / {subscription?.daily_scan_limit || 0}
              </div>
            </div>
            <div className="p-4 bg-purple-50 rounded-lg">
              <div className="text-sm text-purple-600 font-semibold mb-1">Scans This Month</div>
              <div className="text-2xl font-bold text-purple-900">
                {subscription?.scans_used_this_month || 0} / {subscription?.monthly_scan_limit || 0}
              </div>
            </div>
            <div className="p-4 bg-green-50 rounded-lg">
              <div className="text-sm text-green-600 font-semibold mb-1">Concurrent Scans</div>
              <div className="text-2xl font-bold text-green-900">
                {subscription?.concurrent_scans || 1}
              </div>
            </div>
          </div>

          {/* Plan Features */}
          <div className="mb-6">
            <h3 className="font-semibold text-gray-900 mb-3">Your Plan Includes:</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {currentPlan?.features?.map((feature, idx) => (
                <div key={idx} className="flex items-center gap-2 text-gray-700">
                  <FiCheck className="text-green-500 flex-shrink-0" />
                  <span>{feature}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-3">
            {!isFreePlan && !isCancelled && (
              <>
                <button
                  onClick={handleManageBilling}
                  disabled={actionLoading}
                  className="px-6 py-2 bg-primary text-white rounded-lg font-semibold hover:bg-primary-600 transition disabled:opacity-50 flex items-center gap-2"
                >
                  <FiCreditCard />
                  Manage Billing
                </button>
                <button
                  onClick={() => setShowCancelDialog(true)}
                  disabled={actionLoading}
                  className="px-6 py-2 bg-white text-red-600 border border-red-200 rounded-lg font-semibold hover:bg-red-50 transition disabled:opacity-50"
                >
                  Cancel Subscription
                </button>
              </>
            )}

            {isCancelled && (
              <button
                onClick={handleReactivate}
                disabled={actionLoading}
                className="px-6 py-2 bg-green-600 text-white rounded-lg font-semibold hover:bg-green-700 transition disabled:opacity-50 flex items-center gap-2"
              >
                <FiCheckCircle />
                Reactivate Subscription
              </button>
            )}

            {!isCancelled && (
              <button
                onClick={() => setShowUpgradeDialog(true)}
                className="px-6 py-2 bg-white text-primary border border-primary rounded-lg font-semibold hover:bg-primary-50 transition flex items-center gap-2"
              >
                <FiTrendingUp />
                {isFreePlan ? 'Upgrade Plan' : 'Change Plan'}
              </button>
            )}
          </div>
        </div>

        {/* Cancellation Warning */}
        {isCancelled && (
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-8">
            <div className="flex items-start gap-3">
              <FiAlertCircle className="text-yellow-600 flex-shrink-0 mt-0.5" size={20} />
              <div>
                <h3 className="font-semibold text-yellow-900 mb-1">Subscription Cancellation Scheduled</h3>
                <p className="text-yellow-800 text-sm">
                  Your subscription will be cancelled on{' '}
                  <strong>{new Date(subscription.current_period_end).toLocaleDateString()}</strong>.
                  You can continue using all features until then.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Cancel Dialog */}
        {showCancelDialog && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-lg shadow-xl max-w-md w-full p-6">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Cancel Subscription?</h3>
              <p className="text-gray-600 mb-6">
                Are you sure you want to cancel your subscription? You'll lose access to premium features.
              </p>
              <div className="flex gap-3">
                <button
                  onClick={() => handleCancelSubscription(false)}
                  disabled={actionLoading}
                  className="flex-1 px-4 py-2 bg-yellow-600 text-white rounded-lg font-semibold hover:bg-yellow-700 transition disabled:opacity-50"
                >
                  Cancel at Period End
                </button>
                <button
                  onClick={() => setShowCancelDialog(false)}
                  disabled={actionLoading}
                  className="flex-1 px-4 py-2 bg-gray-200 text-gray-800 rounded-lg font-semibold hover:bg-gray-300 transition"
                >
                  Keep Subscription
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Upgrade/Change Plan Dialog */}
        {showUpgradeDialog && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4 overflow-y-auto">
            <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full p-6 my-8">
              <div className="flex justify-between items-center mb-6">
                <h3 className="text-2xl font-bold text-gray-900">Choose Your Plan</h3>
                <button
                  onClick={() => setShowUpgradeDialog(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <FiX size={24} />
                </button>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {plans.map((plan) => (
                  <div
                    key={plan.id}
                    className={`border-2 rounded-lg p-6 cursor-pointer transition ${
                      plan.id === subscription?.plan_id
                        ? 'border-primary bg-primary bg-opacity-5'
                        : 'border-gray-200 hover:border-primary'
                    } ${plan.is_popular ? 'ring-2 ring-primary' : ''}`}
                    onClick={() => setSelectedPlan(plan)}
                  >
                    {plan.is_popular && (
                      <div className="text-xs bg-primary text-white px-2 py-1 rounded-full inline-block mb-2">
                        Popular
                      </div>
                    )}
                    <h4 className="text-xl font-bold text-gray-900 mb-2">{plan.display_name}</h4>
                    <div className="text-3xl font-bold text-primary mb-4">
                      {plan.price === 0 ? 'Free' : `$${plan.price}`}
                      {plan.price > 0 && <span className="text-sm text-gray-500">/mo</span>}
                    </div>
                    <ul className="space-y-2 mb-4">
                      {plan.features?.slice(0, 5).map((feature, idx) => (
                        <li key={idx} className="flex items-start gap-2 text-sm text-gray-700">
                          <FiCheck className="text-green-500 flex-shrink-0 mt-0.5" size={16} />
                          <span>{feature}</span>
                        </li>
                      ))}
                    </ul>
                    {plan.id === subscription?.plan_id ? (
                      <div className="text-center py-2 bg-gray-100 rounded text-gray-600 font-semibold">
                        Current Plan
                      </div>
                    ) : (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleChangePlan(plan.id);
                        }}
                        disabled={actionLoading}
                        className="w-full py-2 bg-primary text-white rounded-lg font-semibold hover:bg-primary-600 transition disabled:opacity-50 flex items-center justify-center gap-2"
                      >
                        {actionLoading ? <FiLoader className="animate-spin" /> : <FiArrowRight />}
                        {plan.price > (currentPlan?.price || 0) ? 'Upgrade' : plan.price === 0 ? 'Downgrade' : 'Switch'}
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default Subscription;
