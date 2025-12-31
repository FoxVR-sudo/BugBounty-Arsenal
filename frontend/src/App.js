import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import LandingPage from './pages/LandingPage';
import Dashboard from './pages/Dashboard';
import ScanDetails from './pages/ScanDetails';
import CategoryScan from './pages/CategoryScan';
import AllResults from './pages/AllResults';
import Analytics from './pages/Analytics';
import Profile from './pages/Profile';
import Pricing from './pages/Pricing';
import Subscription from './pages/Subscription';
import Login from './pages/Login';
import Register from './pages/Register';
import RegisterEnterprise from './pages/RegisterEnterprise';
import PhoneVerification from './pages/PhoneVerification';
import PaymentSuccess from './pages/PaymentSuccess';
import TeamManagement from './pages/TeamManagement';
import Integrations from './pages/Integrations';
import Terms from './pages/Terms';
import Privacy from './pages/Privacy';
import Disclaimer from './pages/Disclaimer';
import Contact from './pages/Contact';
import Footer from './components/Footer';
import CookieConsent from './components/CookieConsent';
import './index.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

// Protected route wrapper
const PrivateRoute = ({ children }) => {
  const token = localStorage.getItem('token');
  return token ? children : <Navigate to="/login" />;
};

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <div className="flex flex-col min-h-screen">
          <div className="flex-grow">
            <Routes>
              <Route path="/" element={<LandingPage />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/register-enterprise" element={<RegisterEnterprise />} />
              <Route path="/payment-success" element={<PaymentSuccess />} />
              <Route path="/terms" element={<Terms />} />
              <Route path="/privacy" element={<Privacy />} />
              <Route path="/disclaimer" element={<Disclaimer />} />
              <Route path="/contact" element={<Contact />} />
              <Route path="/verify-phone" element={<PrivateRoute><PhoneVerification /></PrivateRoute>} />
              <Route
            path="/dashboard"
            element={
              <PrivateRoute>
                <Dashboard />
              </PrivateRoute>
            }
          />
          <Route
            path="/scan/details/:id"
            element={
              <PrivateRoute>
                <ScanDetails />
              </PrivateRoute>
            }
          />
          <Route
            path="/scan/:categoryId"
            element={
              <PrivateRoute>
                <CategoryScan />
              </PrivateRoute>
            }
          />
          <Route
            path="/results"
            element={
              <PrivateRoute>
                <AllResults />
              </PrivateRoute>
            }
          />
          <Route
            path="/analytics"
            element={
              <PrivateRoute>
                <Analytics />
              </PrivateRoute>
            }
          />
          <Route
            path="/profile"
            element={
              <PrivateRoute>
                <Profile />
              </PrivateRoute>
            }
          />
          <Route
            path="/pricing"
            element={
              <PrivateRoute>
                <Pricing />
              </PrivateRoute>
            }
          />
          <Route
            path="/subscription"
            element={
              <PrivateRoute>
                <Subscription />
              </PrivateRoute>
            }
          />
          <Route
            path="/team"
            element={
              <PrivateRoute>
                <TeamManagement />
              </PrivateRoute>
            }
          />
          <Route
            path="/integrations"
            element={
              <PrivateRoute>
                <Integrations />
              </PrivateRoute>
            }
          />
        </Routes>
          </div>
          <Footer />
          <CookieConsent />
        </div>
      </Router>
    </QueryClientProvider>
  );
}

export default App;
