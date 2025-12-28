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
import Login from './pages/Login';
import Register from './pages/Register';
import PhoneVerification from './pages/PhoneVerification';
import TeamManagement from './pages/TeamManagement';
import Integrations from './pages/Integrations';
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
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
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
            path="/profidetails/le"
            element={
              <PrivateRoute>
                <Profile />
              </PrivateRoute>
            }
          />
          <Route
            path="/scan/:id"
            element={
              <PrivateRoute>
                <ScanDetails />
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
      </Router>
    </QueryClientProvider>
  );
}

export default App;
