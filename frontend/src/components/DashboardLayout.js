import React from 'react';
import Sidebar from './Sidebar';
import { useTheme } from '../contexts/ThemeContext';

const DashboardLayout = ({ children }) => {
  const { isDark } = useTheme();
  
  return (
    <div className={`flex h-screen overflow-hidden ${
      isDark 
        ? 'bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900' 
        : 'bg-gradient-to-br from-gray-50 via-white to-gray-100'
    }`}>
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        {children}
      </main>
    </div>
  );
};

export default DashboardLayout;
