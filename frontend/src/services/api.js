import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://127.0.0.1:8001/api';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token to requests
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Auth services
export const authService = {
  login: (email, password) => api.post('/auth/login/', { email, password }),
  register: (userData) => api.post('/auth/signup/', userData),
  logout: () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  },
};

// Scan services
export const scanService = {
  getAll: (params) => api.get('/scans/', { params }),
  getById: (id) => api.get(`/scans/${id}/`),
  create: (data) => api.post('/scans/start/', data),
  cancel: (id) => api.post(`/scans/stop/${id}/`),
  getVulnerabilities: (id, params) => api.get(`/scans/${id}/vulnerabilities/`, { params }),
  downloadPDF: (id) => api.get(`/scans/${id}/pdf/`, { responseType: 'blob' }),
  downloadJSON: (id) => api.get(`/scans/${id}/json/`, { responseType: 'blob' }),
  downloadCSV: (id) => api.get(`/scans/${id}/csv/`, { responseType: 'blob' }),
};

// Stats services
export const statsService = {
  getOverview: () => api.get('/scans/stats/'),
};

export default api;
