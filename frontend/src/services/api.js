import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api';

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
  register: (email, password) => api.post('/auth/register/', { email, password }),
  logout: () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  },
};

// Scan services
export const scanService = {
  getAll: (params) => api.get('/scans/', { params }),
  getById: (id) => api.get(`/scans/${id}/`),
  create: (data) => api.post('/scans/', data),
  cancel: (id) => api.post(`/scans/${id}/cancel/`),
  getVulnerabilities: (id, params) => api.get(`/scans/${id}/vulnerabilities/`, { params }),
  downloadReport: (id, format = 'json') => 
    api.get(`/scans/${id}/export/`, { params: { format }, responseType: 'blob' }),
};

// Stats services
export const statsService = {
  getOverview: () => api.get('/scans/stats/'),
};

export default api;
