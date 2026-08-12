import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export const authAPI = {
  login: (email: string, password: string, code?: string) =>
    api.post('/api/auth/login', { email, password, ...(code ? { code } : {}) }),
  register: (data: { email: string; full_name: string; password: string }) =>
    api.post('/api/auth/register', data),
  getMe: () => api.get('/api/auth/me'),
}

export const dashboardAPI = {
  getDashboard: () => api.get('/api/dashboard/'),
}

export const vulnerabilitiesAPI = {
  list: (params?: { severity?: string; status?: string }) =>
    api.get('/api/vulnerabilities/', { params }),
  getStats: () => api.get('/api/vulnerabilities/stats'),
  get: (id: number) => api.get(`/api/vulnerabilities/${id}`),
  create: (data: any) => api.post('/api/vulnerabilities/', data),
  update: (id: number, data: any) => api.put(`/api/vulnerabilities/${id}`, data),
  delete: (id: number) => api.delete(`/api/vulnerabilities/${id}`),
}

export const complianceAPI = {
  list: (params?: { standard?: string }) =>
    api.get('/api/compliance/', { params }),
  getDashboard: () => api.get('/api/compliance/dashboard'),
  create: (data: any) => api.post('/api/compliance/', data),
  update: (id: number, data: any) => api.put(`/api/compliance/${id}`, data),
}

export const assetsAPI = {
  list: (params?: { asset_type?: string; status?: string }) =>
    api.get('/api/assets/', { params }),
  getStats: () => api.get('/api/assets/stats'),
  get: (id: number) => api.get(`/api/assets/${id}`),
  create: (data: any) => api.post('/api/assets/', data),
  update: (id: number, data: any) => api.put(`/api/assets/${id}`, data),
  delete: (id: number) => api.delete(`/api/assets/${id}`),
}

export const incidentsAPI = {
  list: (params?: { severity?: string; status?: string }) =>
    api.get('/api/incidents/', { params }),
  getStats: () => api.get('/api/incidents/stats'),
  get: (id: number) => api.get(`/api/incidents/${id}`),
  create: (data: any) => api.post('/api/incidents/', data),
  update: (id: number, data: any) => api.put(`/api/incidents/${id}`, data),
}

export const reportsAPI = {
  list: () => api.get('/api/reports/'),
  getTrends: () => api.get('/api/reports/trends'),
  // Devuelven el archivo como blob para descargarlo en el navegador.
  exportCsv: (type: string, organization?: string) =>
    api.get(`/api/reports/export/${type}`, {
      params: organization ? { organization } : undefined,
      responseType: 'blob',
    }),
  exportPdf: (organization: string) =>
    api.get('/api/reports/pdf', { params: { organization }, responseType: 'blob' }),
}

export const aiAPI = {
  getStatus: () => api.get('/api/ai/status'),
  listOrganizations: () => api.get('/api/ai/organizations'),
  generateReport: (organization: string) =>
    api.post('/api/ai/report', { organization }),
}

export const usersAPI = {
  list: () => api.get('/api/users/'),
  create: (data: any) => api.post('/api/users/', data),
  update: (id: number, data: any) => api.put(`/api/users/${id}`, data),
  delete: (id: number) => api.delete(`/api/users/${id}`),
  toggleActive: (id: number) => api.patch(`/api/users/${id}/toggle-active`),
}

export const diagnosticAPI = {
  run: (data: any) => api.post('/api/diagnostic/run', data),
}

export const settingsAPI = {
  getProfile: () => api.get('/api/settings/profile'),
  updateProfile: (data: any) => api.put('/api/settings/profile', data),
  changePassword: (data: any) => api.put('/api/settings/password', data),
  getSystem: () => api.get('/api/settings/system'),
  mfaSetup: () => api.post('/api/settings/mfa/setup'),
  mfaEnable: (code: string) => api.post('/api/settings/mfa/enable', { code }),
  mfaDisable: (password: string) => api.post('/api/settings/mfa/disable', { password }),
}

export default api
