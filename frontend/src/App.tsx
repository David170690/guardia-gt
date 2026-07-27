import { Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import { AuthProvider, useAuth } from './context/AuthContext'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Vulnerabilities from './pages/Vulnerabilities'
import Compliance from './pages/Compliance'
import Assets from './pages/Assets'
import Incidents from './pages/Incidents'
import Reports from './pages/Reports'
import AIInsights from './pages/AIInsights'
import UsersPage from './pages/Users'
import Diagnostic from './pages/Diagnostic'
import SettingsPage from './pages/Settings'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth()
  if (loading) return null
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

function AppRoutes() {
  return (
    <>
      <Toaster position="top-right" toastOptions={{ duration: 4000 }} />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <Layout />
            </ProtectedRoute>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="diagnostic" element={<Diagnostic />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="compliance" element={<Compliance />} />
          <Route path="assets" element={<Assets />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="reports" element={<Reports />} />
          <Route path="ai" element={<AIInsights />} />
          <Route path="users" element={<UsersPage />} />
          <Route path="settings" element={<SettingsPage />} />
        </Route>
      </Routes>
    </>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  )
}
