import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { motion } from 'framer-motion'
import {
  LayoutDashboard,
  Shield,
  FileCheck,
  Server,
  AlertTriangle,
  BarChart3,
  Brain,
  LogOut,
  ShieldCheck,
  Users,
  ScanSearch,
  Settings,
} from 'lucide-react'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/diagnostic', icon: ScanSearch, label: 'Nuevo Diagnóstico' },
  { to: '/vulnerabilities', icon: Shield, label: 'Vulnerabilidades' },
  { to: '/compliance', icon: FileCheck, label: 'Cumplimiento' },
  { to: '/assets', icon: Server, label: 'Activos' },
  { to: '/incidents', icon: AlertTriangle, label: 'Incidentes' },
  { to: '/ai', icon: Brain, label: 'IA Predictiva' },
  { to: '/reports', icon: BarChart3, label: 'Reportes' },
]

const adminItems = [
  { to: '/users', icon: Users, label: 'Usuarios' },
  { to: '/settings', icon: Settings, label: 'Configuración' },
]

export default function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="flex h-screen bg-[#070b14] grid-bg">
      <aside className="w-64 glass-strong border-r border-white/5 flex flex-col">
        <div className="p-4 border-b border-white/5">
          <div className="flex items-center gap-3">
            <motion.div
              whileHover={{ scale: 1.05 }}
              className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-500 flex items-center justify-center glow-cyan"
            >
              <ShieldCheck className="w-6 h-6 text-white" />
            </motion.div>
            <div>
              <h1 className="font-bold text-white">GuardIA GT</h1>
              <p className="text-xs text-gray-400">Ciberseguridad con IA</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'glass bg-cyan-500/10 text-cyan-400 glow-cyan'
                    : 'text-gray-400 hover:text-white hover:bg-white/5'
                }`
              }
            >
              <item.icon className="w-5 h-5" />
              {item.label}
            </NavLink>
          ))}
          <div className="pt-3 mt-3 border-t border-white/5">
            <p className="px-3 py-1 text-xs font-semibold text-gray-500 uppercase">Admin</p>
          </div>
          {adminItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'glass bg-cyan-500/10 text-cyan-400 glow-cyan'
                    : 'text-gray-400 hover:text-white hover:bg-white/5'
                }`
              }
            >
              <item.icon className="w-5 h-5" />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="p-4 border-t border-white/5">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500 to-blue-500 flex items-center justify-center text-white text-sm font-bold">
              {user?.full_name?.charAt(0) || 'U'}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-white truncate">
                {user?.full_name || 'Usuario'}
              </p>
              <p className="text-xs text-gray-400 truncate">{user?.email}</p>
            </div>
          </div>
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={handleLogout}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-gray-400 hover:text-white hover:bg-white/5 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Cerrar Sesión
          </motion.button>
        </div>
      </aside>

      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}
