import { useState, useEffect } from 'react'
import { dashboardAPI } from '../services/api'
import { DashboardData, ThreatItem } from '../types'
import { motion } from 'framer-motion'
import {
  Shield,
  AlertTriangle,
  Server,
  FileCheck,
  TrendingUp,
  TrendingDown,
  Activity,
} from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { DashboardSkeleton } from '../components/Skeleton'
import { StaggerChildren, StaggerItem } from '../components/PageTransition'
import Sparkline from '../components/Sparkline'

const severityColors: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-green-500',
}

const severityTextColors: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-green-400',
}

const container = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.08 },
  },
}

const item = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { duration: 0.4, ease: 'easeOut' } },
}

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await dashboardAPI.getDashboard()
        setData(response.data)
      } catch (error) {
        console.error('Error fetching dashboard:', error)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [])

  if (loading) return <DashboardSkeleton />
  if (!data) return null

  const kpiCards = [
    { ...data.vulnerabilities, icon: Shield, color: 'from-red-500 to-orange-500', sparkData: [12, 15, 11, 14, 13, 12], sparkColor: '#ef4444' },
    { ...data.compliance, icon: FileCheck, color: 'from-green-500 to-emerald-500', sparkData: [40, 42, 45, 48, 50, 50], sparkColor: '#22c55e' },
    { ...data.assets, icon: Server, color: 'from-blue-500 to-cyan-500', sparkData: [4, 5, 5, 6, 6, 6], sparkColor: '#3b82f6' },
    { ...data.incidents, icon: AlertTriangle, color: 'from-orange-500 to-yellow-500', sparkData: [5, 4, 3, 4, 3, 2], sparkColor: '#f97316' },
  ]

  return (
    <motion.div
      variants={container}
      initial="hidden"
      animate="show"
      className="p-6 space-y-6 grid-bg"
    >
      {/* Header */}
      <motion.div variants={item} className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white glow-text-cyan">Dashboard Ejecutivo</h1>
          <p className="text-gray-400 mt-1">Monitoreo en tiempo real de seguridad</p>
        </div>
        <div className="flex items-center gap-2 glass px-3 py-2 rounded-lg">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <Activity className="w-4 h-4 text-cyan-400" />
          <span className="text-sm text-gray-400">En vivo</span>
        </div>
      </motion.div>

      {/* Risk Level Banner */}
      <motion.div
        variants={item}
        className="glass-strong rounded-xl p-4 flex items-center justify-between border-glow"
      >
        <div className="flex items-center gap-4">
          <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
            data.risk_level === 'BAJO' ? 'bg-green-500/20' :
            data.risk_level === 'MEDIO' ? 'bg-yellow-500/20' : 'bg-red-500/20'
          }`}>
            <Shield className={`w-6 h-6 ${
              data.risk_level === 'BAJO' ? 'text-green-400' :
              data.risk_level === 'MEDIO' ? 'text-yellow-400' : 'text-red-400'
            }`} />
          </div>
          <div>
            <p className="text-sm text-gray-400">Nivel de Riesgo General</p>
            <p className={`text-2xl font-bold ${
              data.risk_level === 'BAJO' ? 'text-green-400' :
              data.risk_level === 'MEDIO' ? 'text-yellow-400' : 'text-red-400'
            }`}>
              {data.risk_level}
            </p>
          </div>
        </div>
        <div className="text-right">
          <p className="text-sm text-gray-400">Score de Riesgo</p>
          <p className="text-3xl font-bold text-white">{data.risk_score}/100</p>
        </div>
      </motion.div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {kpiCards.map((kpi, index) => (
          <motion.div
            key={index}
            variants={item}
            className="glass-card rounded-xl p-4 cursor-pointer"
          >
            <div className="flex items-center justify-between mb-3">
              <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${kpi.color} flex items-center justify-center`}>
                <kpi.icon className="w-5 h-5 text-white" />
              </div>
              <Sparkline data={kpi.sparkData} color={kpi.sparkColor} width={60} height={24} />
            </div>
            <p className="text-2xl font-bold text-white tabular-nums">{kpi.value}</p>
            <p className="text-sm text-gray-400 mt-1">{kpi.label}</p>
            {kpi.change && (
              <p className="text-xs text-cyan-400 mt-2">{kpi.change}</p>
            )}
          </motion.div>
        ))}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div variants={item} className="glass-card rounded-xl p-5">
          <h3 className="text-lg font-semibold text-white mb-4">Nivel de Riesgo por Categoría</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.risk_categories}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="category" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    background: 'rgba(17, 28, 50, 0.9)',
                    backdropFilter: 'blur(8px)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                  }}
                />
                <Bar dataKey="score" fill="url(#gradient)" radius={[4, 4, 0, 0]} />
                <defs>
                  <linearGradient id="gradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#06b6d4" stopOpacity={1} />
                    <stop offset="100%" stopColor="#3b82f6" stopOpacity={1} />
                  </linearGradient>
                </defs>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </motion.div>

        <motion.div variants={item} className="glass-card rounded-xl p-5">
          <h3 className="text-lg font-semibold text-white mb-4">Amenazas Activas</h3>
          <div className="space-y-3">
            {data.active_threats.map((threat: ThreatItem, index: number) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className="flex items-center gap-3 p-3 glass rounded-lg cursor-pointer hover:border-cyan-500/30 transition-all"
              >
                <div className={`w-3 h-3 rounded-full ${severityColors[threat.severity]} ${
                  threat.severity === 'critical' ? 'animate-pulse-glow' : ''
                }`} />
                <div className="flex-1">
                  <p className="text-sm font-medium text-white">{threat.name}</p>
                  <p className="text-xs text-gray-400">{threat.description}</p>
                </div>
                <span className={`text-xs font-medium ${severityTextColors[threat.severity]}`}>
                  {threat.count}
                </span>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </motion.div>
  )
}
