import { useState, useEffect } from 'react'
import { dashboardAPI } from '../services/api'
import { DashboardData, ThreatItem, RecentIncident } from '../types'
import { motion } from 'framer-motion'
import {
  Shield,
  AlertTriangle,
  Server,
  FileCheck,
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

const statusLabels: Record<string, string> = {
  open: 'Abierto',
  investigating: 'Investigando',
  contained: 'Contenido',
  resolved: 'Resuelto',
  closed: 'Cerrado',
}

const container = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.08 } },
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

  // Sin `sparkData`: las miniaturas de tendencia eran arreglos escritos a mano
  // junto a cifras reales, la combinación más engañosa posible.
  const kpiCards = [
    { ...data.vulnerabilities, icon: Shield, color: 'from-red-500 to-orange-500' },
    { ...data.compliance, icon: FileCheck, color: 'from-green-500 to-emerald-500' },
    { ...data.assets, icon: Server, color: 'from-blue-500 to-cyan-500' },
    { ...data.incidents, icon: AlertTriangle, color: 'from-orange-500 to-yellow-500' },
  ]

  const hasRiskData = data.risk_categories.some((c) => c.score > 0)

  return (
    <motion.div
      variants={container}
      initial="hidden"
      animate="show"
      className="p-6 space-y-6 grid-bg"
    >
      <motion.div variants={item} className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white glow-text-cyan">Dashboard Ejecutivo</h1>
          <p className="text-gray-400 mt-1">
            {data.organization ? `Organización: ${data.organization}` : 'Todas las organizaciones'}
          </p>
        </div>
        <div className="flex items-center gap-2 glass px-3 py-2 rounded-lg">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <Activity className="w-4 h-4 text-cyan-400" />
          <span className="text-sm text-gray-400">En vivo</span>
        </div>
      </motion.div>

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
          <p className="text-3xl font-bold text-white tabular-nums">{data.risk_score}/100</p>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {kpiCards.map((kpi, index) => (
          <motion.div key={index} variants={item} className="glass-card rounded-xl p-4">
            <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${kpi.color} flex items-center justify-center mb-3`}>
              <kpi.icon className="w-5 h-5 text-white" />
            </div>
            <p className="text-2xl font-bold text-white tabular-nums">{kpi.value}</p>
            <p className="text-sm text-gray-400 mt-1">{kpi.label}</p>
            {kpi.change && <p className="text-xs text-cyan-400 mt-2">{kpi.change}</p>}
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div variants={item} className="glass-card rounded-xl p-5">
          <h3 className="text-lg font-semibold text-white mb-1">Riesgo por Categoría de Activo</h3>
          <p className="text-xs text-gray-500 mb-4">Suma ponderada por severidad de los hallazgos abiertos</p>
          <div className="h-64">
            {hasRiskData ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.risk_categories}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="category" stroke="#64748b" fontSize={12} />
                  <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
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
            ) : (
              <div className="h-full flex items-center justify-center">
                <p className="text-sm text-gray-500 text-center max-w-xs">
                  Sin hallazgos abiertos. Ejecuta un diagnóstico para poblar esta vista.
                </p>
              </div>
            )}
          </div>
        </motion.div>

        <motion.div variants={item} className="glass-card rounded-xl p-5">
          <h3 className="text-lg font-semibold text-white mb-1">Hallazgos Más Frecuentes</h3>
          <p className="text-xs text-gray-500 mb-4">Agrupados por tipo, ordenados por severidad</p>
          <div className="space-y-3">
            {data.active_threats.length > 0 ? (
              data.active_threats.map((threat: ThreatItem, index: number) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.1 }}
                  className="flex items-center gap-3 p-3 glass rounded-lg"
                >
                  <div className={`w-3 h-3 rounded-full flex-shrink-0 ${severityColors[threat.severity]} ${
                    threat.severity === 'critical' ? 'animate-pulse-glow' : ''
                  }`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-white truncate">{threat.name}</p>
                    <p className="text-xs text-gray-400">{threat.description}</p>
                  </div>
                  <span className={`text-xs font-medium tabular-nums ${severityTextColors[threat.severity]}`}>
                    {threat.count}
                  </span>
                </motion.div>
              ))
            ) : (
              <p className="text-sm text-gray-500 py-8 text-center">
                No hay hallazgos abiertos registrados.
              </p>
            )}
          </div>
        </motion.div>
      </div>

      <motion.div variants={item} className="glass-card rounded-xl p-5">
        <h3 className="text-lg font-semibold text-white mb-4">Incidentes Recientes</h3>
        {data.recent_incidents.length > 0 ? (
          <div className="space-y-2">
            {data.recent_incidents.map((incident: RecentIncident) => (
              <div key={incident.id} className="flex items-center gap-3 p-3 glass rounded-lg">
                <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${severityColors[incident.severity] || 'bg-gray-500'}`} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-white truncate">{incident.title}</p>
                  <p className="text-xs text-gray-400">
                    {incident.affected_asset || 'Sin activo asociado'}
                    {incident.detected_at && ` · ${new Date(incident.detected_at).toLocaleString('es-GT')}`}
                  </p>
                </div>
                <span className="text-xs text-gray-400 flex-shrink-0">
                  {statusLabels[incident.status] || incident.status}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-gray-500 py-6 text-center">Sin incidentes registrados.</p>
        )}
      </motion.div>
    </motion.div>
  )
}
