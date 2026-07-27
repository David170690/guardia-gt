import { useState, useEffect } from 'react'
import { dashboardAPI } from '../services/api'
import { DashboardData, ThreatItem } from '../types'
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

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500" />
      </div>
    )
  }

  if (!data) return null

  const kpiCards = [
    { ...data.vulnerabilities, icon: Shield, color: 'from-red-500 to-orange-500' },
    { ...data.compliance, icon: FileCheck, color: 'from-green-500 to-emerald-500' },
    { ...data.assets, icon: Server, color: 'from-blue-500 to-cyan-500' },
    { ...data.incidents, icon: AlertTriangle, color: 'from-orange-500 to-yellow-500' },
  ]

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard Ejecutivo</h1>
          <p className="text-gray-400 mt-1">Monitoreo en tiempo real de seguridad</p>
        </div>
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" />
          <span className="text-sm text-gray-400">Última actualización: hace 12s</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-[#111c32] to-[#1a2744] border border-white/10 rounded-xl p-4 flex items-center justify-between">
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
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {kpiCards.map((kpi, index) => (
          <div
            key={index}
            className="bg-[#111c32] border border-white/10 rounded-xl p-4 hover:border-cyan-500/30 transition-colors"
          >
            <div className="flex items-center justify-between mb-3">
              <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${kpi.color} flex items-center justify-center`}>
                <kpi.icon className="w-5 h-5 text-white" />
              </div>
              {kpi.trend === 'up' && <TrendingUp className="w-4 h-4 text-green-400" />}
              {kpi.trend === 'down' && <TrendingDown className="w-4 h-4 text-red-400" />}
            </div>
            <p className="text-2xl font-bold text-white">{kpi.value}</p>
            <p className="text-sm text-gray-400 mt-1">{kpi.label}</p>
            {kpi.change && (
              <p className="text-xs text-cyan-400 mt-2">{kpi.change}</p>
            )}
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#111c32] border border-white/10 rounded-xl p-5">
          <h3 className="text-lg font-semibold text-white mb-4">Nivel de Riesgo por Categoría</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.risk_categories}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="category" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                  }}
                />
                <Bar dataKey="score" fill="#06b6d4" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-[#111c32] border border-white/10 rounded-xl p-5">
          <h3 className="text-lg font-semibold text-white mb-4">Amenazas Activas</h3>
          <div className="space-y-3">
            {data.active_threats.map((threat: ThreatItem, index: number) => (
              <div
                key={index}
                className="flex items-center gap-3 p-3 bg-[#0d1424] rounded-lg border border-white/5"
              >
                <div className={`w-3 h-3 rounded-full ${severityColors[threat.severity]} ${
                  threat.severity === 'critical' ? 'animate-pulse' : ''
                }`} />
                <div className="flex-1">
                  <p className="text-sm font-medium text-white">{threat.name}</p>
                  <p className="text-xs text-gray-400">{threat.description}</p>
                </div>
                <span className={`text-xs font-medium ${severityTextColors[threat.severity]}`}>
                  {threat.count}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
