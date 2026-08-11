import { useState, useEffect } from 'react'
import { reportsAPI, incidentsAPI, vulnerabilitiesAPI } from '../services/api'
import { Report, ReportsResponse, TrendsResponse, IncidentStats, VulnerabilityStats } from '../types'
import { BarChart3, FileText, TrendingDown, Database } from 'lucide-react'
import {
  LineChart,
  Line,
  Legend,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import DataNote from '../components/DataNote'
import EmptyState from '../components/EmptyState'

export default function Reports() {
  const [data, setData] = useState<ReportsResponse | null>(null)
  const [trends, setTrends] = useState<TrendsResponse | null>(null)
  const [incidentStats, setIncidentStats] = useState<IncidentStats | null>(null)
  const [vulnStats, setVulnStats] = useState<VulnerabilityStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [reportsRes, trendsRes, incidentsRes, vulnsRes] = await Promise.all([
          reportsAPI.list(),
          reportsAPI.getTrends(),
          incidentsAPI.getStats(),
          vulnerabilitiesAPI.getStats(),
        ])
        setData(reportsRes.data)
        setTrends(trendsRes.data)
        setIncidentStats(incidentsRes.data)
        setVulnStats(vulnsRes.data)
      } catch (error) {
        console.error('Error:', error)
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

  const chartData = trends
    ? trends.months.map((month, i) => ({
        month,
        descubiertas: trends.vulnerabilities[i],
        remediadas: trends.remediated[i],
      }))
    : []

  const hasHistory = chartData.some((d) => d.descubiertas > 0 || d.remediadas > 0)

  // Todas estas métricas se leen de la API; ninguna está escrita en el componente.
  const metrics = [
    {
      label: 'Hallazgos abiertos',
      value: data ? String(data.summary.open_vulnerabilities) : '—',
      color: 'text-red-400',
    },
    {
      label: 'Hallazgos remediados',
      value: vulnStats ? String(vulnStats.remediated) : '—',
      color: 'text-green-400',
    },
    {
      label: 'Tiempo medio de resolución',
      value: incidentStats?.mttr_minutes != null ? `${incidentStats.mttr_minutes} min` : 'Sin datos',
      color: incidentStats?.mttr_minutes != null ? 'text-cyan-400' : 'text-gray-500',
    },
    {
      label: 'Incidentes activos',
      value: incidentStats ? String(incidentStats.active) : '—',
      color: 'text-orange-400',
    },
    {
      label: 'Activos registrados',
      value: data ? String(data.summary.total_assets) : '—',
      color: 'text-white',
    },
  ]

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Reportes y Analítica</h1>
        <p className="text-gray-400 mt-1">Tendencias y métricas calculadas sobre los datos de la plataforma</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#111c32] border border-white/10 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <TrendingDown className="w-5 h-5 text-cyan-400" />
            <h3 className="font-semibold text-white">Hallazgos por mes</h3>
          </div>
          {hasHistory ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="month" stroke="#64748b" fontSize={12} />
                  <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1e293b',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Line type="monotone" dataKey="descubiertas" stroke="#ef4444" strokeWidth={2} dot={{ fill: '#ef4444' }} />
                  <Line type="monotone" dataKey="remediadas" stroke="#22c55e" strokeWidth={2} dot={{ fill: '#22c55e' }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center">
              <p className="text-sm text-gray-500 text-center max-w-xs">
                Todavía no hay historial. La tendencia se construye con las fechas de los
                diagnósticos conforme los vayas ejecutando.
              </p>
            </div>
          )}
        </div>

        <div className="bg-[#111c32] border border-white/10 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <BarChart3 className="w-5 h-5 text-green-400" />
            <h3 className="font-semibold text-white">Métricas de Seguridad</h3>
          </div>
          <div className="space-y-3">
            {metrics.map((metric) => (
              <div key={metric.label} className="flex items-center justify-between p-3 bg-[#0d1424] rounded-lg">
                <span className="text-sm text-gray-400">{metric.label}</span>
                <span className={`text-sm font-bold tabular-nums ${metric.color}`}>{metric.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="bg-[#111c32] border border-white/10 rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-2">
          <FileText className="w-5 h-5 text-purple-400" />
          <h3 className="font-semibold text-white">Reportes Disponibles</h3>
        </div>

        {data?.note && <DataNote tone="info">{data.note}</DataNote>}

        {data && data.reports.length > 0 ? (
          <div className="space-y-3">
            {data.reports.map((report: Report) => (
              <div
                key={report.id}
                className="flex items-center justify-between p-4 bg-[#0d1424] rounded-lg border border-white/5"
              >
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center flex-shrink-0">
                    <Database className="w-5 h-5 text-purple-400" />
                  </div>
                  <div>
                    <h4 className="text-sm font-medium text-white">{report.name}</h4>
                    <p className="text-xs text-gray-400">{report.description}</p>
                  </div>
                </div>
                <div className="flex items-center gap-4 flex-shrink-0">
                  <span className="text-xs text-gray-400 tabular-nums">
                    {report.records} registro{report.records === 1 ? '' : 's'}
                  </span>
                  <span
                    className={`text-xs font-medium px-2 py-1 rounded ${
                      report.available
                        ? 'text-green-400 bg-green-500/10'
                        : 'text-gray-500 bg-gray-500/10'
                    }`}
                  >
                    {report.available ? 'Con datos' : 'Sin datos'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            type="data"
            title="Sin reportes"
            description="Ejecuta un diagnóstico para generar datos que reportar."
          />
        )}
      </div>
    </div>
  )
}
