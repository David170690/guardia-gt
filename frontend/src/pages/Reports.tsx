import { useState, useEffect } from 'react'
import { reportsAPI } from '../services/api'
import { Report } from '../types'
import { BarChart3, Download, Clock, FileText, TrendingDown } from 'lucide-react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

export default function Reports() {
  const [reports, setReports] = useState<Report[]>([])
  const [trends, setTrends] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [reportsRes, trendsRes] = await Promise.all([
          reportsAPI.list(),
          reportsAPI.getTrends(),
        ])
        setReports(reportsRes.data.reports)
        setTrends(trendsRes.data)
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

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Reportes y Analítica</h1>
        <p className="text-gray-400 mt-1">Tendencias de riesgo y métricas de seguridad</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#111c32] border border-white/10 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <TrendingDown className="w-5 h-5 text-cyan-400" />
            <h3 className="font-semibold text-white">Tendencia de Riesgo (6 meses)</h3>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trends ? {
                months: trends.months,
                risk_scores: trends.risk_scores,
              } : { months: [], risk_scores: [] }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="months" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="risk_scores"
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={{ fill: '#ef4444', strokeWidth: 2 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-[#111c32] border border-white/10 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <BarChart3 className="w-5 h-5 text-green-400" />
            <h3 className="font-semibold text-white">Métricas de Seguridad</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 bg-[#0d1424] rounded-lg">
              <span className="text-sm text-gray-400">Vulnerabilidades remediadas</span>
              <span className="text-sm font-bold text-green-400">127</span>
            </div>
            <div className="flex items-center justify-between p-3 bg-[#0d1424] rounded-lg">
              <span className="text-sm text-gray-400">Tiempo medio respuesta</span>
              <span className="text-sm font-bold text-cyan-400">42 min</span>
            </div>
            <div className="flex items-center justify-between p-3 bg-[#0d1424] rounded-lg">
              <span className="text-sm text-gray-400">Incidentes bloqueados</span>
              <span className="text-sm font-bold text-green-400">342</span>
            </div>
            <div className="flex items-center justify-between p-3 bg-[#0d1424] rounded-lg">
              <span className="text-sm text-gray-400">Phishing detectado</span>
              <span className="text-sm font-bold text-orange-400">89</span>
            </div>
            <div className="flex items-center justify-between p-3 bg-[#0d1424] rounded-lg">
              <span className="text-sm text-gray-400">Score de seguridad</span>
              <span className="text-sm font-bold text-cyan-400">73/100</span>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-[#111c32] border border-white/10 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <FileText className="w-5 h-5 text-purple-400" />
          <h3 className="font-semibold text-white">Reportes Generados</h3>
        </div>
        <div className="space-y-3">
          {reports.map((report) => (
            <div
              key={report.id}
              className="flex items-center justify-between p-4 bg-[#0d1424] rounded-lg border border-white/5 hover:border-cyan-500/30 transition-colors"
            >
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
                  <FileText className="w-5 h-5 text-purple-400" />
                </div>
                <div>
                  <h4 className="text-sm font-medium text-white">{report.name}</h4>
                  <p className="text-xs text-gray-400">
                    {report.pages ? `${report.pages} páginas` : 'Generando...'} · {report.format || '—'}
                    {report.generated_at && ` · ${new Date(report.generated_at).toLocaleDateString('es-GT')}`}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className={`text-xs font-medium ${
                  report.status === 'ready' ? 'text-green-400' : 'text-cyan-400 animate-pulse'
                }`}>
                  {report.status === 'ready' ? 'Listo' : 'Generando...'}
                </span>
                {report.status === 'ready' && (
                  <button className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors">
                    <Download className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
