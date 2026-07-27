import { useState, useEffect } from 'react'
import { incidentsAPI } from '../services/api'
import { Incident, IncidentStats } from '../types'
import { AlertTriangle, Clock, CheckCircle, Search } from 'lucide-react'

const severityConfig: Record<string, { bg: string; text: string; border: string; label: string }> = {
  critical: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-l-red-500', label: 'Crítico' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-l-orange-500', label: 'Alto' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-l-yellow-500', label: 'Medio' },
  low: { bg: 'bg-green-500/10', text: 'text-green-400', border: 'border-l-green-500', label: 'Bajo' },
}

const statusConfig: Record<string, { bg: string; text: string; label: string }> = {
  open: { bg: 'bg-red-500/10', text: 'text-red-400', label: 'Abierto' },
  investigating: { bg: 'bg-orange-500/10', text: 'text-orange-400', label: 'Investigando' },
  contained: { bg: 'bg-blue-500/10', text: 'text-blue-400', label: 'Contenido' },
  resolved: { bg: 'bg-green-500/10', text: 'text-green-400', label: 'Resuelto' },
  closed: { bg: 'bg-gray-500/10', text: 'text-gray-400', label: 'Cerrado' },
}

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [stats, setStats] = useState<IncidentStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [incidentsRes, statsRes] = await Promise.all([
          incidentsAPI.list(),
          incidentsAPI.getStats(),
        ])
        setIncidents(incidentsRes.data)
        setStats(statsRes.data)
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
        <h1 className="text-2xl font-bold text-white">Gestión de Incidentes</h1>
        <p className="text-gray-400 mt-1">SOC virtual 24/7 — Detección y respuesta automatizada</p>
      </div>

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Activos</p>
            <p className="text-2xl font-bold text-red-400">{stats.active}</p>
          </div>
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Críticos</p>
            <p className="text-2xl font-bold text-orange-400">{stats.critical}</p>
          </div>
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Resueltos Hoy</p>
            <p className="text-2xl font-bold text-green-400">{stats.resolved_today}</p>
          </div>
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">MTTR</p>
            <p className="text-2xl font-bold text-cyan-400">{stats.mttr_minutes}min</p>
          </div>
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Total</p>
            <p className="text-2xl font-bold text-white">{stats.total}</p>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {incidents.map((incident) => {
          const severity = severityConfig[incident.severity]
          const status = statusConfig[incident.status]
          return (
            <div
              key={incident.id}
              className={`bg-[#111c32] border border-white/10 rounded-xl p-4 border-l-4 ${severity.border} hover:border-cyan-500/30 transition-colors`}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-xs font-medium ${severity.text}`}>
                      {severity.label}
                    </span>
                    <span className="text-gray-600">·</span>
                    <span className="text-xs text-gray-400">
                      {new Date(incident.detected_at).toLocaleString('es-GT')}
                    </span>
                  </div>
                  <h3 className="font-semibold text-white">{incident.title}</h3>
                  <p className="text-sm text-gray-400 mt-1">{incident.description}</p>
                  {incident.source_ip && (
                    <p className="text-xs text-gray-500 mt-2">
                      IP origen: <span className="font-mono text-gray-400">{incident.source_ip}</span>
                    </p>
                  )}
                  {incident.response_action && (
                    <p className="text-xs text-green-400 mt-2">
                      Acción: {incident.response_action}
                    </p>
                  )}
                </div>
                <div className="flex flex-col items-end gap-2">
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${status.bg} ${status.text}`}>
                    {status.label}
                  </span>
                  <span className="text-xs text-gray-500">{incident.affected_asset}</span>
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
