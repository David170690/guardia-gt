import { useState, useEffect } from 'react'
import { vulnerabilitiesAPI } from '../services/api'
import { Vulnerability, VulnerabilityStats } from '../types'
import { Shield, AlertCircle, CheckCircle, Clock, Search } from 'lucide-react'

const severityConfig: Record<string, { bg: string; text: string; label: string }> = {
  critical: { bg: 'bg-red-500/10', text: 'text-red-400', label: 'Crítico' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-400', label: 'Alto' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', label: 'Medio' },
  low: { bg: 'bg-green-500/10', text: 'text-green-400', label: 'Bajo' },
}

const statusConfig: Record<string, { bg: string; text: string; label: string }> = {
  open: { bg: 'bg-red-500/10', text: 'text-red-400', label: 'Abierta' },
  in_progress: { bg: 'bg-orange-500/10', text: 'text-orange-400', label: 'En progreso' },
  remediated: { bg: 'bg-green-500/10', text: 'text-green-400', label: 'Remediada' },
  accepted: { bg: 'bg-blue-500/10', text: 'text-blue-400', label: 'Aceptada' },
}

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState<Vulnerability[]>([])
  const [stats, setStats] = useState<VulnerabilityStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<string>('all')

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [vulnsRes, statsRes] = await Promise.all([
          vulnerabilitiesAPI.list(),
          vulnerabilitiesAPI.getStats(),
        ])
        setVulns(vulnsRes.data)
        setStats(statsRes.data)
      } catch (error) {
        console.error('Error:', error)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [])

  const filteredVulns = filter === 'all'
    ? vulns
    : vulns.filter((v) => v.severity === filter)

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
        <h1 className="text-2xl font-bold text-white">Vulnerabilidades</h1>
        <p className="text-gray-400 mt-1">Escaneo, tracking y priorización con IA</p>
      </div>

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Críticas</p>
            <p className="text-2xl font-bold text-red-400">{stats.critical}</p>
          </div>
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Altas</p>
            <p className="text-2xl font-bold text-orange-400">{stats.high}</p>
          </div>
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Medias</p>
            <p className="text-2xl font-bold text-yellow-400">{stats.medium}</p>
          </div>
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Bajas</p>
            <p className="text-2xl font-bold text-green-400">{stats.low}</p>
          </div>
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Remediadas</p>
            <p className="text-2xl font-bold text-cyan-400">{stats.remediated}</p>
          </div>
        </div>
      )}

      <div className="flex gap-2 flex-wrap">
        {['all', 'critical', 'high', 'medium', 'low'].map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              filter === f
                ? 'bg-cyan-500 text-white'
                : 'bg-[#111c32] text-gray-400 hover:text-white border border-white/10'
            }`}
          >
            {f === 'all' ? 'Todas' : severityConfig[f]?.label}
          </button>
        ))}
      </div>

      <div className="bg-[#111c32] border border-white/10 rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/10">
              <th className="text-left text-xs font-medium text-gray-400 uppercase tracking-wider px-4 py-3">
                CVE
              </th>
              <th className="text-left text-xs font-medium text-gray-400 uppercase tracking-wider px-4 py-3">
                Título
              </th>
              <th className="text-left text-xs font-medium text-gray-400 uppercase tracking-wider px-4 py-3">
                CVSS
              </th>
              <th className="text-left text-xs font-medium text-gray-400 uppercase tracking-wider px-4 py-3">
                Severidad
              </th>
              <th className="text-left text-xs font-medium text-gray-400 uppercase tracking-wider px-4 py-3">
                Estado
              </th>
              <th className="text-left text-xs font-medium text-gray-400 uppercase tracking-wider px-4 py-3">
                Activo
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {filteredVulns.map((vuln) => (
              <tr key={vuln.id} className="hover:bg-white/5 transition-colors">
                <td className="px-4 py-3">
                  <span className="font-mono text-sm text-cyan-400">{vuln.cve_id}</span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-sm text-white">{vuln.title}</span>
                </td>
                <td className="px-4 py-3">
                  <span className={`text-sm font-bold ${
                    vuln.cvss_score >= 9 ? 'text-red-400' :
                    vuln.cvss_score >= 7 ? 'text-orange-400' :
                    vuln.cvss_score >= 4 ? 'text-yellow-400' : 'text-green-400'
                  }`}>
                    {vuln.cvss_score}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${severityConfig[vuln.severity]?.bg} ${severityConfig[vuln.severity]?.text}`}>
                    {severityConfig[vuln.severity]?.label}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${statusConfig[vuln.status]?.bg} ${statusConfig[vuln.status]?.text}`}>
                    {statusConfig[vuln.status]?.label}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-sm text-gray-400">{vuln.affected_component}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
