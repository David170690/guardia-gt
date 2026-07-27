import { useState, useEffect } from 'react'
import { complianceAPI } from '../services/api'
import { ComplianceDashboard } from '../types'
import { FileCheck, CheckCircle, AlertCircle, XCircle } from 'lucide-react'

const standardNames: Record<string, string> = {
  iso_27001: 'ISO 27001',
  nist_csf: 'NIST CSF 2.0',
  cis_v8: 'CIS Controls v8',
  owasp_top10: 'OWASP Top 10',
  mitre_attack: 'MITRE ATT&CK',
}

const standardColors: Record<string, string> = {
  iso_27001: 'from-green-500 to-emerald-500',
  nist_csf: 'from-cyan-500 to-blue-500',
  cis_v8: 'from-orange-500 to-yellow-500',
  owasp_top10: 'from-purple-500 to-pink-500',
  mitre_attack: 'from-blue-500 to-indigo-500',
}

export default function Compliance() {
  const [data, setData] = useState<ComplianceDashboard | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await complianceAPI.getDashboard()
        setData(response.data)
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

  if (!data) return null

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Cumplimiento Normativo</h1>
        <p className="text-gray-400 mt-1">5 estándares internacionales evaluados simultáneamente</p>
      </div>

      <div className="bg-gradient-to-r from-[#111c32] to-[#1a2744] border border-white/10 rounded-xl p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-gray-400">Score General de Cumplimiento</p>
            <p className="text-4xl font-bold text-white mt-1">{data.overall_score}%</p>
          </div>
          <div className="text-right">
            <p className="text-sm text-gray-400">Hallazgos Críticos</p>
            <p className="text-4xl font-bold text-red-400 mt-1">{data.critical_findings}</p>
          </div>
        </div>
        <div className="mt-4 h-3 bg-[#0d1424] rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-500"
            style={{ width: `${data.overall_score}%` }}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
        {data.standards.map((std) => (
          <div
            key={std.standard}
            className="bg-[#111c32] border border-white/10 rounded-xl p-4 hover:border-cyan-500/30 transition-colors"
          >
            <div className={`w-12 h-12 rounded-lg bg-gradient-to-br ${standardColors[std.standard]} flex items-center justify-center mb-3`}>
              <FileCheck className="w-6 h-6 text-white" />
            </div>
            <h3 className="font-semibold text-white text-sm">{standardNames[std.standard]}</h3>
            <p className="text-2xl font-bold text-cyan-400 mt-2">{std.score}%</p>
            <div className="mt-3 space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-green-400 flex items-center gap-1">
                  <CheckCircle className="w-3 h-3" /> Cumple
                </span>
                <span className="text-white">{std.compliant}</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-yellow-400 flex items-center gap-1">
                  <AlertCircle className="w-3 h-3" /> Parcial
                </span>
                <span className="text-white">{std.partial}</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-red-400 flex items-center gap-1">
                  <XCircle className="w-3 h-3" /> No cumple
                </span>
                <span className="text-white">{std.non_compliant}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
