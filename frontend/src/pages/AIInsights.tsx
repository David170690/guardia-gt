import { useState, useEffect } from 'react'
import { aiAPI, reportsAPI } from '../services/api'
import { Brain, Shield, AlertTriangle, CheckCircle2, FileDown, Sparkles, Cpu } from 'lucide-react'
import toast from 'react-hot-toast'
import DataNote from '../components/DataNote'
import EmptyState from '../components/EmptyState'

interface AiStatus {
  enabled: boolean
  model: string | null
  mode: string
  note: string
}

interface Report {
  organization: string
  risk_level: string
  generated_by: string
  model: string | null
  executive_summary: string
  key_risks: string[]
  remediation_plan: string[]
}

const riskColors: Record<string, string> = {
  crítico: 'text-red-400 bg-red-500/10 border-red-500/20',
  alto: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  medio: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  bajo: 'text-green-400 bg-green-500/10 border-green-500/20',
}

function downloadBlob(data: Blob, filename: string) {
  const url = window.URL.createObjectURL(data)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(url)
}

export default function AIInsights() {
  const [status, setStatus] = useState<AiStatus | null>(null)
  const [organizations, setOrganizations] = useState<string[]>([])
  const [selected, setSelected] = useState('')
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(false)
  const [downloading, setDownloading] = useState(false)

  useEffect(() => {
    const load = async () => {
      try {
        const [statusRes, orgsRes] = await Promise.all([
          aiAPI.getStatus(),
          aiAPI.listOrganizations(),
        ])
        setStatus(statusRes.data)
        const orgs = orgsRes.data.organizations || []
        setOrganizations(orgs)
        if (orgs.length > 0) setSelected(orgs[0])
      } catch {
        toast.error('No se pudo cargar el estado de la IA')
      }
    }
    load()
  }, [])

  const generate = async () => {
    if (!selected) {
      toast.error('Selecciona una organización')
      return
    }
    setLoading(true)
    setReport(null)
    try {
      const res = await aiAPI.generateReport(selected)
      setReport(res.data)
      toast.success('Informe generado')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'No se pudo generar el informe')
    } finally {
      setLoading(false)
    }
  }

  const downloadPdf = async () => {
    if (!selected) return
    setDownloading(true)
    try {
      const res = await reportsAPI.exportPdf(selected)
      downloadBlob(res.data, `informe_${selected.replace(/\s+/g, '_')}.pdf`)
    } catch {
      toast.error('No se pudo descargar el PDF')
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Informe Ejecutivo con IA</h1>
        <p className="text-gray-400 mt-1">
          Redacción del resumen ejecutivo y plan de remediación a partir de los hallazgos reales
        </p>
      </div>

      {status && (
        <DataNote tone={status.enabled ? 'info' : 'demo'} title={status.enabled ? `Modelo activo: ${status.model}` : 'Modo plantilla (sin modelo configurado)'}>
          {status.note}
        </DataNote>
      )}

      {/* Generador */}
      <div className="bg-[#111c32] border border-white/10 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/20 flex items-center justify-center">
            <Brain className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white">Generar informe</h3>
            <p className="text-xs text-gray-400">Elige una organización diagnosticada</p>
          </div>
        </div>

        {organizations.length > 0 ? (
          <div className="flex flex-col sm:flex-row gap-3">
            <select
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
              className="flex-1 px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            >
              {organizations.map((org) => (
                <option key={org} value={org}>{org}</option>
              ))}
            </select>
            <button
              onClick={generate}
              disabled={loading}
              className="flex items-center justify-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-blue-600 transition-all disabled:opacity-50"
            >
              <Sparkles className="w-4 h-4" />
              {loading ? 'Generando…' : 'Generar informe'}
            </button>
          </div>
        ) : (
          <p className="text-sm text-gray-400 py-4">
            Aún no hay organizaciones con datos. Ejecuta un diagnóstico primero.
          </p>
        )}
      </div>

      {/* Resultado */}
      {report && (
        <div className="space-y-4">
          <div className={`p-5 rounded-xl border flex items-center justify-between ${riskColors[report.risk_level] || 'text-gray-400 bg-gray-500/10 border-gray-500/20'}`}>
            <div>
              <p className="text-xs uppercase opacity-70">Nivel de riesgo</p>
              <p className="text-2xl font-bold uppercase">{report.risk_level}</p>
            </div>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1.5 text-xs opacity-80">
                <Cpu className="w-3.5 h-3.5" />
                {report.generated_by === 'mimo' ? `IA · ${report.model}` : 'Plantilla determinista'}
              </span>
              <button
                onClick={downloadPdf}
                disabled={downloading}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-white text-sm transition-colors disabled:opacity-50"
              >
                <FileDown className="w-4 h-4" />
                {downloading ? 'Generando PDF…' : 'Descargar PDF'}
              </button>
            </div>
          </div>

          <div className="bg-[#111c32] border border-white/10 rounded-xl p-6">
            <h3 className="text-sm font-semibold text-cyan-400 mb-2 flex items-center gap-2">
              <Shield className="w-4 h-4" /> Resumen ejecutivo
            </h3>
            <p className="text-sm text-gray-300 leading-relaxed">{report.executive_summary}</p>
          </div>

          {report.key_risks.length > 0 && (
            <div className="bg-[#111c32] border border-white/10 rounded-xl p-6">
              <h3 className="text-sm font-semibold text-orange-400 mb-3 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" /> Riesgos principales
              </h3>
              <ul className="space-y-2">
                {report.key_risks.map((risk, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                    <span className="text-orange-400 mt-0.5">•</span>
                    {risk}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {report.remediation_plan.length > 0 && (
            <div className="bg-[#111c32] border border-white/10 rounded-xl p-6">
              <h3 className="text-sm font-semibold text-green-400 mb-3 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4" /> Plan de remediación priorizado
              </h3>
              <ol className="space-y-2">
                {report.remediation_plan.map((step, i) => (
                  <li key={i} className="flex items-start gap-3 text-sm text-gray-300">
                    <span className="flex-shrink-0 w-5 h-5 rounded-full bg-green-500/20 text-green-400 text-xs flex items-center justify-center font-semibold">
                      {i + 1}
                    </span>
                    {step}
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      )}

      {!report && !loading && organizations.length > 0 && (
        <EmptyState
          type="security"
          title="Sin informe generado"
          description="Selecciona una organización y genera su informe ejecutivo con los hallazgos reales del diagnóstico."
        />
      )}
    </div>
  )
}
