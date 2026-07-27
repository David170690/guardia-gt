import { useState } from 'react'
import { diagnosticAPI } from '../services/api'
import { ScanSearch, Plus, Trash2, Server, Shield, AlertTriangle, FileCheck, CheckCircle2, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react'
import toast from 'react-hot-toast'

interface AssetInput {
  name: string
  asset_type: string
  ip_address: string
  operating_system: string
  criticality: string
}

interface DiagnosticResult {
  assets_created: number
  vulnerabilities_found: number
  incidents_created: number
  compliance_score: number
  risk_level: string
  summary: string
}

export default function Diagnostic() {
  const [orgName, setOrgName] = useState('')
  const [ipRange, setIpRange] = useState('')
  const [scanType, setScanType] = useState('full')
  const [assets, setAssets] = useState<AssetInput[]>([
    { name: '', asset_type: 'server', ip_address: '', operating_system: '', criticality: 'medium' },
  ])
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [expandedCard, setExpandedCard] = useState<string | null>(null)

  const addAsset = () => {
    setAssets([...assets, { name: '', asset_type: 'server', ip_address: '', operating_system: '', criticality: 'medium' }])
  }

  const removeAsset = (index: number) => {
    if (assets.length === 1) return
    setAssets(assets.filter((_, i) => i !== index))
  }

  const updateAsset = (index: number, field: keyof AssetInput, value: string) => {
    const updated = [...assets]
    updated[index] = { ...updated[index], [field]: value }
    setAssets(updated)
  }

  const handleScan = async () => {
    if (!orgName.trim()) { toast.error('Ingresa el nombre de la organización'); return }
    const validAssets = assets.filter(a => a.name.trim())
    if (validAssets.length === 0) { toast.error('Agrega al menos un activo con nombre'); return }

    setLoading(true)
    try {
      const res = await diagnosticAPI.run({
        organization_name: orgName,
        ip_range: ipRange,
        assets: validAssets,
        scan_type: scanType,
      })
      setResult(res.data)
      toast.success('Diagnóstico completado')
    } catch {
      toast.error('Error al ejecutar diagnóstico')
    } finally {
      setLoading(false)
    }
  }

  const assetTypes = [
    { value: 'server', label: 'Servidor' },
    { value: 'endpoint', label: 'Endpoint' },
    { value: 'network', label: 'Red/Firewall' },
    { value: 'web_app', label: 'Aplicación Web' },
    { value: 'database', label: 'Base de Datos' },
    { value: 'cloud', label: 'Cloud' },
  ]

  const criticalities = [
    { value: 'critical', label: 'Crítico' },
    { value: 'high', label: 'Alto' },
    { value: 'medium', label: 'Medio' },
    { value: 'low', label: 'Bajo' },
  ]

  const riskColors: Record<string, string> = {
    crítico: 'text-red-400 bg-red-500/10 border-red-500/20',
    alto: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    medio: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
    bajo: 'text-green-400 bg-green-500/10 border-green-500/20',
  }

  if (result) {
    const toggleCard = (card: string) => setExpandedCard(expandedCard === card ? null : card)

    const sevColor: Record<string, string> = {
      critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-green-400',
    }
    const statusColor: Record<string, string> = {
      open: 'text-red-400 bg-red-500/10', in_progress: 'text-yellow-400 bg-yellow-500/10',
      investigating: 'text-orange-400 bg-orange-500/10', remediated: 'text-green-400 bg-green-500/10',
      resolved: 'text-green-400 bg-green-500/10', contained: 'text-blue-400 bg-blue-500/10',
    }
    const critColor: Record<string, string> = {
      critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-green-400',
    }
    const compColor: Record<string, string> = {
      compliant: 'text-green-400', partial: 'text-yellow-400', non_compliant: 'text-red-400', not_applicable: 'text-gray-400',
    }

    return (
      <div className="p-8">
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <CheckCircle2 className="w-7 h-7 text-green-400" />
            Diagnóstico Completado
          </h1>
          <p className="text-gray-400 mt-1">{orgName}</p>
        </div>

        <div className={`p-6 rounded-xl border mb-8 ${riskColors[result.risk_level] || 'text-gray-400 bg-gray-500/10 border-gray-500/20'}`}>
          <p className="text-lg font-semibold uppercase">Nivel de Riesgo: {result.risk_level}</p>
          <p className="mt-2 text-sm opacity-80">{result.summary}</p>
        </div>

        <div className="grid grid-cols-4 gap-4 mb-8">
          <button onClick={() => toggleCard('assets')} className={`bg-[#111c32] border rounded-xl p-5 text-center transition-all hover:border-cyan-500/30 ${expandedCard === 'assets' ? 'border-cyan-500/50 ring-1 ring-cyan-500/20' : 'border-white/5'}`}>
            <Server className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
            <p className="text-3xl font-bold text-white">{result.assets_created}</p>
            <p className="text-sm text-gray-400">Activos Escaneados</p>
            <p className="text-xs text-cyan-400 mt-1 flex items-center justify-center gap-1">{expandedCard === 'assets' ? 'Ocultar' : 'Ver detalle'} {expandedCard === 'assets' ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}</p>
          </button>
          <button onClick={() => toggleCard('vulns')} className={`bg-[#111c32] border rounded-xl p-5 text-center transition-all hover:border-red-500/30 ${expandedCard === 'vulns' ? 'border-red-500/50 ring-1 ring-red-500/20' : 'border-white/5'}`}>
            <Shield className="w-8 h-8 text-red-400 mx-auto mb-2" />
            <p className="text-3xl font-bold text-white">{result.vulnerabilities_found}</p>
            <p className="text-sm text-gray-400">Vulnerabilidades</p>
            <p className="text-xs text-red-400 mt-1 flex items-center justify-center gap-1">{expandedCard === 'vulns' ? 'Ocultar' : 'Ver detalle'} {expandedCard === 'vulns' ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}</p>
          </button>
          <button onClick={() => toggleCard('incidents')} className={`bg-[#111c32] border rounded-xl p-5 text-center transition-all hover:border-orange-500/30 ${expandedCard === 'incidents' ? 'border-orange-500/50 ring-1 ring-orange-500/20' : 'border-white/5'}`}>
            <AlertTriangle className="w-8 h-8 text-orange-400 mx-auto mb-2" />
            <p className="text-3xl font-bold text-white">{result.incidents_created}</p>
            <p className="text-sm text-gray-400">Incidentes</p>
            <p className="text-xs text-orange-400 mt-1 flex items-center justify-center gap-1">{expandedCard === 'incidents' ? 'Ocultar' : 'Ver detalle'} {expandedCard === 'incidents' ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}</p>
          </button>
          <button onClick={() => toggleCard('compliance')} className={`bg-[#111c32] border rounded-xl p-5 text-center transition-all hover:border-green-500/30 ${expandedCard === 'compliance' ? 'border-green-500/50 ring-1 ring-green-500/20' : 'border-white/5'}`}>
            <FileCheck className="w-8 h-8 text-green-400 mx-auto mb-2" />
            <p className="text-3xl font-bold text-white">{result.compliance_score}%</p>
            <p className="text-sm text-gray-400">Cumplimiento</p>
            <p className="text-xs text-green-400 mt-1 flex items-center justify-center gap-1">{expandedCard === 'compliance' ? 'Ocultar' : 'Ver detalle'} {expandedCard === 'compliance' ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}</p>
          </button>
        </div>

        {/* DETALLE: ACTIVOS */}
        {expandedCard === 'assets' && result.assets_detail && (
          <div className="bg-[#111c32] border border-cyan-500/20 rounded-xl p-6 mb-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2"><Server className="w-5 h-5 text-cyan-400" /> Activos Escaneados</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {result.assets_detail.map((a: any) => (
                <div key={a.id} className="bg-[#0d1424] border border-white/5 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-white font-medium">{a.name}</span>
                    <span className={`text-xs font-semibold uppercase ${critColor[a.criticality] || 'text-gray-400'}`}>{a.criticality}</span>
                  </div>
                  <div className="space-y-1 text-sm text-gray-400">
                    <p>Tipo: <span className="text-gray-300">{a.asset_type}</span></p>
                    <p>IP: <span className="text-gray-300">{a.ip_address || 'N/A'}</span></p>
                    <p>SO: <span className="text-gray-300">{a.operating_system || 'N/A'}</span></p>
                    <p>Estado: <span className="text-green-400">{a.status}</span></p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* DETALLE: VULNERABILIDADES */}
        {expandedCard === 'vulns' && result.vulns_detail && (
          <div className="bg-[#111c32] border border-red-500/20 rounded-xl p-6 mb-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2"><Shield className="w-5 h-5 text-red-400" /> Vulnerabilidades Detectadas</h3>
            <div className="space-y-2">
              {result.vulns_detail.map((v: any) => (
                <div key={v.id} className="bg-[#0d1424] border border-white/5 rounded-lg p-4 flex items-center gap-4">
                  <div className="text-center min-w-[60px]">
                    <p className={`text-xl font-bold ${sevColor[v.severity] || 'text-gray-400'}`}>{v.cvss_score}</p>
                    <p className="text-xs text-gray-500">CVSS</p>
                  </div>
                  <div className="flex-1">
                    <p className="text-white font-medium">{v.title}</p>
                    <p className="text-sm text-gray-400">{v.cve_id} — {v.affected_component}</p>
                    {v.solution && <p className="text-xs text-cyan-400 mt-1">Solución: {v.solution}</p>}
                  </div>
                  <div className="text-right">
                    <span className={`inline-block px-2 py-1 rounded text-xs font-medium uppercase ${sevColor[v.severity]}`}>{v.severity}</span>
                    <p className={`text-xs mt-1 ${statusColor[v.status]?.split(' ')[0] || 'text-gray-400'}`}>{v.status}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* DETALLE: INCIDENTES */}
        {expandedCard === 'incidents' && result.incidents_detail && (
          <div className="bg-[#111c32] border border-orange-500/20 rounded-xl p-6 mb-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-orange-400" /> Incidentes Generados</h3>
            <div className="space-y-2">
              {result.incidents_detail.map((inc: any) => (
                <div key={inc.id} className="bg-[#0d1424] border border-white/5 rounded-lg p-4 flex items-center gap-4">
                  <div className={`w-3 h-3 rounded-full flex-shrink-0 ${inc.severity === 'critical' ? 'bg-red-500' : inc.severity === 'high' ? 'bg-orange-500' : inc.severity === 'medium' ? 'bg-yellow-500' : 'bg-green-500'}`} />
                  <div className="flex-1">
                    <p className="text-white font-medium">{inc.title}</p>
                    <p className="text-sm text-gray-400">Activo: {inc.affected_asset || 'N/A'}</p>
                    {inc.response_action && <p className="text-xs text-cyan-400 mt-1">Acción: {inc.response_action}</p>}
                  </div>
                  <div className="text-right">
                    <span className={`inline-block px-2 py-1 rounded text-xs font-medium uppercase ${sevColor[inc.severity] || 'text-gray-400'}`}>{inc.severity}</span>
                    <p className={`text-xs mt-1 px-2 py-0.5 rounded inline-block ${statusColor[inc.status] || 'text-gray-400 bg-gray-500/10'}`}>{inc.status}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* DETALLE: CUMPLIMIENTO */}
        {expandedCard === 'compliance' && result.compliance_detail && (
          <div className="bg-[#111c32] border border-green-500/20 rounded-xl p-6 mb-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2"><FileCheck className="w-5 h-5 text-green-400" /> Controles de Cumplimiento</h3>
            <div className="space-y-2">
              {result.compliance_detail.map((c: any, i: number) => (
                <div key={i} className="bg-[#0d1424] border border-white/5 rounded-lg p-4 flex items-center gap-4">
                  <div className="text-center min-w-[50px]">
                    <p className="text-lg font-bold text-white">{c.score}%</p>
                  </div>
                  <div className="flex-1">
                    <p className="text-white font-medium">{c.control_name}</p>
                    <p className="text-sm text-gray-400">{c.standard.toUpperCase()} — {c.control_id}</p>
                    {c.findings && <p className="text-xs text-yellow-400 mt-1">Hallazgo: {c.findings}</p>}
                  </div>
                  <span className={`text-xs font-semibold uppercase ${compColor[c.status] || 'text-gray-400'}`}>{c.status}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <button onClick={() => { setResult(null); setOrgName(''); setAssets([{ name: '', asset_type: 'server', ip_address: '', operating_system: '', criticality: 'medium' }]) }} className="px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-blue-600 transition-all">
          Nuevo Diagnóstico
        </button>
      </div>
    )
  }

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <ScanSearch className="w-7 h-7 text-cyan-400" />
          Nuevo Diagnóstico
        </h1>
        <p className="text-gray-400 mt-1">Escanear y diagnosticar la infraestructura de seguridad de un cliente</p>
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">
        <div className="bg-[#111c32] border border-white/5 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Información del Cliente</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-300 mb-1">Nombre de la organización *</label>
              <input type="text" value={orgName} onChange={(e) => setOrgName(e.target.value)} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50" placeholder="Ej: Municipalidad de Guatemala" />
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-1">Rango de IPs (opcional)</label>
              <input type="text" value={ipRange} onChange={(e) => setIpRange(e.target.value)} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50" placeholder="Ej: 192.168.1.0/24" />
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-1">Tipo de escaneo</label>
              <select value={scanType} onChange={(e) => setScanType(e.target.value)} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50">
                <option value="full">Completo (Activos + Vulns + Cumplimiento)</option>
                <option value="assets">Solo Activos</option>
                <option value="vulnerabilities">Solo Vulnerabilidades</option>
                <option value="compliance">Solo Cumplimiento</option>
              </select>
            </div>
          </div>
        </div>

        <div className="bg-[#111c32] border border-white/5 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">Activos a Escanear</h2>
            <button onClick={addAsset} className="flex items-center gap-1 px-3 py-1.5 text-sm text-cyan-400 hover:bg-cyan-500/10 rounded-lg transition-colors">
              <Plus className="w-4 h-4" /> Agregar
            </button>
          </div>
          <div className="space-y-3 max-h-[400px] overflow-auto">
            {assets.map((asset, i) => (
              <div key={i} className="bg-[#0d1424] border border-white/5 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-2">
                  <input type="text" value={asset.name} onChange={(e) => updateAsset(i, 'name', e.target.value)} className="flex-1 px-3 py-1.5 bg-transparent border border-white/10 rounded text-white text-sm focus:outline-none focus:ring-1 focus:ring-cyan-500/50" placeholder="Nombre del activo" />
                  {assets.length > 1 && (
                    <button onClick={() => removeAsset(i)} className="p-1.5 text-gray-400 hover:text-red-400 transition-colors"><Trash2 className="w-4 h-4" /></button>
                  )}
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <select value={asset.asset_type} onChange={(e) => updateAsset(i, 'asset_type', e.target.value)} className="px-2 py-1.5 bg-[#111c32] border border-white/10 rounded text-white text-xs focus:outline-none">
                    {assetTypes.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                  <input type="text" value={asset.ip_address} onChange={(e) => updateAsset(i, 'ip_address', e.target.value)} className="px-2 py-1.5 bg-[#111c32] border border-white/10 rounded text-white text-xs focus:outline-none" placeholder="IP" />
                  <select value={asset.criticality} onChange={(e) => updateAsset(i, 'criticality', e.target.value)} className="px-2 py-1.5 bg-[#111c32] border border-white/10 rounded text-white text-xs focus:outline-none">
                    {criticalities.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
                  </select>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <button onClick={handleScan} disabled={loading} className="w-full py-3 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-semibold rounded-xl hover:from-cyan-600 hover:to-blue-600 transition-all disabled:opacity-50 disabled:cursor-not-allowed text-lg">
        {loading ? 'Escaneando...' : 'Ejecutar Diagnóstico'}
      </button>
    </div>
  )
}
