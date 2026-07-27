import { useState } from 'react'
import { diagnosticAPI } from '../services/api'
import { ScanSearch, Plus, Trash2, Server, Shield, AlertTriangle, FileCheck, CheckCircle2 } from 'lucide-react'
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
  const [result, setResult] = useState<DiagnosticResult | null>(null)
  const [loading, setLoading] = useState(false)

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
          <div className="bg-[#111c32] border border-white/5 rounded-xl p-5 text-center">
            <Server className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
            <p className="text-3xl font-bold text-white">{result.assets_created}</p>
            <p className="text-sm text-gray-400">Activos Escaneados</p>
          </div>
          <div className="bg-[#111c32] border border-white/5 rounded-xl p-5 text-center">
            <Shield className="w-8 h-8 text-red-400 mx-auto mb-2" />
            <p className="text-3xl font-bold text-white">{result.vulnerabilities_found}</p>
            <p className="text-sm text-gray-400">Vulnerabilidades</p>
          </div>
          <div className="bg-[#111c32] border border-white/5 rounded-xl p-5 text-center">
            <AlertTriangle className="w-8 h-8 text-orange-400 mx-auto mb-2" />
            <p className="text-3xl font-bold text-white">{result.incidents_created}</p>
            <p className="text-sm text-gray-400">Incidentes</p>
          </div>
          <div className="bg-[#111c32] border border-white/5 rounded-xl p-5 text-center">
            <FileCheck className="w-8 h-8 text-green-400 mx-auto mb-2" />
            <p className="text-3xl font-bold text-white">{result.compliance_score}%</p>
            <p className="text-sm text-gray-400">Cumplimiento</p>
          </div>
        </div>

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
