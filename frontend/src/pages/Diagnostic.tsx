import { useState } from 'react'
import { diagnosticAPI } from '../services/api'
import { ScanSearch, Plus, Trash2, Server, Shield, AlertTriangle, FileCheck, CheckCircle2, ChevronDown, ChevronRight, Info, ExternalLink } from 'lucide-react'
import toast from 'react-hot-toast'
import Modal from '../components/Modal'

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

const VULN_DETAILS: Record<string, { what: string; risk: string; fix: string }> = {
  'CVE-2023-44487': {
    what: 'Vulnerabilidad HTTP/2 Rapid Reset que permite ataques de denegación de servicio (DoS) al enviar y cancelar rápidamente peticiones HTTP/2.',
    risk: 'Un atacante puede saturar el servidor con menos de 100 peticiones por segundo, dejando el servicio fuera de línea para usuarios legítimos.',
    fix: 'Actualizar el servidor web (Nginx, Apache, etc.) a la última versión que incluye el parche para esta vulnerabilidad.'
  },
  'CVE-2023-38408': {
    what: 'Vulnerabilidad en OpenSSH que permite ejecución remota de código cuando el agente SSH está forwarding y se conecta a un servidor malicioso.',
    risk: 'Un atacante remoto puede ejecutar código arbitrario en el cliente si este tiene agent forwarding habilitado y se conecta a un servidor comprometido.',
    fix: 'Actualizar OpenSSH a versión 9.3p2 o superior. Deshabilitar agent forwarding si no es necesario.'
  },
  'CVE-2023-26460': {
    what: 'Vulnerabilidad en servidores FTP que permite bypass de autenticación o acceso no autorizado.',
    risk: 'Un atacante puede acceder a archivos del servidor FTP sin credenciales válidas, exponiendo información confidencial.',
    fix: 'Actualizar el servidor FTP a la última versión. Considerar usar SFTP en su lugar.'
  },
  'CVE-2023-36884': {
    what: 'Vulnerabilidad en servicios de escritorio remoto (RDP, VNC) que permite elevación de privilegios o ejecución remota de código.',
    risk: 'Un atacante puede obtener control total del sistema comprometido, ejecutando código con privilegios de administrador.',
    fix: 'Aplicar parches del vendor. Restringir acceso a estos puertos solo por VPN o whitelist de IPs.'
  },
  'CVE-2023-28856': {
    what: 'Vulnerabilidad en Redis que permite ejecución de comandos arbitrarios cuando el servicio está expuesto sin autenticación.',
    risk: 'Un atacante puede leer/escribir datos, ejecutar comandos del sistema y comprometer completamente el servidor.',
    fix: 'Habilitar autenticación en Redis (requirepass). Restringir acceso por firewall. No exponer Redis a Internet.'
  },
  'ADMIN-EXPOSED': {
    what: 'Puerto administrativo expuesto a la red sin restricción de acceso.',
    risk: 'Servicios como RDP, VNC, FTP o bases de datos expuestos son targets comunes de fuerza bruta y ataques de día cero.',
    fix: 'Configurar firewall para permitir acceso solo desde IPs autorizadas. Usar VPN para acceso remoto.'
  },
  'VERSION-DETECTED': {
    what: 'El escáner detectó la versión exacta del servicio ejecutándose.',
    risk: 'Los atacantes pueden buscar vulnerabilidades específicas para esa versión conocida.',
    fix: 'Suprimir banners de versión donde sea posible. Mantener todos los servicios actualizados.'
  },
}

const INCIDENT_DETAILS: Record<string, { what: string; impact: string; response: string }> = {
  'high': {
    what: 'Se detectó una vulnerabilidad de severidad ALTA en tu infraestructura que requiere atención inmediata.',
    impact: 'Puede ser explotada para obtener acceso no autorizado, robo de datos o compromiso del sistema.',
    response: '1. Identificar el activo afectado\n2. Evaluar si está siendo explotada\n3. Aplicar parche o mitigación temporal\n4. Monitorear actividad sospechosa\n5. Documentar el incidente'
  },
  'critical': {
    what: 'Se detectó una vulnerabilidad CRÍTICA que representa un riesgo inminente para la organización.',
    impact: 'Puede permitir compromiso total del sistema, robo de datos masivo o ransomware.',
    response: '1. AISLAR el activo afectado de la red\n2. Activar equipo de respuesta a incidentes\n3. Aplicar parche de emergencia\n4. Realizar forense digital\n5. Notificar a la dirección y autoridades si aplica'
  },
  'medium': {
    what: 'Vulnerabilidad de severidad MEDIA que podría ser explotada en combinación con otras debilidades.',
    impact: 'Riesgo moderado de acceso parcial o fuga de información no crítica.',
    response: '1. Programar remediación en próximo ciclo de parches\n2. Implementar controles compensatorios\n3. Monitorear intentos de explotación'
  },
  'low': {
    what: 'Vulnerabilidad de severidad BAJA que representa un riesgo mínimo pero debe ser addressed.',
    impact: 'Riesgo bajo, generalmente requiere combinación con otros factores para ser explotada.',
    response: '1. Incluir en próximo mantenimiento programado\n2. Documentar para seguimiento\n3. Verificar que controles existentes mitigan el riesgo'
  },
}

const COMPLIANCE_DETAILS: Record<string, { description: string; requirement: string; action: string }> = {
  'ISO_27001': {
    description: 'Estándar internacional para sistemas de gestión de seguridad de la información (SGSI).',
    requirement: 'Establecer, implementar, mantener y mejorar continuamente un sistema de gestión de seguridad de la información.',
    action: 'Implementar controles del Anexo A, realizar auditorías internas, capacitación continua del personal.'
  },
  'NIST_CSF': {
    description: 'Marco de Ciberseguridad del Instituto Nacional de Estándares y Tecnología de EE.UU.',
    requirement: 'Identificar, proteger, detectar, responder y recuperar de incidentes de ciberseguridad.',
    action: 'Mapear activos, implementar controles preventivos, establecer monitoreo continuo, crear planes de respuesta.'
  },
  'CIS_V8': {
    description: 'Controles de Seguridad del Centro de Seguridad de Internet, versión 8.',
    requirement: 'Implementar 18 controles prioritarios de ciberseguridad en orden de impacto.',
    action: 'Comenzar con controles básicos (inventario de activos, control de acceso), avanzar a controles avanzados.'
  },
  'OWASP_TOP10': {
    description: 'Los 10 riesgos de seguridad más críticos en aplicaciones web según OWASP.',
    requirement: 'Mitigar vulnerabilidades como Broken Access Control, Injection, XSS, entre otras.',
    action: 'Realizar revisiones de código, pentesting, implementar WAF, capacitación en desarrollo seguro.'
  },
  'MITRE_ATTACK': {
    description: 'Framework de tácticas y técnicas de amenazas cibernéticas basado en experiencia real.',
    requirement: 'Comprender y detectar las tácticas que usan los atacantes en el ciclo de vida de un ataque.',
    action: 'Mapear controles actuales al framework, identificar brechas, implementar detección por tácticas.'
  },
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
  const [modalOpen, setModalOpen] = useState(false)
  const [modalType, setModalType] = useState<'vuln' | 'incident' | 'compliance'>('vuln')
  const [selectedItem, setSelectedItem] = useState<any>(null)

  const openModal = (type: 'vuln' | 'incident' | 'compliance', item: any) => {
    setModalType(type)
    setSelectedItem(item)
    setModalOpen(true)
  }

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

  const getVulnInfo = (cveId: string, title: string) => {
    if (!cveId) return {
      what: `Vulnerabilidad detectada: ${title || 'desconocida'}. Esta vulnerabilidad fue identificada por el escáner de seguridad y requiere revisión.`,
      risk: `Puede ser explotada para comprometer la seguridad del activo afectado.`,
      fix: `Revisar la documentación del CVE correspondiente y aplicar las recomendaciones del vendor.`
    }
    const key = Object.keys(VULN_DETAILS).find(k => cveId.includes(k))
    if (key) return VULN_DETAILS[key]
    if (cveId.includes('ADMIN')) return VULN_DETAILS['ADMIN-EXPOSED']
    if (cveId.includes('VERSION')) return VULN_DETAILS['VERSION-DETECTED']
    return {
      what: `Vulnerabilidad detectada: ${title}. Esta vulnerabilidad fue identificada por el escáner de seguridad y requiere revisión.`,
      risk: `Puede ser explotada para comprometer la seguridad del activo afectado.`,
      fix: `Revisar la documentación del CVE correspondiente y aplicar las recomendaciones del vendor.`
    }
  }

  const getIncidentInfo = (severity: string) => {
    return INCIDENT_DETAILS[severity] || INCIDENT_DETAILS['medium']
  }

  const getComplianceInfo = (standard: string) => {
    if (!standard) return {
      description: 'Estándar de cumplimiento de seguridad.',
      requirement: 'Cumplir con los controles establecidos.',
      action: 'Revisar y implementar los controles requeridos.'
    }
    const key = Object.keys(COMPLIANCE_DETAILS).find(k => standard.includes(k))
    return key ? COMPLIANCE_DETAILS[key] : {
      description: 'Estándar de cumplimiento de seguridad.',
      requirement: 'Cumplir con los controles establecidos.',
      action: 'Revisar y implementar los controles requeridos.'
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
    const sevBg: Record<string, string> = {
      critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-green-500',
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
    const compBg: Record<string, string> = {
      compliant: 'bg-green-500/10 border-green-500/20', partial: 'bg-yellow-500/10 border-yellow-500/20',
      non_compliant: 'bg-red-500/10 border-red-500/20',
    }
    const compLabel: Record<string, string> = {
      compliant: 'Cumple', partial: 'Parcial', non_compliant: 'No cumple', not_applicable: 'N/A',
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

        {/* DETALLE: VULNERABILIDADES */}
        {expandedCard === 'vulns' && result.vulns_detail && (
          <div className="bg-[#111c32] border border-red-500/20 rounded-xl p-6 mb-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2"><Shield className="w-5 h-5 text-red-400" /> Vulnerabilidades Detectadas</h3>
            <div className="space-y-2">
              {result.vulns_detail.map((v: any) => (
                <button key={v.id} onClick={() => openModal('vuln', v)} className="w-full text-left bg-[#0d1424] border border-white/5 hover:border-red-500/30 rounded-lg p-4 flex items-center gap-4 transition-all cursor-pointer">
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
                  <Info className="w-5 h-5 text-gray-500 flex-shrink-0" />
                </button>
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
                <button key={inc.id} onClick={() => openModal('incident', inc)} className="w-full text-left bg-[#0d1424] border border-white/5 hover:border-orange-500/30 rounded-lg p-4 flex items-center gap-4 transition-all cursor-pointer">
                  <div className={`w-3 h-3 rounded-full flex-shrink-0 ${sevBg[inc.severity] || 'bg-gray-500'}`} />
                  <div className="flex-1">
                    <p className="text-white font-medium">{inc.title}</p>
                    <p className="text-sm text-gray-400">Activo: {inc.affected_asset || 'N/A'}</p>
                    {inc.response_action && <p className="text-xs text-cyan-400 mt-1">Acción: {inc.response_action}</p>}
                  </div>
                  <div className="text-right">
                    <span className={`inline-block px-2 py-1 rounded text-xs font-medium uppercase ${sevColor[inc.severity] || 'text-gray-400'}`}>{inc.severity}</span>
                    <p className={`text-xs mt-1 px-2 py-0.5 rounded inline-block ${statusColor[inc.status] || 'text-gray-400 bg-gray-500/10'}`}>{inc.status}</p>
                  </div>
                  <Info className="w-5 h-5 text-gray-500 flex-shrink-0" />
                </button>
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
                <button key={i} onClick={() => openModal('compliance', c)} className="w-full text-left bg-[#0d1424] border border-white/5 hover:border-green-500/30 rounded-lg p-4 flex items-center gap-4 transition-all cursor-pointer">
                  <div className="text-center min-w-[50px]">
                    <p className="text-lg font-bold text-white">{c.score}%</p>
                  </div>
                  <div className="flex-1">
                    <p className="text-white font-medium">{c.control_name}</p>
                    <p className="text-sm text-gray-400">{c.standard.toUpperCase()} — {c.control_id}</p>
                    {c.findings && <p className="text-xs text-yellow-400 mt-1">Hallazgo: {c.findings}</p>}
                  </div>
                  <span className={`text-xs font-semibold uppercase ${compColor[c.status] || 'text-gray-400'}`}>{compLabel[c.status] || c.status}</span>
                  <Info className="w-5 h-5 text-gray-500 flex-shrink-0" />
                </button>
              ))}
            </div>
          </div>
        )}

        <button onClick={() => { setResult(null); setOrgName(''); setAssets([{ name: '', asset_type: 'server', ip_address: '', operating_system: '', criticality: 'medium' }]) }} className="px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-blue-600 transition-all">
          Nuevo Diagnóstico
        </button>

        {/* MODAL: VULNERABILIDAD */}
        <Modal isOpen={modalOpen && modalType === 'vuln'} onClose={() => setModalOpen(false)} title="Detalle de Vulnerabilidad">
          {selectedItem && (() => {
            const info = getVulnInfo(selectedItem.cve_id, selectedItem.title)
            return (
              <div className="space-y-6">
                <div className="flex items-start gap-4">
                  <div className={`px-3 py-2 rounded-lg text-center ${selectedItem.severity === 'critical' ? 'bg-red-500/20 border border-red-500/30' : selectedItem.severity === 'high' ? 'bg-orange-500/20 border border-orange-500/30' : selectedItem.severity === 'medium' ? 'bg-yellow-500/20 border border-yellow-500/30' : 'bg-green-500/20 border border-green-500/30'}`}>
                    <p className={`text-2xl font-bold ${sevColor[selectedItem.severity]}`}>{selectedItem.cvss_score}</p>
                    <p className="text-xs text-gray-400">CVSS</p>
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white">{selectedItem.title}</h3>
                    <p className="text-sm text-gray-400 mt-1">{selectedItem.cve_id}</p>
                    <p className="text-sm text-gray-400">Activo: {selectedItem.affected_component}</p>
                  </div>
                </div>

                <div className="bg-[#0d1424] border border-white/5 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-cyan-400 mb-2 flex items-center gap-2">
                    <Shield className="w-4 h-4" /> ¿Qué es esta vulnerabilidad?
                  </h4>
                  <p className="text-sm text-gray-300">{info.what}</p>
                </div>

                <div className="bg-[#0d1424] border border-white/5 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-orange-400 mb-2 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" /> ¿Cuál es el riesgo?
                  </h4>
                  <p className="text-sm text-gray-300">{info.risk}</p>
                </div>

                <div className="bg-[#0d1424] border border-white/5 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-green-400 mb-2 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4" /> ¿Cómo solucionarlo?
                  </h4>
                  <p className="text-sm text-gray-300">{info.fix}</p>
                </div>

                <div className="flex items-center justify-between pt-2">
                  <span className={`inline-block px-3 py-1 rounded text-sm font-medium uppercase ${sevColor[selectedItem.severity]}`}>Severidad: {selectedItem.severity}</span>
                  <a href={`https://nvd.nist.gov/vuln/detail/${selectedItem.cve_id}`} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300">
                    <ExternalLink className="w-4 h-4" /> Ver en NVD
                  </a>
                </div>
              </div>
            )
          })()}
        </Modal>

        {/* MODAL: INCIDENTE */}
        <Modal isOpen={modalOpen && modalType === 'incident'} onClose={() => setModalOpen(false)} title="Detalle de Incidente">
          {selectedItem && (() => {
            const info = getIncidentInfo(selectedItem.severity)
            return (
              <div className="space-y-6">
                <div className="flex items-start gap-4">
                  <div className={`w-4 h-4 rounded-full flex-shrink-0 mt-1 ${sevBg[selectedItem.severity] || 'bg-gray-500'}`} />
                  <div>
                    <h3 className="text-lg font-semibold text-white">{selectedItem.title}</h3>
                    <p className="text-sm text-gray-400 mt-1">Activo: {selectedItem.affected_asset || 'N/A'}</p>
                  </div>
                </div>

                <div className="bg-[#0d1424] border border-white/5 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-cyan-400 mb-2 flex items-center gap-2">
                    <Info className="w-4 h-4" /> ¿Qué está pasando?
                  </h4>
                  <p className="text-sm text-gray-300">{info.what}</p>
                </div>

                <div className="bg-[#0d1424] border border-white/5 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-orange-400 mb-2 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" /> ¿Cuál es el impacto?
                  </h4>
                  <p className="text-sm text-gray-300">{info.impact}</p>
                </div>

                <div className="bg-[#0d1424] border border-white/5 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-green-400 mb-2 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4" /> ¿Qué hacer? (Plan de Respuesta)
                  </h4>
                  <div className="text-sm text-gray-300 whitespace-pre-line">{info.response}</div>
                </div>

                <div className="flex items-center justify-between pt-2">
                  <div className="flex gap-2">
                    <span className={`inline-block px-3 py-1 rounded text-sm font-medium uppercase ${sevColor[selectedItem.severity]}`}>{selectedItem.severity}</span>
                    <span className={`inline-block px-3 py-1 rounded text-sm font-medium ${statusColor[selectedItem.status] || 'text-gray-400 bg-gray-500/10'}`}>{selectedItem.status}</span>
                  </div>
                </div>
              </div>
            )
          })()}
        </Modal>

        {/* MODAL: CUMPLIMIENTO */}
        <Modal isOpen={modalOpen && modalType === 'compliance'} onClose={() => setModalOpen(false)} title="Detalle de Cumplimiento">
          {selectedItem && (() => {
            const info = getComplianceInfo(selectedItem.standard)
            return (
              <div className="space-y-6">
                <div className="flex items-start gap-4">
                  <div className="text-center">
                    <p className="text-3xl font-bold text-white">{selectedItem.score}%</p>
                    <p className="text-xs text-gray-400 mt-1">Cumplimiento</p>
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white">{selectedItem.control_name}</h3>
                    <p className="text-sm text-gray-400 mt-1">{selectedItem.standard.toUpperCase()} — {selectedItem.control_id}</p>
                    <span className={`inline-block px-2 py-1 rounded text-xs font-medium uppercase mt-2 ${compColor[selectedItem.status] || 'text-gray-400'}`}>{compLabel[selectedItem.status] || selectedItem.status}</span>
                  </div>
                </div>

                <div className="bg-[#0d1424] border border-white/5 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-cyan-400 mb-2 flex items-center gap-2">
                    <Info className="w-4 h-4" /> ¿Qué es este estándar?
                  </h4>
                  <p className="text-sm text-gray-300">{info.description}</p>
                </div>

                <div className="bg-[#0d1424] border border-white/5 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-yellow-400 mb-2 flex items-center gap-2">
                    <FileCheck className="w-4 h-4" /> ¿Qué requiere?
                  </h4>
                  <p className="text-sm text-gray-300">{info.requirement}</p>
                </div>

                <div className="bg-[#0d1424] border border-white/5 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-green-400 mb-2 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4" /> ¿Qué acciones tomar?
                  </h4>
                  <p className="text-sm text-gray-300">{info.action}</p>
                </div>

                {selectedItem.findings && (
                  <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4">
                    <h4 className="text-sm font-semibold text-yellow-400 mb-2">Hallazgo Detectado</h4>
                    <p className="text-sm text-gray-300">{selectedItem.findings}</p>
                  </div>
                )}
              </div>
            )
          })()}
        </Modal>
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
