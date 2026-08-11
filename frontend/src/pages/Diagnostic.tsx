import { useState } from 'react'
import { diagnosticAPI } from '../services/api'
import { DiagnosticResult, DiagnosticFinding } from '../types'
import {
  ScanSearch, Plus, Trash2, Server, Shield, AlertTriangle, FileCheck,
  CheckCircle2, ChevronDown, ChevronRight, Info, ExternalLink,
} from 'lucide-react'
import toast from 'react-hot-toast'
import Modal from '../components/Modal'
import DataNote from '../components/DataNote'

interface AssetInput {
  name: string
  asset_type: string
  ip_address: string
  operating_system: string
  criticality: string
}

/** Un identificador solo enlaza al NVD si es un CVE con formato real. */
const CVE_PATTERN = /^CVE-\d{4}-\d{4,7}$/

interface FindingExplanation {
  what: string
  risk: string
  fix: string
}

/**
 * Explicaciones por tipo de hallazgo.
 *
 * Las claves corresponden a los identificadores que emite el escáner. Ya no hay
 * entradas para CVEs concretos porque el escáner no afirma CVEs sin evidencia de
 * versión: reporta exposiciones, problemas de TLS y alcanzabilidad.
 */
const FINDING_DETAILS: Record<string, FindingExplanation> = {
  'SSL-EXPIRED': {
    what: 'El certificado TLS de este servicio ya expiró. Los navegadores muestran una advertencia de seguridad a todo el que intente entrar.',
    risk: 'Las conexiones dejan de estar verificadas. Un atacante en la misma red puede interponerse (man-in-the-middle) y capturar credenciales o inyectar contenido. Además, los usuarios pierden confianza y muchos abandonan el sitio.',
    fix: 'Renovar el certificado de inmediato. Con Let\'s Encrypt: certbot renew. Con un certificado comercial, solicitar la reemisión al proveedor y verificar que la renovación automática quede activa.',
  },
  'SSL-EXPIRING': {
    what: 'El certificado TLS sigue siendo válido pero vence en menos de 30 días.',
    risk: 'Si vence sin renovarse, el servicio queda inaccesible en la práctica: los navegadores bloquean o advierten, y las integraciones automatizadas fallan.',
    fix: 'Programar la renovación ahora y confirmar que el proceso automático funciona. Verificar también que el dominio del certificado coincida con el del servicio.',
  },
  'SSL-OK': {
    what: 'El certificado TLS del servicio es válido y está vigente. Este hallazgo es informativo.',
    risk: 'Ninguno. Se incluye en el informe como evidencia de que el cifrado en tránsito está correctamente configurado.',
    fix: 'Mantener la renovación automática y revisar la fecha de vencimiento en el próximo diagnóstico.',
  },
  'TLS-HANDSHAKE': {
    what: 'El puerto acepta conexiones pero no completó la negociación TLS, así que no fue posible leer su certificado.',
    risk: 'Puede indicar una configuración incorrecta, un certificado dañado o que el servicio solo acepta protocolos obsoletos como TLS 1.0/1.1, que ya no se consideran seguros.',
    fix: 'Revisar la configuración TLS del servidor. Habilitar TLS 1.2 y 1.3, y comprobar que la cadena de certificados esté completa.',
  },
  'HTTP-NO-TLS': {
    what: 'El servicio atiende peticiones HTTP sin cifrar y no se detectó un equivalente HTTPS.',
    risk: 'Todo el tráfico viaja legible: credenciales, cookies de sesión y datos de formularios pueden ser capturados por cualquiera en la ruta de red.',
    fix: 'Emitir un certificado (Let\'s Encrypt es gratuito), publicar el servicio en HTTPS y configurar una redirección permanente desde el puerto 80.',
  },
  'CLEARTEXT': {
    what: 'El servicio usa un protocolo que transmite credenciales y datos sin cifrar.',
    risk: 'Las contraseñas viajan en texto plano. Cualquier equipo en la ruta de red puede leerlas sin necesidad de romper ningún cifrado.',
    fix: 'Sustituir el protocolo por su equivalente cifrado (SFTP en lugar de FTP, SSH en lugar de Telnet, IMAPS en lugar de IMAP) y cerrar el puerto antiguo.',
  },
  'EXPOSED': {
    what: 'Este servicio respondió a una conexión desde fuera. El escaneo confirma que el puerto es alcanzable; no comprueba la versión ni la configuración interna.',
    risk: 'Bases de datos, escritorios remotos y paneles administrativos accesibles desde la red son objetivos habituales de fuerza bruta y de exploits publicados. La exposición no implica que el servicio sea vulnerable, pero amplía innecesariamente la superficie de ataque.',
    fix: 'Restringir el acceso por cortafuegos a las direcciones que realmente lo necesitan, o publicarlo únicamente a través de VPN.',
  },
  'BANNER': {
    what: 'El servicio incluye su nombre y versión en la respuesta de bienvenida.',
    risk: 'Riesgo bajo por sí solo. Le ahorra trabajo a un atacante: puede buscar exploits publicados para esa versión exacta en lugar de probar a ciegas.',
    fix: 'Suprimir el banner en la configuración del servicio (ServerTokens Prod en Apache, server_tokens off en Nginx) y, sobre todo, mantener el servicio actualizado.',
  },
  'NO-OPEN-PORTS': {
    what: 'Se sondearon los puertos del perfil y ninguno respondió.',
    risk: 'Ninguno. El activo puede estar apagado, protegido por un cortafuegos o sencillamente sin servicios publicados.',
    fix: 'No requiere acción si es el comportamiento esperado. Si el activo debería exponer un servicio, revisar que esté encendido y accesible.',
  },
  'UNREACHABLE': {
    what: 'El destino no pudo escanearse. La descripción del hallazgo indica el motivo exacto.',
    risk: 'No es un problema de seguridad del cliente, sino una limitación del escaneo: sin visibilidad no hay diagnóstico para ese activo.',
    fix: 'Para direcciones privadas, ejecutar GuardIA desde dentro de la red del cliente. Para nombres que no resuelven, verificar el DNS.',
  },
  'SCAN-PARTIAL': {
    what: 'El escaneo del activo agotó su presupuesto de tiempo antes de terminar.',
    risk: 'Los resultados de ese activo son incompletos: puede haber servicios expuestos que no se alcanzaron a sondear.',
    fix: 'Repetir el diagnóstico con menos activos por ejecución, o ampliar el presupuesto de tiempo en la configuración del servidor.',
  },
}

const COMPLIANCE_DETAILS: Record<string, { description: string; requirement: string; action: string }> = {
  iso_27001: {
    description: 'Norma internacional para sistemas de gestión de seguridad de la información (SGSI).',
    requirement: 'Establecer, implementar, mantener y mejorar de forma continua un sistema de gestión de seguridad de la información.',
    action: 'Implementar los controles del Anexo A, realizar auditorías internas y mantener la capacitación del personal.',
  },
  nist_csf: {
    description: 'Marco de ciberseguridad del Instituto Nacional de Estándares y Tecnología de Estados Unidos.',
    requirement: 'Gobernar, identificar, proteger, detectar, responder y recuperar frente a incidentes de ciberseguridad.',
    action: 'Mapear los activos, implementar controles preventivos, establecer monitoreo continuo y documentar planes de respuesta.',
  },
  cis_v8: {
    description: 'Controles de seguridad del Center for Internet Security, versión 8.',
    requirement: 'Implementar 18 controles prioritarios ordenados por impacto defensivo.',
    action: 'Comenzar por los controles básicos (inventario de activos y control de acceso) antes de avanzar a los avanzados.',
  },
  owasp_top10: {
    description: 'Los diez riesgos de seguridad más críticos en aplicaciones web según OWASP.',
    requirement: 'Mitigar debilidades como pérdida de control de acceso, inyección y fallos criptográficos.',
    action: 'Revisiones de código, pruebas de penetración, WAF y formación en desarrollo seguro.',
  },
  mitre_attack: {
    description: 'Marco de tácticas y técnicas de adversarios documentadas a partir de intrusiones reales.',
    requirement: 'Comprender y detectar las tácticas que emplean los atacantes a lo largo del ciclo de una intrusión.',
    action: 'Mapear los controles actuales contra el marco, identificar brechas de detección y priorizarlas.',
  },
}

const INCIDENT_DETAILS: Record<string, { what: string; impact: string; response: string }> = {
  critical: {
    what: 'Se abrió un incidente por un hallazgo de severidad CRÍTICA que representa un riesgo inmediato.',
    impact: 'Puede derivar en compromiso total del sistema, exfiltración masiva de datos o despliegue de ransomware.',
    response: '1. Aislar el activo afectado de la red\n2. Activar al equipo de respuesta a incidentes\n3. Aplicar el parche o la mitigación de emergencia\n4. Preservar evidencia para el análisis forense\n5. Notificar a la dirección y a las autoridades si corresponde',
  },
  high: {
    what: 'Se abrió un incidente por un hallazgo de severidad ALTA que requiere atención prioritaria.',
    impact: 'Puede aprovecharse para obtener acceso no autorizado, extraer información o servir de punto de entrada a un ataque mayor.',
    response: '1. Identificar el activo y el servicio afectado\n2. Evaluar si hay señales de explotación activa\n3. Aplicar el parche o una mitigación temporal\n4. Monitorear actividad sospechosa\n5. Documentar el incidente y su cierre',
  },
  medium: {
    what: 'Hallazgo de severidad MEDIA que podría explotarse en combinación con otras debilidades.',
    impact: 'Riesgo moderado de acceso parcial o divulgación de información no crítica.',
    response: '1. Programar la remediación en el próximo ciclo de parches\n2. Implementar controles compensatorios\n3. Vigilar intentos de explotación',
  },
  low: {
    what: 'Hallazgo de severidad BAJA que conviene atender, pero sin urgencia.',
    impact: 'Riesgo bajo por sí solo; generalmente requiere combinarse con otros factores para ser aprovechable.',
    response: '1. Incluir en el próximo mantenimiento programado\n2. Documentar para seguimiento\n3. Verificar que los controles existentes mitiguen el riesgo',
  },
}

const GENERIC_EXPLANATION: FindingExplanation = {
  what: 'Hallazgo identificado por el escáner de seguridad durante el diagnóstico.',
  risk: 'Revisar la descripción del hallazgo para dimensionar el impacto sobre el activo afectado.',
  fix: 'Aplicar la remediación sugerida y volver a ejecutar el diagnóstico para confirmar el cierre.',
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

  const resetForm = () => {
    setResult(null)
    setOrgName('')
    setIpRange('')
    setExpandedCard(null)
    setAssets([{ name: '', asset_type: 'server', ip_address: '', operating_system: '', criticality: 'medium' }])
  }

  const handleScan = async () => {
    if (!orgName.trim()) {
      toast.error('Ingresa el nombre de la organización')
      return
    }
    const validAssets = assets.filter((a) => a.name.trim())
    if (validAssets.length === 0) {
      toast.error('Agrega al menos un activo con nombre')
      return
    }

    setLoading(true)
    try {
      const res = await diagnosticAPI.run({
        organization_name: orgName.trim(),
        ip_range: ipRange,
        assets: validAssets,
        scan_type: scanType,
      })
      setResult(res.data)
      toast.success('Diagnóstico completado')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Error al ejecutar el diagnóstico')
    } finally {
      setLoading(false)
    }
  }

  const getFindingInfo = (finding: DiagnosticFinding): FindingExplanation => {
    const id = finding?.cve_id || ''
    const key = Object.keys(FINDING_DETAILS).find((k) => id.startsWith(k))
    if (key) return FINDING_DETAILS[key]
    if (CVE_PATTERN.test(id)) {
      return {
        what: `${finding.title}. Este identificador corresponde a una vulnerabilidad publicada en el catálogo CVE.`,
        risk: 'Consultar la entrada del NVD para conocer el vector de ataque y las versiones afectadas.',
        fix: finding.solution || 'Aplicar la actualización indicada por el fabricante.',
      }
    }
    return GENERIC_EXPLANATION
  }

  const getComplianceInfo = (standard: string) => {
    const key = (standard || '').toLowerCase()
    return COMPLIANCE_DETAILS[key] || {
      description: 'Estándar de cumplimiento de seguridad.',
      requirement: 'Cumplir con los controles establecidos por el marco.',
      action: 'Revisar e implementar los controles requeridos.',
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

  const sevColor: Record<string, string> = {
    critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400',
    low: 'text-green-400', info: 'text-gray-400',
  }
  const sevBg: Record<string, string> = {
    critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500',
    low: 'bg-green-500', info: 'bg-gray-500',
  }
  const statusColor: Record<string, string> = {
    open: 'text-red-400 bg-red-500/10', in_progress: 'text-yellow-400 bg-yellow-500/10',
    investigating: 'text-orange-400 bg-orange-500/10', remediated: 'text-green-400 bg-green-500/10',
    resolved: 'text-green-400 bg-green-500/10', contained: 'text-blue-400 bg-blue-500/10',
  }
  const compColor: Record<string, string> = {
    compliant: 'text-green-400', partial: 'text-yellow-400',
    non_compliant: 'text-red-400', not_applicable: 'text-gray-400',
  }
  const compLabel: Record<string, string> = {
    compliant: 'Cumple', partial: 'Parcial', non_compliant: 'No cumple', not_applicable: 'N/A',
  }
  const typeLabel: Record<string, string> = {
    cve: 'CVE confirmado', exposure: 'Exposición', ssl: 'Certificado TLS', reachability: 'Alcance',
  }

  if (result) {
    const toggleCard = (card: string) => setExpandedCard(expandedCard === card ? null : card)

    return (
      <div className="p-8">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <CheckCircle2 className="w-7 h-7 text-green-400" />
            Diagnóstico Completado
          </h1>
          <p className="text-gray-400 mt-1">{result.organization}</p>
        </div>

        <div className={`p-6 rounded-xl border mb-6 ${riskColors[result.risk_level] || 'text-gray-400 bg-gray-500/10 border-gray-500/20'}`}>
          <p className="text-lg font-semibold uppercase">Nivel de Riesgo: {result.risk_level}</p>
          <p className="mt-2 text-sm opacity-80">{result.summary}</p>
          <p className="mt-3 text-xs opacity-70">
            {result.assets_scanned} de {result.assets_created} activos escaneados
            {result.assets_unreachable > 0 && ` · ${result.assets_unreachable} no alcanzables`}
          </p>
        </div>

        {result.notes.length > 0 && (
          <div className="space-y-2 mb-6">
            {result.notes.map((note, i) => (
              <DataNote key={i} tone="info">{note}</DataNote>
            ))}
          </div>
        )}

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <button onClick={() => toggleCard('assets')} className={`bg-[#111c32] border rounded-xl p-5 text-center transition-all hover:border-cyan-500/30 ${expandedCard === 'assets' ? 'border-cyan-500/50 ring-1 ring-cyan-500/20' : 'border-white/5'}`}>
            <Server className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
            <p className="text-3xl font-bold text-white tabular-nums">{result.assets_created}</p>
            <p className="text-sm text-gray-400">Activos</p>
            <p className="text-xs text-cyan-400 mt-1 flex items-center justify-center gap-1">
              {expandedCard === 'assets' ? 'Ocultar' : 'Ver detalle'}
              {expandedCard === 'assets' ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
            </p>
          </button>

          <button onClick={() => toggleCard('vulns')} className={`bg-[#111c32] border rounded-xl p-5 text-center transition-all hover:border-red-500/30 ${expandedCard === 'vulns' ? 'border-red-500/50 ring-1 ring-red-500/20' : 'border-white/5'}`}>
            <Shield className="w-8 h-8 text-red-400 mx-auto mb-2" />
            <p className="text-3xl font-bold text-white tabular-nums">{result.vulnerabilities_found}</p>
            <p className="text-sm text-gray-400">Hallazgos accionables</p>
            <p className="text-xs text-red-400 mt-1 flex items-center justify-center gap-1">
              {expandedCard === 'vulns' ? 'Ocultar' : 'Ver detalle'}
              {expandedCard === 'vulns' ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
            </p>
          </button>

          <button onClick={() => toggleCard('incidents')} className={`bg-[#111c32] border rounded-xl p-5 text-center transition-all hover:border-orange-500/30 ${expandedCard === 'incidents' ? 'border-orange-500/50 ring-1 ring-orange-500/20' : 'border-white/5'}`}>
            <AlertTriangle className="w-8 h-8 text-orange-400 mx-auto mb-2" />
            <p className="text-3xl font-bold text-white tabular-nums">{result.incidents_created}</p>
            <p className="text-sm text-gray-400">Incidentes</p>
            <p className="text-xs text-orange-400 mt-1 flex items-center justify-center gap-1">
              {expandedCard === 'incidents' ? 'Ocultar' : 'Ver detalle'}
              {expandedCard === 'incidents' ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
            </p>
          </button>

          <button onClick={() => toggleCard('compliance')} className={`bg-[#111c32] border rounded-xl p-5 text-center transition-all hover:border-green-500/30 ${expandedCard === 'compliance' ? 'border-green-500/50 ring-1 ring-green-500/20' : 'border-white/5'}`}>
            <FileCheck className="w-8 h-8 text-green-400 mx-auto mb-2" />
            <p className="text-3xl font-bold text-white tabular-nums">{result.compliance_score}%</p>
            <p className="text-sm text-gray-400">Marco de referencia</p>
            <p className="text-xs text-green-400 mt-1 flex items-center justify-center gap-1">
              {expandedCard === 'compliance' ? 'Ocultar' : 'Ver detalle'}
              {expandedCard === 'compliance' ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
            </p>
          </button>
        </div>

        {expandedCard === 'assets' && (
          <div className="bg-[#111c32] border border-cyan-500/20 rounded-xl p-6 mb-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Server className="w-5 h-5 text-cyan-400" /> Activos Registrados
            </h3>
            <div className="space-y-2">
              {result.assets_detail.map((a) => (
                <div key={a.id} className="bg-[#0d1424] border border-white/5 rounded-lg p-4 flex items-center gap-4">
                  <div className="flex-1">
                    <p className="text-white font-medium">{a.name}</p>
                    <p className="text-sm text-gray-400">
                      {a.asset_type} · {a.ip_address || 'sin dirección'}
                      {a.operating_system && ` · ${a.operating_system}`}
                    </p>
                  </div>
                  <span className={`text-xs font-semibold uppercase ${sevColor[a.criticality] || 'text-gray-400'}`}>
                    {a.criticality}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {expandedCard === 'vulns' && (
          <div className="bg-[#111c32] border border-red-500/20 rounded-xl p-6 mb-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5 text-red-400" /> Hallazgos Detectados
            </h3>
            {result.vulns_detail.length > 0 ? (
              <div className="space-y-2">
                {result.vulns_detail.map((v) => (
                  <button key={v.id} onClick={() => openModal('vuln', v)} className="w-full text-left bg-[#0d1424] border border-white/5 hover:border-red-500/30 rounded-lg p-4 flex items-center gap-4 transition-all">
                    <div className="text-center min-w-[60px]">
                      <p className={`text-xl font-bold tabular-nums ${sevColor[v.severity] || 'text-gray-400'}`}>{v.cvss_score}</p>
                      <p className="text-xs text-gray-500">CVSS</p>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-medium">{v.title}</p>
                      <p className="text-sm text-gray-400 truncate">{v.cve_id} — {v.affected_component}</p>
                      {v.solution && <p className="text-xs text-cyan-400 mt-1 truncate">Solución: {v.solution}</p>}
                    </div>
                    <div className="text-right flex-shrink-0">
                      <span className={`inline-block px-2 py-1 rounded text-xs font-medium uppercase ${sevColor[v.severity]}`}>{v.severity}</span>
                      {v.finding_type && (
                        <p className="text-xs mt-1 text-gray-500">{typeLabel[v.finding_type] || v.finding_type}</p>
                      )}
                    </div>
                    <Info className="w-5 h-5 text-gray-500 flex-shrink-0" />
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-400 py-6 text-center">
                El escaneo no produjo hallazgos. Un informe vacío es un resultado válido.
              </p>
            )}
          </div>
        )}

        {expandedCard === 'incidents' && (
          <div className="bg-[#111c32] border border-orange-500/20 rounded-xl p-6 mb-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-orange-400" /> Incidentes Generados
            </h3>
            {result.incidents_detail.length > 0 ? (
              <div className="space-y-2">
                {result.incidents_detail.map((inc) => (
                  <button key={inc.id} onClick={() => openModal('incident', inc)} className="w-full text-left bg-[#0d1424] border border-white/5 hover:border-orange-500/30 rounded-lg p-4 flex items-center gap-4 transition-all">
                    <div className={`w-3 h-3 rounded-full flex-shrink-0 ${sevBg[inc.severity] || 'bg-gray-500'}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-medium">{inc.title}</p>
                      <p className="text-sm text-gray-400">Activo: {inc.affected_asset || 'N/A'}</p>
                      {inc.response_action && <p className="text-xs text-cyan-400 mt-1 truncate">Acción: {inc.response_action}</p>}
                    </div>
                    <div className="text-right flex-shrink-0">
                      <span className={`inline-block px-2 py-1 rounded text-xs font-medium uppercase ${sevColor[inc.severity] || 'text-gray-400'}`}>{inc.severity}</span>
                      <p className={`text-xs mt-1 px-2 py-0.5 rounded inline-block ${statusColor[inc.status] || 'text-gray-400 bg-gray-500/10'}`}>{inc.status}</p>
                    </div>
                    <Info className="w-5 h-5 text-gray-500 flex-shrink-0" />
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-400 py-6 text-center">
                No se generaron incidentes: no hubo hallazgos de severidad alta o crítica.
              </p>
            )}
          </div>
        )}

        {expandedCard === 'compliance' && (
          <div className="bg-[#111c32] border border-green-500/20 rounded-xl p-6 mb-6 space-y-4">
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <FileCheck className="w-5 h-5 text-green-400" /> Controles de Cumplimiento
            </h3>
            {!result.compliance_assessed && (
              <DataNote tone="demo" title="Marco de referencia, no una evaluación de este cliente">
                Estos controles son la línea base cargada en la plataforma. Todavía no se
                evalúan contra la infraestructura de {result.organization}: el porcentaje
                describe el marco, no el estado de cumplimiento de esta organización.
              </DataNote>
            )}
            <div className="space-y-2">
              {result.compliance_detail.map((c, i) => (
                <button key={i} onClick={() => openModal('compliance', c)} className="w-full text-left bg-[#0d1424] border border-white/5 hover:border-green-500/30 rounded-lg p-4 flex items-center gap-4 transition-all">
                  <div className="text-center min-w-[50px]">
                    <p className="text-lg font-bold text-white tabular-nums">{c.score}%</p>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-white font-medium">{c.control_name}</p>
                    <p className="text-sm text-gray-400">{(c.standard || '').toUpperCase()} — {c.control_id}</p>
                    {c.findings && <p className="text-xs text-yellow-400 mt-1">Hallazgo: {c.findings}</p>}
                  </div>
                  <span className={`text-xs font-semibold uppercase flex-shrink-0 ${compColor[c.status] || 'text-gray-400'}`}>
                    {compLabel[c.status] || c.status}
                  </span>
                  <Info className="w-5 h-5 text-gray-500 flex-shrink-0" />
                </button>
              ))}
            </div>
          </div>
        )}

        <button onClick={resetForm} className="px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-blue-600 transition-all">
          Nuevo Diagnóstico
        </button>

        {/* MODAL: HALLAZGO */}
        <Modal isOpen={modalOpen && modalType === 'vuln'} onClose={() => setModalOpen(false)} title="Detalle del Hallazgo">
          {selectedItem && (() => {
            const info = getFindingInfo(selectedItem)
            const isRealCve = CVE_PATTERN.test(selectedItem.cve_id || '')
            return (
              <div className="space-y-6">
                <div className="flex items-start gap-4">
                  <div className={`px-3 py-2 rounded-lg text-center flex-shrink-0 ${
                    selectedItem.severity === 'critical' ? 'bg-red-500/20 border border-red-500/30'
                    : selectedItem.severity === 'high' ? 'bg-orange-500/20 border border-orange-500/30'
                    : selectedItem.severity === 'medium' ? 'bg-yellow-500/20 border border-yellow-500/30'
                    : 'bg-green-500/20 border border-green-500/30'}`}>
                    <p className={`text-2xl font-bold tabular-nums ${sevColor[selectedItem.severity]}`}>{selectedItem.cvss_score}</p>
                    <p className="text-xs text-gray-400">CVSS</p>
                  </div>
                  <div className="min-w-0">
                    <h3 className="text-lg font-semibold text-white">{selectedItem.title}</h3>
                    <p className="text-sm text-gray-400 mt-1">{selectedItem.cve_id}</p>
                    <p className="text-sm text-gray-400">Componente: {selectedItem.affected_component}</p>
                    {selectedItem.finding_type && (
                      <span className="inline-block mt-2 px-2 py-0.5 rounded text-xs bg-white/5 text-gray-300 border border-white/10">
                        {typeLabel[selectedItem.finding_type] || selectedItem.finding_type}
                      </span>
                    )}
                  </div>
                </div>

                {selectedItem.finding_type === 'exposure' && (
                  <DataNote tone="info">
                    Este hallazgo confirma que el puerto responde desde la red. No se comprobó la
                    versión del servicio, así que no implica una vulnerabilidad conocida.
                  </DataNote>
                )}

                <div className="bg-[#0d1424] border border-white/5 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-cyan-400 mb-2 flex items-center gap-2">
                    <Shield className="w-4 h-4" /> ¿Qué significa este hallazgo?
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

                {selectedItem.ssl_info && (
                  <div className="bg-[#0d1424] border border-cyan-500/20 rounded-lg p-4">
                    <h4 className="text-sm font-semibold text-cyan-400 mb-3 flex items-center gap-2">
                      <Shield className="w-4 h-4" /> Certificado leído del servidor
                    </h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                      <div>
                        <p className="text-gray-500">Dominio (CN)</p>
                        <p className="text-white break-all">{selectedItem.ssl_info.cn || 'N/A'}</p>
                      </div>
                      <div className="min-w-0">
                        <p className="text-gray-500">Emisor</p>
                        <p className="text-white truncate" title={selectedItem.ssl_info.issuer || 'N/A'}>
                          {selectedItem.ssl_info.issuer || 'N/A'}
                        </p>
                      </div>
                      <div>
                        <p className="text-gray-500">Válido desde</p>
                        <p className="text-white">
                          {selectedItem.ssl_info.not_before
                            ? new Date(selectedItem.ssl_info.not_before).toLocaleDateString('es-GT')
                            : 'N/A'}
                        </p>
                      </div>
                      <div>
                        <p className="text-gray-500">Vence el</p>
                        <p className={`font-medium ${
                          selectedItem.ssl_info.expired ? 'text-red-400'
                          : (selectedItem.ssl_info.days_left ?? 999) <= 30 ? 'text-yellow-400'
                          : 'text-green-400'}`}>
                          {selectedItem.ssl_info.not_after
                            ? new Date(selectedItem.ssl_info.not_after).toLocaleDateString('es-GT')
                            : 'N/A'}
                          {selectedItem.ssl_info.days_left !== undefined && (
                            <span className="text-xs ml-2">({selectedItem.ssl_info.days_left} días)</span>
                          )}
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                <div className="flex items-center justify-between pt-2">
                  <span className={`inline-block px-3 py-1 rounded text-sm font-medium uppercase ${sevColor[selectedItem.severity]}`}>
                    Severidad: {selectedItem.severity}
                  </span>
                  {/* Solo se enlaza al NVD cuando el identificador es un CVE real:
                      los identificadores propios del escáner darían un 404. */}
                  {isRealCve && (
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${selectedItem.cve_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300"
                    >
                      <ExternalLink className="w-4 h-4" /> Ver en NVD
                    </a>
                  )}
                </div>
              </div>
            )
          })()}
        </Modal>

        {/* MODAL: INCIDENTE */}
        <Modal isOpen={modalOpen && modalType === 'incident'} onClose={() => setModalOpen(false)} title="Detalle de Incidente">
          {selectedItem && (() => {
            const info = INCIDENT_DETAILS[selectedItem.severity] || INCIDENT_DETAILS.medium
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
                    <CheckCircle2 className="w-4 h-4" /> Plan de respuesta
                  </h4>
                  <div className="text-sm text-gray-300 whitespace-pre-line">{info.response}</div>
                </div>

                <div className="flex gap-2 pt-2">
                  <span className={`inline-block px-3 py-1 rounded text-sm font-medium uppercase ${sevColor[selectedItem.severity]}`}>
                    {selectedItem.severity}
                  </span>
                  <span className={`inline-block px-3 py-1 rounded text-sm font-medium ${statusColor[selectedItem.status] || 'text-gray-400 bg-gray-500/10'}`}>
                    {selectedItem.status}
                  </span>
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
                  <div className="text-center flex-shrink-0">
                    <p className="text-3xl font-bold text-white tabular-nums">{selectedItem.score}%</p>
                    <p className="text-xs text-gray-400 mt-1">Cumplimiento</p>
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white">{selectedItem.control_name}</h3>
                    <p className="text-sm text-gray-400 mt-1">
                      {(selectedItem.standard || '').toUpperCase()} — {selectedItem.control_id}
                    </p>
                    <span className={`inline-block px-2 py-1 rounded text-xs font-medium uppercase mt-2 ${compColor[selectedItem.status] || 'text-gray-400'}`}>
                      {compLabel[selectedItem.status] || selectedItem.status}
                    </span>
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
                    <h4 className="text-sm font-semibold text-yellow-400 mb-2">Hallazgo registrado</h4>
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
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <ScanSearch className="w-7 h-7 text-cyan-400" />
          Nuevo Diagnóstico
        </h1>
        <p className="text-gray-400 mt-1">Escanear la infraestructura expuesta de una organización</p>
      </div>

      <DataNote tone="info" title="Qué escanea y qué no">
        El escaneo detecta puertos TCP abiertos y lee certificados TLS de direcciones públicas.
        Las direcciones privadas (192.168.x, 10.x, 172.16-31.x) no son alcanzables desde el
        servidor y se reportan como tales, sin inventar hallazgos. Escanea únicamente
        infraestructura que tengas autorización para evaluar.
      </DataNote>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 my-6">
        <div className="bg-[#111c32] border border-white/5 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Información del Cliente</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-300 mb-1">Nombre de la organización *</label>
              <input type="text" value={orgName} onChange={(e) => setOrgName(e.target.value)} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50" placeholder="Ej: Municipalidad de Guatemala" />
              <p className="text-xs text-gray-500 mt-1">
                Los resultados quedan asociados a este nombre. Repetir el diagnóstico reemplaza
                solo los datos de esta organización.
              </p>
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-1">Rango de IPs (referencia)</label>
              <input type="text" value={ipRange} onChange={(e) => setIpRange(e.target.value)} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50" placeholder="Ej: 203.0.113.0/24" />
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-1">Tipo de escaneo</label>
              <select value={scanType} onChange={(e) => setScanType(e.target.value)} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50">
                <option value="full">Completo — 26 puertos</option>
                <option value="vuln">Enfocado — 14 puertos de riesgo</option>
                <option value="quick">Rápido — 11 puertos comunes</option>
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
                    <button onClick={() => removeAsset(i)} className="p-1.5 text-gray-400 hover:text-red-400 transition-colors">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <select value={asset.asset_type} onChange={(e) => updateAsset(i, 'asset_type', e.target.value)} className="px-2 py-1.5 bg-[#111c32] border border-white/10 rounded text-white text-xs focus:outline-none">
                    {assetTypes.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                  <input type="text" value={asset.ip_address} onChange={(e) => updateAsset(i, 'ip_address', e.target.value)} className="px-2 py-1.5 bg-[#111c32] border border-white/10 rounded text-white text-xs focus:outline-none" placeholder="IP o dominio" />
                  <select value={asset.criticality} onChange={(e) => updateAsset(i, 'criticality', e.target.value)} className="px-2 py-1.5 bg-[#111c32] border border-white/10 rounded text-white text-xs focus:outline-none">
                    {criticalities.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
                  </select>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <button onClick={handleScan} disabled={loading} className="w-full py-3 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-semibold rounded-xl hover:from-cyan-600 hover:to-blue-600 transition-all disabled:opacity-50 disabled:cursor-not-allowed text-lg">
        {loading ? 'Escaneando…' : 'Ejecutar Diagnóstico'}
      </button>
    </div>
  )
}
