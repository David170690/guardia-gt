import { Brain, Zap, Shield, AlertTriangle, TrendingUp, FileText } from 'lucide-react'

export default function AIInsights() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">IA Predictiva</h1>
        <p className="text-gray-400 mt-1">OpenAI + Llama — Predicción de ataques y generación de reportes</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gradient-to-br from-[#0f172a] to-[#1e293b] border border-white/10 rounded-xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/20 flex items-center justify-center">
              <Brain className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h3 className="font-semibold text-white">Predicción de Ataques</h3>
              <p className="text-xs text-gray-400">Basado en patrones de los últimos 90 días</p>
            </div>
          </div>
          <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg mb-4">
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-sm text-red-400 font-medium">Alta probabilidad de ataque ransomware</p>
                <p className="text-xs text-gray-400 mt-1">
                  Predicción para las próximas 72 horas contra servidores de base de datos.
                  Confianza: 87%
                </p>
              </div>
            </div>
          </div>
          <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
            <div className="flex items-start gap-2">
              <Zap className="w-5 h-5 text-yellow-400 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-sm text-yellow-400 font-medium">Intentos de phishing incrementando</p>
                <p className="text-xs text-gray-400 mt-1">
                  Incremento del 34% en campañas de phishing dirigidas al sector gubernamental.
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-gradient-to-br from-[#0f172a] to-[#1e293b] border border-white/10 rounded-xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
              <Shield className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <h3 className="font-semibold text-white">Análisis de Riesgos</h3>
              <p className="text-xs text-gray-400">Priorización automática con IA</p>
            </div>
          </div>
          <div className="space-y-3">
            <div className="p-3 bg-[#0d1424] rounded-lg border border-white/5">
              <div className="flex items-center justify-between">
                <span className="text-sm text-white">CVE-2026-1234</span>
                <span className="text-xs font-bold text-red-400">CVSS 9.8</span>
              </div>
              <p className="text-xs text-gray-400 mt-1">Prioridad: Inmediata — Servidor web expuesto</p>
            </div>
            <div className="p-3 bg-[#0d1424] rounded-lg border border-white/5">
              <div className="flex items-center justify-between">
                <span className="text-sm text-white">CVE-2026-0567</span>
                <span className="text-xs font-bold text-orange-400">CVSS 8.5</span>
              </div>
              <p className="text-xs text-gray-400 mt-1">Prioridad: Alta — Firewall vulnerable</p>
            </div>
            <div className="p-3 bg-[#0d1424] rounded-lg border border-white/5">
              <div className="flex items-center justify-between">
                <span className="text-sm text-white">CVE-2026-0891</span>
                <span className="text-xs font-bold text-orange-400">CVSS 7.2</span>
              </div>
              <p className="text-xs text-gray-400 mt-1">Prioridad: Alta — Base de datos comprometida</p>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-[#111c32] border border-white/10 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-lg bg-green-500/20 flex items-center justify-center">
            <FileText className="w-5 h-5 text-green-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white">Generación Automática de Reportes</h3>
            <p className="text-xs text-gray-400">Documentos listos para auditoría</p>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 bg-[#0d1424] rounded-lg border border-white/5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-white">Cumplimiento ISO 27001</span>
              <span className="text-xs text-green-400">Listo</span>
            </div>
            <p className="text-xs text-gray-400">48 páginas · PDF · Generado hoy</p>
          </div>
          <div className="p-4 bg-[#0d1424] rounded-lg border border-white/5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-white">Vulnerabilidades Mensual</span>
              <span className="text-xs text-green-400">Listo</span>
            </div>
            <p className="text-xs text-gray-400">24 páginas · PDF · Generado hoy</p>
          </div>
          <div className="p-4 bg-[#0d1424] rounded-lg border border-white/5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-white">Resumen Ejecutivo IA</span>
              <span className="text-xs text-green-400">Listo</span>
            </div>
            <p className="text-xs text-gray-400">12 páginas · PDF · Generado ayer</p>
          </div>
          <div className="p-4 bg-[#0d1424] rounded-lg border border-cyan-500/30">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-white">NIST CSF 2.0</span>
              <span className="text-xs text-cyan-400 animate-pulse">Generando...</span>
            </div>
            <p className="text-xs text-gray-400">En proceso · estimado 5 min</p>
          </div>
        </div>
      </div>

      <div className="bg-[#111c32] border border-white/10 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center">
            <TrendingUp className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white">Métricas de IA</h3>
            <p className="text-xs text-gray-400">Rendimiento de los modelos</p>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-3 bg-[#0d1424] rounded-lg border border-white/5 text-center">
            <p className="text-2xl font-bold text-cyan-400">87%</p>
            <p className="text-xs text-gray-400 mt-1">Precisión predicciones</p>
          </div>
          <div className="p-3 bg-[#0d1424] rounded-lg border border-white/5 text-center">
            <p className="text-2xl font-bold text-green-400">2.3s</p>
            <p className="text-xs text-gray-400 mt-1">Tiempo respuesta IA</p>
          </div>
          <div className="p-3 bg-[#0d1424] rounded-lg border border-white/5 text-center">
            <p className="text-2xl font-bold text-purple-400">1,247</p>
            <p className="text-xs text-gray-400 mt-1">Análisis este mes</p>
          </div>
          <div className="p-3 bg-[#0d1424] rounded-lg border border-white/5 text-center">
            <p className="text-2xl font-bold text-orange-400">Q245K</p>
            <p className="text-xs text-gray-400 mt-1">Ahorro estimado</p>
          </div>
        </div>
      </div>
    </div>
  )
}
