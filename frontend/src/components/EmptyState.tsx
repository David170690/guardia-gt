import { ReactNode } from 'react'
import { motion } from 'framer-motion'
import { Shield, Server, AlertTriangle, FileCheck, Search, Database, Lock, Activity } from 'lucide-react'

interface EmptyStateProps {
  title: string
  description: string
  icon?: ReactNode
  action?: ReactNode
  type?: 'default' | 'security' | 'data' | 'search'
}

const iconMap = {
  security: <Shield className="w-16 h-16" />,
  data: <Database className="w-16 h-16" />,
  search: <Search className="w-16 h-16" />,
  default: <Activity className="w-16 h-16" />,
}

export default function EmptyState({ title, description, icon, action, type = 'default' }: EmptyStateProps) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.4 }}
      className="flex flex-col items-center justify-center py-16 px-4"
    >
      <div className="relative mb-6">
        <div className="absolute inset-0 bg-cyan-500/20 blur-3xl rounded-full" />
        <div className="relative text-cyan-500/40">
          {icon || iconMap[type]}
        </div>
      </div>
      <h3 className="text-xl font-semibold text-white mb-2 text-center">{title}</h3>
      <p className="text-gray-400 text-center max-w-md mb-6">{description}</p>
      {action && <div>{action}</div>}
    </motion.div>
  )
}

export function EmptyVulnerabilities() {
  return (
    <EmptyState
      type="security"
      title="Sin vulnerabilidades detectadas"
      description="No se encontraron vulnerabilidades activas. Tu infraestructura está segura por el momento."
    />
  )
}

export function EmptyAssets() {
  return (
    <EmptyState
      type="data"
      title="No hay activos registrados"
      description="Comienza agregando activos a tu inventario o ejecuta un diagnóstico para escanear automáticamente."
    />
  )
}

export function EmptyIncidents() {
  return (
    <EmptyState
      type="security"
      title="Sin incidentes activos"
      description="No hay incidentes de seguridad que requieran atención en este momento."
    />
  )
}

export function EmptySearch() {
  return (
    <EmptyState
      type="search"
      title="Sin resultados"
      description="No se encontraron elementos que coincidan con tu búsqueda. Intenta con otros términos."
    />
  )
}

export function EmptyCompliance() {
  return (
    <EmptyState
      type="security"
      title="Sin controles de cumplimiento"
      description="Aún no se han configurado controles de cumplimiento normativo."
    />
  )
}

export function EmptyReports() {
  return (
    <EmptyState
      type="data"
      title="Sin reportes generados"
      description="Los reportes aparecerán aquí una vez que se generen desde el módulo de diagnóstico."
    />
  )
}

export function EmptyUsers() {
  return (
    <EmptyState
      type="data"
      title="Sin usuarios registrados"
      description="Crea el primer usuario para comenzar a usar la plataforma."
    />
  )
}
