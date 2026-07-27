import { useState, useEffect } from 'react'
import { assetsAPI } from '../services/api'
import { Asset, AssetStats } from '../types'
import { Server, Wifi, WifiOff, Monitor, Globe, Database, Cloud } from 'lucide-react'

const typeIcons: Record<string, any> = {
  server: Server,
  endpoint: Monitor,
  network: Globe,
  web_app: Globe,
  database: Database,
  cloud: Cloud,
}

const statusColors: Record<string, { bg: string; text: string; dot: string }> = {
  online: { bg: 'bg-green-500/10', text: 'text-green-400', dot: 'bg-green-500' },
  offline: { bg: 'bg-red-500/10', text: 'text-red-400', dot: 'bg-red-500' },
  maintenance: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', dot: 'bg-yellow-500' },
}

const criticalityColors: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-green-400',
}

export default function Assets() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [stats, setStats] = useState<AssetStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [assetsRes, statsRes] = await Promise.all([
          assetsAPI.list(),
          assetsAPI.getStats(),
        ])
        setAssets(assetsRes.data)
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
        <h1 className="text-2xl font-bold text-white">Gestión de Activos TI</h1>
        <p className="text-gray-400 mt-1">Inventario automatizado y monitoreo en tiempo real</p>
      </div>

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Total</p>
            <p className="text-2xl font-bold text-white">{stats.total}</p>
          </div>
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">En línea</p>
            <p className="text-2xl font-bold text-green-400">{stats.online}</p>
          </div>
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Offline</p>
            <p className="text-2xl font-bold text-red-400">{stats.offline}</p>
          </div>
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Servidores</p>
            <p className="text-2xl font-bold text-blue-400">{stats.servers}</p>
          </div>
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Endpoints</p>
            <p className="text-2xl font-bold text-purple-400">{stats.endpoints}</p>
          </div>
          <div className="bg-[#111c32] border border-white/10 rounded-xl p-4">
            <p className="text-sm text-gray-400">Apps Web</p>
            <p className="text-2xl font-bold text-cyan-400">{stats.web_apps}</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {assets.map((asset) => {
          const Icon = typeIcons[asset.asset_type] || Server
          const status = statusColors[asset.status] || statusColors.online
          return (
            <div
              key={asset.id}
              className="bg-[#111c32] border border-white/10 rounded-xl p-4 hover:border-cyan-500/30 transition-colors"
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center">
                    <Icon className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-white text-sm">{asset.name}</h3>
                    <p className="text-xs text-gray-400">{asset.ip_address}</p>
                  </div>
                </div>
                <div className={`flex items-center gap-1.5 ${status.text}`}>
                  <div className={`w-2 h-2 rounded-full ${status.dot}`} />
                  <span className="text-xs font-medium capitalize">{asset.status}</span>
                </div>
              </div>

              <p className="text-xs text-gray-400 mb-3">{asset.operating_system}</p>

              <div className="space-y-2">
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-400">CPU</span>
                    <span className="text-white">{asset.cpu_usage}%</span>
                  </div>
                  <div className="h-1.5 bg-[#0d1424] rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        asset.cpu_usage > 80 ? 'bg-red-500' :
                        asset.cpu_usage > 60 ? 'bg-yellow-500' : 'bg-green-500'
                      }`}
                      style={{ width: `${asset.cpu_usage}%` }}
                    />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-400">RAM</span>
                    <span className="text-white">{asset.ram_usage}%</span>
                  </div>
                  <div className="h-1.5 bg-[#0d1424] rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        asset.ram_usage > 80 ? 'bg-red-500' :
                        asset.ram_usage > 60 ? 'bg-yellow-500' : 'bg-green-500'
                      }`}
                      style={{ width: `${asset.ram_usage}%` }}
                    />
                  </div>
                </div>
              </div>

              <div className="mt-3 pt-3 border-t border-white/5 flex items-center justify-between">
                <span className={`text-xs font-medium ${criticalityColors[asset.criticality]}`}>
                  {asset.criticality.toUpperCase()}
                </span>
                <span className="text-xs text-gray-500">{asset.asset_type}</span>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
