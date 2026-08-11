import { useState, useEffect } from 'react'
import { settingsAPI } from '../services/api'
import { Settings, User, Lock, Save, Server, Bell } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuth } from '../context/AuthContext'
import DataNote from '../components/DataNote'

export default function SettingsPage() {
  const { user } = useAuth()
  const [tab, setTab] = useState<'profile' | 'password' | 'system'>('profile')
  const [profile, setProfile] = useState({ full_name: '', email: '' })
  const [passwords, setPasswords] = useState({ current_password: '', new_password: '', confirm_password: '' })
  const [system, setSystem] = useState<any>(null)

  useEffect(() => {
    if (user) setProfile({ full_name: user.full_name || '', email: user.email || '' })
    loadSystem()
  }, [user])

  const loadSystem = async () => {
    try {
      const res = await settingsAPI.getSystem()
      setSystem(res.data)
    } catch {}
  }

  const saveProfile = async () => {
    try {
      await settingsAPI.updateProfile(profile)
      toast.success('Perfil actualizado')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Error al actualizar')
    }
  }

  const changePassword = async () => {
    if (passwords.new_password !== passwords.confirm_password) {
      toast.error('Las contraseñas no coinciden')
      return
    }
    if (passwords.new_password.length < 6) {
      toast.error('La contraseña debe tener al menos 6 caracteres')
      return
    }
    try {
      await settingsAPI.changePassword({ current_password: passwords.current_password, new_password: passwords.new_password })
      toast.success('Contraseña actualizada')
      setPasswords({ current_password: '', new_password: '', confirm_password: '' })
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Error al cambiar contraseña')
    }
  }

  const tabs = [
    { key: 'profile', label: 'Perfil', icon: User },
    { key: 'password', label: 'Contraseña', icon: Lock },
    { key: 'system', label: 'Sistema', icon: Server },
  ]

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Settings className="w-7 h-7 text-cyan-400" />
          Configuración
        </h1>
        <p className="text-gray-400 mt-1">Gestionar perfil, seguridad y configuración del sistema</p>
      </div>

      <div className="flex gap-2 mb-6">
        {tabs.map((t) => (
          <button key={t.key} onClick={() => setTab(t.key as any)} className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${tab === t.key ? 'bg-cyan-500/10 text-cyan-400' : 'text-gray-400 hover:text-white hover:bg-white/5'}`}>
            <t.icon className="w-4 h-4" />
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'profile' && (
        <div className="bg-[#111c32] border border-white/5 rounded-xl p-6 max-w-lg">
          <h2 className="text-lg font-semibold text-white mb-4">Información del Perfil</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-300 mb-1">Nombre completo</label>
              <input type="text" value={profile.full_name} onChange={(e) => setProfile({ ...profile, full_name: e.target.value })} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50" />
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-1">Correo electrónico</label>
              <input type="email" value={profile.email} onChange={(e) => setProfile({ ...profile, email: e.target.value })} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50" />
            </div>
            <button onClick={saveProfile} className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-blue-600 transition-all">
              <Save className="w-4 h-4" />
              Guardar Cambios
            </button>
          </div>
        </div>
      )}

      {tab === 'password' && (
        <div className="bg-[#111c32] border border-white/5 rounded-xl p-6 max-w-lg">
          <h2 className="text-lg font-semibold text-white mb-4">Cambiar Contraseña</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-300 mb-1">Contraseña actual</label>
              <input type="password" value={passwords.current_password} onChange={(e) => setPasswords({ ...passwords, current_password: e.target.value })} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50" />
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-1">Nueva contraseña</label>
              <input type="password" value={passwords.new_password} onChange={(e) => setPasswords({ ...passwords, new_password: e.target.value })} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50" />
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-1">Confirmar contraseña</label>
              <input type="password" value={passwords.confirm_password} onChange={(e) => setPasswords({ ...passwords, confirm_password: e.target.value })} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50" />
            </div>
            <button onClick={changePassword} className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-blue-600 transition-all">
              <Lock className="w-4 h-4" />
              Actualizar Contraseña
            </button>
          </div>
        </div>
      )}

      {tab === 'system' && system && (
        <div className="bg-[#111c32] border border-white/5 rounded-xl p-6 max-w-2xl space-y-4">
          <h2 className="text-lg font-semibold text-white">Configuración del Sistema</h2>

          <DataNote tone="info">{system.note}</DataNote>

          <div className="space-y-1">
            {[
              { label: 'Versión de la plataforma', value: system.app_version },
              { label: 'Duración del token de acceso', value: `${system.access_token_expire_minutes} minutos` },
              { label: 'Duración del token de refresco', value: `${system.refresh_token_expire_days} días` },
              { label: 'Máximo de activos por diagnóstico', value: String(system.scan_max_assets) },
              { label: 'Espera por puerto', value: `${system.scan_port_timeout_seconds} s` },
              { label: 'Presupuesto de tiempo por activo', value: `${system.scan_host_budget_seconds} s` },
            ].map((row) => (
              <div key={row.label} className="flex items-center justify-between py-3 border-b border-white/5">
                <p className="text-white font-medium">{row.label}</p>
                <p className="text-sm text-gray-400 tabular-nums">{row.value}</p>
              </div>
            ))}

            <div className="flex items-center justify-between py-3 border-b border-white/5">
              <div>
                <p className="text-white font-medium">Escaneo de redes privadas</p>
                <p className="text-sm text-gray-400">
                  Sondear direcciones internas desde el servidor
                </p>
              </div>
              <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${system.scan_allow_private_targets ? 'text-yellow-400 bg-yellow-500/10' : 'text-green-400 bg-green-500/10'}`}>
                {system.scan_allow_private_targets ? 'Permitido' : 'Bloqueado'}
              </span>
            </div>

            <div className="flex items-center justify-between py-3 border-b border-white/5">
              <div>
                <p className="text-white font-medium">Endpoint de datos de demostración</p>
                <p className="text-sm text-gray-400">Requiere la cabecera X-Seed-Token</p>
              </div>
              <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${system.seed_endpoint_enabled ? 'text-yellow-400 bg-yellow-500/10' : 'text-green-400 bg-green-500/10'}`}>
                {system.seed_endpoint_enabled ? 'Habilitado' : 'Deshabilitado'}
              </span>
            </div>

            <div className="py-3">
              <p className="text-white font-medium mb-2">Orígenes permitidos (CORS)</p>
              <div className="flex flex-wrap gap-2">
                {system.cors_origins.map((origin: string) => (
                  <span key={origin} className="text-xs font-mono text-gray-400 bg-[#0d1424] border border-white/5 rounded px-2 py-1">
                    {origin}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}
