import { useState, useEffect } from 'react'
import { settingsAPI } from '../services/api'
import { Settings, User, Lock, Save, Server, ShieldCheck } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuth } from '../context/AuthContext'
import DataNote from '../components/DataNote'

export default function SettingsPage() {
  const { user, checkAuth } = useAuth()
  const [tab, setTab] = useState<'profile' | 'password' | 'mfa' | 'system'>('profile')
  const [profile, setProfile] = useState({ full_name: '', email: '' })
  const [passwords, setPasswords] = useState({ current_password: '', new_password: '', confirm_password: '' })
  const [system, setSystem] = useState<any>(null)

  // MFA
  const [mfaSetup, setMfaSetup] = useState<{ qr_data_uri: string; secret: string } | null>(null)
  const [mfaCode, setMfaCode] = useState('')
  const [disablePassword, setDisablePassword] = useState('')

  useEffect(() => {
    if (user) setProfile({ full_name: user.full_name || '', email: user.email || '' })
    loadSystem()
  }, [user])

  const startMfaSetup = async () => {
    try {
      const res = await settingsAPI.mfaSetup()
      setMfaSetup(res.data)
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'No se pudo iniciar la configuración de MFA')
    }
  }

  const enableMfa = async () => {
    try {
      await settingsAPI.mfaEnable(mfaCode)
      toast.success('MFA activado')
      setMfaSetup(null)
      setMfaCode('')
      await checkAuth()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Código incorrecto')
    }
  }

  const disableMfa = async () => {
    try {
      await settingsAPI.mfaDisable(disablePassword)
      toast.success('MFA desactivado')
      setDisablePassword('')
      await checkAuth()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'No se pudo desactivar')
    }
  }

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
    if (passwords.new_password.length < 8) {
      toast.error('La contraseña debe tener al menos 8 caracteres')
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
    { key: 'mfa', label: 'Doble factor', icon: ShieldCheck },
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

      {tab === 'mfa' && (
        <div className="bg-[#111c32] border border-white/5 rounded-xl p-6 max-w-lg space-y-4">
          <div>
            <h2 className="text-lg font-semibold text-white">Autenticación de doble factor</h2>
            <p className="text-sm text-gray-400 mt-1">
              Estado actual:{' '}
              <span className={user?.mfa_enabled ? 'text-green-400 font-medium' : 'text-yellow-400 font-medium'}>
                {user?.mfa_enabled ? 'Activado' : 'Desactivado'}
              </span>
            </p>
          </div>

          {!user?.mfa_enabled && !mfaSetup && (
            <>
              <DataNote tone="info">
                Añade una segunda capa de seguridad con una app como Google Authenticator o Authy.
                Al iniciar sesión se pedirá un código de seis dígitos además de tu contraseña.
              </DataNote>
              <button
                onClick={startMfaSetup}
                className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-blue-600 transition-all"
              >
                <ShieldCheck className="w-4 h-4" />
                Activar doble factor
              </button>
            </>
          )}

          {!user?.mfa_enabled && mfaSetup && (
            <div className="space-y-4">
              <p className="text-sm text-gray-300">
                1. Escanea este código QR con tu app de autenticación:
              </p>
              <div className="bg-white p-3 rounded-lg w-fit">
                <img src={mfaSetup.qr_data_uri} alt="Código QR de MFA" className="w-44 h-44" />
              </div>
              <p className="text-xs text-gray-500">
                ¿No puedes escanear? Ingresa la clave manualmente:{' '}
                <span className="font-mono text-gray-300 break-all">{mfaSetup.secret}</span>
              </p>
              <div>
                <label className="block text-sm text-gray-300 mb-1">2. Ingresa el código de seis dígitos</label>
                <input
                  type="text"
                  inputMode="numeric"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white tracking-widest focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
                  placeholder="000000"
                />
              </div>
              <div className="flex gap-2">
                <button
                  onClick={enableMfa}
                  className="px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-blue-600 transition-all"
                >
                  Confirmar y activar
                </button>
                <button
                  onClick={() => { setMfaSetup(null); setMfaCode('') }}
                  className="px-5 py-2.5 text-gray-400 hover:text-white rounded-lg transition-colors"
                >
                  Cancelar
                </button>
              </div>
            </div>
          )}

          {user?.mfa_enabled && (
            <div className="space-y-4">
              <DataNote tone="info">
                El doble factor está activo en tu cuenta. Para desactivarlo, confirma tu contraseña.
              </DataNote>
              <div>
                <label className="block text-sm text-gray-300 mb-1">Contraseña actual</label>
                <input
                  type="password"
                  value={disablePassword}
                  onChange={(e) => setDisablePassword(e.target.value)}
                  className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
                />
              </div>
              <button
                onClick={disableMfa}
                className="px-5 py-2.5 bg-red-500/10 text-red-400 border border-red-500/20 font-medium rounded-lg hover:bg-red-500/20 transition-all"
              >
                Desactivar doble factor
              </button>
            </div>
          )}
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
