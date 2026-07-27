import { useState, useEffect } from 'react'
import { usersAPI } from '../services/api'
import { Users, Plus, Edit2, Trash2, X, Shield, UserCheck, UserX } from 'lucide-react'
import toast from 'react-hot-toast'

interface User {
  id: number
  email: string
  full_name: string
  role: string
  is_active: boolean
  mfa_enabled: boolean
  created_at: string
}

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [editingUser, setEditingUser] = useState<User | null>(null)
  const [form, setForm] = useState({ full_name: '', email: '', password: '', role: 'viewer' })

  useEffect(() => { loadUsers() }, [])

  const loadUsers = async () => {
    try {
      const res = await usersAPI.list()
      setUsers(res.data)
    } catch {
      toast.error('Error al cargar usuarios')
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      if (editingUser) {
        await usersAPI.update(editingUser.id, form)
        toast.success('Usuario actualizado')
      } else {
        await usersAPI.create(form)
        toast.success('Usuario creado')
      }
      setShowModal(false)
      setForm({ full_name: '', email: '', password: '', role: 'viewer' })
      setEditingUser(null)
      loadUsers()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Error al guardar')
    }
  }

  const handleEdit = (user: User) => {
    setEditingUser(user)
    setForm({ full_name: user.full_name, email: user.email, password: '', role: user.role })
    setShowModal(true)
  }

  const handleDelete = async (id: number) => {
    if (!confirm('¿Eliminar este usuario?')) return
    try {
      await usersAPI.delete(id)
      toast.success('Usuario eliminado')
      loadUsers()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Error al eliminar')
    }
  }

  const handleToggle = async (id: number) => {
    try {
      await usersAPI.toggleActive(id)
      toast.success('Estado actualizado')
      loadUsers()
    } catch {
      toast.error('Error al cambiar estado')
    }
  }

  const roleLabel = (role: string) => {
    const roles: Record<string, string> = { admin: 'Administrador', analyst: 'Analista', viewer: 'Observador' }
    return roles[role] || role
  }

  const roleColor = (role: string) => {
    const colors: Record<string, string> = { admin: 'text-red-400 bg-red-500/10', analyst: 'text-cyan-400 bg-cyan-500/10', viewer: 'text-gray-400 bg-gray-500/10' }
    return colors[role] || 'text-gray-400 bg-gray-500/10'
  }

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Users className="w-7 h-7 text-cyan-400" />
            Gestión de Usuarios
          </h1>
          <p className="text-gray-400 mt-1">Administrar cuentas y permisos del sistema</p>
        </div>
        <button
          onClick={() => { setEditingUser(null); setForm({ full_name: '', email: '', password: '', role: 'viewer' }); setShowModal(true) }}
          className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-blue-600 transition-all"
        >
          <Plus className="w-5 h-5" />
          Nuevo Usuario
        </button>
      </div>

      <div className="bg-[#111c32] border border-white/5 rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/5">
              <th className="text-left px-6 py-4 text-xs font-semibold text-gray-400 uppercase">Usuario</th>
              <th className="text-left px-6 py-4 text-xs font-semibold text-gray-400 uppercase">Email</th>
              <th className="text-left px-6 py-4 text-xs font-semibold text-gray-400 uppercase">Rol</th>
              <th className="text-left px-6 py-4 text-xs font-semibold text-gray-400 uppercase">Estado</th>
              <th className="text-left px-6 py-4 text-xs font-semibold text-gray-400 uppercase">Creado</th>
              <th className="text-right px-6 py-4 text-xs font-semibold text-gray-400 uppercase">Acciones</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id} className="border-b border-white/5 hover:bg-white/[0.02]">
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-full bg-gradient-to-br from-cyan-500 to-blue-500 flex items-center justify-center text-white text-sm font-bold">
                      {user.full_name.charAt(0)}
                    </div>
                    <span className="text-white font-medium">{user.full_name}</span>
                  </div>
                </td>
                <td className="px-6 py-4 text-gray-300">{user.email}</td>
                <td className="px-6 py-4">
                  <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium ${roleColor(user.role)}`}>
                    <Shield className="w-3 h-3" />
                    {roleLabel(user.role)}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium ${user.is_active ? 'text-green-400 bg-green-500/10' : 'text-red-400 bg-red-500/10'}`}>
                    {user.is_active ? <UserCheck className="w-3 h-3" /> : <UserX className="w-3 h-3" />}
                    {user.is_active ? 'Activo' : 'Inactivo'}
                  </span>
                </td>
                <td className="px-6 py-4 text-gray-400 text-sm">
                  {new Date(user.created_at).toLocaleDateString('es-GT')}
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center justify-end gap-2">
                    <button onClick={() => handleToggle(user.id)} className="p-2 rounded-lg text-gray-400 hover:text-yellow-400 hover:bg-yellow-500/10 transition-colors" title="Activar/Desactivar">
                      {user.is_active ? <UserX className="w-4 h-4" /> : <UserCheck className="w-4 h-4" />}
                    </button>
                    <button onClick={() => handleEdit(user)} className="p-2 rounded-lg text-gray-400 hover:text-cyan-400 hover:bg-cyan-500/10 transition-colors" title="Editar">
                      <Edit2 className="w-4 h-4" />
                    </button>
                    <button onClick={() => handleDelete(user.id)} className="p-2 rounded-lg text-gray-400 hover:text-red-400 hover:bg-red-500/10 transition-colors" title="Eliminar">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {users.length === 0 && !loading && (
          <div className="text-center py-12 text-gray-500">No hay usuarios registrados</div>
        )}
      </div>

      {showModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#111c32] border border-white/10 rounded-2xl p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-bold text-white">{editingUser ? 'Editar Usuario' : 'Nuevo Usuario'}</h2>
              <button onClick={() => setShowModal(false)} className="text-gray-400 hover:text-white"><X className="w-5 h-5" /></button>
            </div>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm text-gray-300 mb-1">Nombre completo</label>
                <input type="text" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50" required />
              </div>
              <div>
                <label className="block text-sm text-gray-300 mb-1">Email</label>
                <input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50" required />
              </div>
              <div>
                <label className="block text-sm text-gray-300 mb-1">{editingUser ? 'Nueva contraseña (dejar vacío para no cambiar)' : 'Contraseña'}</label>
                <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50" {...(!editingUser ? { required: true } : {})} />
              </div>
              <div>
                <label className="block text-sm text-gray-300 mb-1">Rol</label>
                <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} className="w-full px-4 py-2.5 bg-[#0d1424] border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50">
                  <option value="admin">Administrador</option>
                  <option value="analyst">Analista</option>
                  <option value="viewer">Observador</option>
                </select>
              </div>
              <button type="submit" className="w-full py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-blue-600 transition-all">
                {editingUser ? 'Guardar Cambios' : 'Crear Usuario'}
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
