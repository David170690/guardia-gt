import toast from 'react-hot-toast'
import { CheckCircle2, AlertCircle, AlertTriangle, Info, X, Shield } from 'lucide-react'

interface ToastOptions {
  duration?: number
  position?: 'top-right' | 'top-center' | 'top-left' | 'bottom-right' | 'bottom-center' | 'bottom-left'
}

const baseStyle = {
  background: 'rgba(17, 28, 50, 0.95)',
  backdropFilter: 'blur(12px)',
  color: '#f1f5f9',
  border: '1px solid rgba(255, 255, 255, 0.08)',
  borderRadius: '12px',
  padding: '12px 16px',
  fontSize: '14px',
  fontFamily: "'Plus Jakarta Sans', sans-serif",
}

export const toastSuccess = (message: string, options?: ToastOptions) => {
  return toast.custom(
    (t) => (
      <div
        style={{
          ...baseStyle,
          borderColor: t.visible ? 'rgba(34, 197, 94, 0.3)' : baseStyle.border,
          boxShadow: t.visible ? '0 0 20px rgba(34, 197, 94, 0.1)' : 'none',
        }}
        className="flex items-center gap-3"
      >
        <div className="w-8 h-8 rounded-lg bg-green-500/20 flex items-center justify-center flex-shrink-0">
          <CheckCircle2 className="w-5 h-5 text-green-400" />
        </div>
        <p className="flex-1 text-white font-medium">{message}</p>
        <button onClick={() => toast.dismiss(t.id)} className="text-gray-400 hover:text-white">
          <X className="w-4 h-4" />
        </button>
      </div>
    ),
    { duration: options?.duration || 4000, position: options?.position || 'top-right' }
  )
}

export const toastError = (message: string, options?: ToastOptions) => {
  return toast.custom(
    (t) => (
      <div
        style={{
          ...baseStyle,
          borderColor: t.visible ? 'rgba(239, 68, 68, 0.3)' : baseStyle.border,
          boxShadow: t.visible ? '0 0 20px rgba(239, 68, 68, 0.1)' : 'none',
        }}
        className="flex items-center gap-3"
      >
        <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center flex-shrink-0">
          <AlertCircle className="w-5 h-5 text-red-400" />
        </div>
        <p className="flex-1 text-white font-medium">{message}</p>
        <button onClick={() => toast.dismiss(t.id)} className="text-gray-400 hover:text-white">
          <X className="w-4 h-4" />
        </button>
      </div>
    ),
    { duration: options?.duration || 5000, position: options?.position || 'top-right' }
  )
}

export const toastWarning = (message: string, options?: ToastOptions) => {
  return toast.custom(
    (t) => (
      <div
        style={{
          ...baseStyle,
          borderColor: t.visible ? 'rgba(234, 179, 8, 0.3)' : baseStyle.border,
          boxShadow: t.visible ? '0 0 20px rgba(234, 179, 8, 0.1)' : 'none',
        }}
        className="flex items-center gap-3"
      >
        <div className="w-8 h-8 rounded-lg bg-yellow-500/20 flex items-center justify-center flex-shrink-0">
          <AlertTriangle className="w-5 h-5 text-yellow-400" />
        </div>
        <p className="flex-1 text-white font-medium">{message}</p>
        <button onClick={() => toast.dismiss(t.id)} className="text-gray-400 hover:text-white">
          <X className="w-4 h-4" />
        </button>
      </div>
    ),
    { duration: options?.duration || 4000, position: options?.position || 'top-right' }
  )
}

export const toastInfo = (message: string, options?: ToastOptions) => {
  return toast.custom(
    (t) => (
      <div
        style={{
          ...baseStyle,
          borderColor: t.visible ? 'rgba(6, 182, 212, 0.3)' : baseStyle.border,
          boxShadow: t.visible ? '0 0 20px rgba(6, 182, 212, 0.1)' : 'none',
        }}
        className="flex items-center gap-3"
      >
        <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
          <Info className="w-5 h-5 text-cyan-400" />
        </div>
        <p className="flex-1 text-white font-medium">{message}</p>
        <button onClick={() => toast.dismiss(t.id)} className="text-gray-400 hover:text-white">
          <X className="w-4 h-4" />
        </button>
      </div>
    ),
    { duration: options?.duration || 4000, position: options?.position || 'top-right' }
  )
}

export const toastSecurity = (message: string, options?: ToastOptions) => {
  return toast.custom(
    (t) => (
      <div
        style={{
          ...baseStyle,
          borderColor: t.visible ? 'rgba(168, 85, 247, 0.3)' : baseStyle.border,
          boxShadow: t.visible ? '0 0 20px rgba(168, 85, 247, 0.15)' : 'none',
        }}
        className="flex items-center gap-3"
      >
        <div className="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center flex-shrink-0">
          <Shield className="w-5 h-5 text-purple-400" />
        </div>
        <p className="flex-1 text-white font-medium">{message}</p>
        <button onClick={() => toast.dismiss(t.id)} className="text-gray-400 hover:text-white">
          <X className="w-4 h-4" />
        </button>
      </div>
    ),
    { duration: options?.duration || 5000, position: options?.position || 'top-right' }
  )
}
