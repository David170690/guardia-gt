import { Info, FlaskConical } from 'lucide-react'

type Tone = 'info' | 'demo'

interface DataNoteProps {
  tone?: Tone
  title?: string
  children: React.ReactNode
}

const tones: Record<Tone, { wrap: string; icon: string; Icon: typeof Info }> = {
  info: {
    wrap: 'bg-cyan-500/5 border-cyan-500/20 text-cyan-300',
    icon: 'text-cyan-400',
    Icon: Info,
  },
  demo: {
    wrap: 'bg-amber-500/5 border-amber-500/25 text-amber-200',
    icon: 'text-amber-400',
    Icon: FlaskConical,
  },
}

/**
 * Nota sobre el origen de los datos de una vista.
 *
 * Se usa para marcar de forma visible qué pantallas muestran datos de
 * demostración, de modo que nadie los confunda con resultados medidos.
 */
export default function DataNote({ tone = 'info', title, children }: DataNoteProps) {
  const { wrap, icon, Icon } = tones[tone]
  return (
    <div className={`flex items-start gap-3 rounded-lg border px-4 py-3 ${wrap}`}>
      <Icon className={`w-4 h-4 mt-0.5 flex-shrink-0 ${icon}`} />
      <div className="text-sm leading-relaxed">
        {title && <p className="font-semibold mb-0.5">{title}</p>}
        <div className="opacity-90">{children}</div>
      </div>
    </div>
  )
}
