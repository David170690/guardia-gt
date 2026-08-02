interface SkeletonProps {
  className?: string
  lines?: number
  type?: 'text' | 'card' | 'stat' | 'chart' | 'table'
}

export default function Skeleton({ className = '', lines = 1, type = 'text' }: SkeletonProps) {
  if (type === 'stat') {
    return (
      <div className={`glass-card rounded-xl p-5 ${className}`}>
        <div className="skeleton w-10 h-10 rounded-lg mb-3" />
        <div className="skeleton w-20 h-8 rounded mb-2" />
        <div className="skeleton w-32 h-4 rounded" />
      </div>
    )
  }

  if (type === 'card') {
    return (
      <div className={`glass-card rounded-xl p-6 ${className}`}>
        <div className="skeleton w-48 h-6 rounded mb-4" />
        <div className="skeleton w-full h-32 rounded-lg" />
      </div>
    )
  }

  if (type === 'chart') {
    return (
      <div className={`glass-card rounded-xl p-6 ${className}`}>
        <div className="skeleton w-40 h-6 rounded mb-4" />
        <div className="flex items-end gap-2 h-40">
          {[...Array(6)].map((_, i) => (
            <div
              key={i}
              className="skeleton flex-1 rounded-t"
              style={{ height: `${30 + Math.random() * 70}%` }}
            />
          ))}
        </div>
      </div>
    )
  }

  if (type === 'table') {
    return (
      <div className={`glass-card rounded-xl overflow-hidden ${className}`}>
        <div className="p-4 border-b border-white/5">
          <div className="skeleton w-48 h-6 rounded" />
        </div>
        {[...Array(lines)].map((_, i) => (
          <div key={i} className="flex items-center gap-4 p-4 border-b border-white/5">
            <div className="skeleton w-8 h-8 rounded-full" />
            <div className="flex-1">
              <div className="skeleton w-3/4 h-4 rounded mb-2" />
              <div className="skeleton w-1/2 h-3 rounded" />
            </div>
            <div className="skeleton w-16 h-6 rounded-full" />
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className={`space-y-2 ${className}`}>
      {[...Array(lines)].map((_, i) => (
        <div
          key={i}
          className="skeleton h-4 rounded"
          style={{ width: `${60 + Math.random() * 40}%` }}
        />
      ))}
    </div>
  )
}

export function DashboardSkeleton() {
  return (
    <div className="p-8 space-y-6">
      <div className="skeleton w-64 h-8 rounded mb-2" />
      <div className="skeleton w-96 h-4 rounded" />

      <div className="glass-card rounded-xl p-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="skeleton w-48 h-4 rounded mb-2" />
            <div className="skeleton w-20 h-10 rounded" />
          </div>
          <div className="skeleton w-24 h-16 rounded-lg" />
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <Skeleton key={i} type="stat" />
        ))}
      </div>

      <div className="grid grid-cols-2 gap-6">
        <Skeleton type="chart" />
        <Skeleton type="card" />
      </div>
    </div>
  )
}

export function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return <Skeleton type="table" lines={rows} />
}
