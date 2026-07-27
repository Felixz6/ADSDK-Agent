import { AnimatePresence, motion } from 'framer-motion'
import { CheckCircle2, AlertTriangle, Info, X, XCircle } from 'lucide-react'
import { useUIStore, type ToastItem } from '@/stores/uiStore'
import { cn } from '@/utils'

type ToastKind = ToastItem['kind']

const KIND_ICON: Record<ToastKind, typeof CheckCircle2> = {
  success: CheckCircle2,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
}

const KIND_COLOR: Record<ToastKind, string> = {
  success: 'text-[var(--success)]',
  error: 'text-[var(--danger)]',
  warning: 'text-[var(--warning)]',
  info: 'text-[var(--accent-blue)]',
}

export function ToastViewport() {
  const toasts = useUIStore((s) => s.toasts)
  const dismiss = useUIStore((s) => s.dismissToast)

  return (
    <div
      className="fixed bottom-4 right-4 z-[130] flex flex-col gap-2 w-[min(92vw,360px)]"
      role="region"
      aria-label="通知"
    >
      <AnimatePresence>
        {toasts.map((t) => (
          <ToastCard key={t.id} toast={t} onDismiss={() => dismiss(t.id)} />
        ))}
      </AnimatePresence>
    </div>
  )
}

function ToastCard({ toast, onDismiss }: { toast: ToastItem; onDismiss: () => void }) {
  const Icon = KIND_ICON[toast.kind]
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 40, scale: 0.96 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 40, scale: 0.96 }}
      transition={{ duration: 0.18, ease: 'easeOut' }}
      className="glass-strong rounded-[14px] px-3.5 py-3 flex items-start gap-2.5 shadow-[var(--shadow-glass)]"
      role="status"
      aria-live="polite"
    >
      <Icon size={18} className={cn('mt-0.5 shrink-0', KIND_COLOR[toast.kind])} aria-hidden />
      <p className="text-sm text-[var(--text-primary)] flex-1 leading-relaxed break-words">{toast.message}</p>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="关闭通知"
        className="text-[var(--text-tertiary)] hover:text-[var(--text-primary)] transition-colors shrink-0"
      >
        <X size={16} />
      </button>
    </motion.div>
  )
}

export default ToastViewport
