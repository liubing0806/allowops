import {
  useCallback,
  useContext,
  useEffect,
  useId,
  useState,
  type ReactNode,
} from 'react'
import { useTranslation } from 'react-i18next'
import { XIcon } from 'lucide-react'
import {
  NotificationContext,
  NotificationDisplayContext,
  type Notice,
} from '@/lib/notification-context'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

export function NotificationProvider({ children }: { children: ReactNode }) {
  const [notice, setNotice] = useState<Notice | null>(null)
  const [dialogs, setDialogs] = useState<string[]>([])
  const registerDialog = useCallback((id: string) => {
    setNotice(null)
    setDialogs((current) => [...current, id])
    return () => setDialogs((current) => current.filter((dialog) => dialog !== id))
  }, [])
  const dismiss = () => setNotice(null)
  return (
    <NotificationContext.Provider value={setNotice}>
      <NotificationDisplayContext.Provider
        value={{ notice, dismiss, dialogId: dialogs.at(-1), registerDialog }}
      >
        {children}
        {!dialogs.length && notice && (
          <Notification notice={notice} onClose={dismiss} />
        )}
      </NotificationDisplayContext.Provider>
    </NotificationContext.Provider>
  )
}

// Render inside the active Radix content's DOM and React tree so its aria-hidden,
// focus scope and outside-pointer handling all include the notification.
export function DialogNotification() {
  const display = useContext(NotificationDisplayContext)
  const id = useId()
  const registerDialog = display?.registerDialog
  useEffect(() => registerDialog?.(id), [id, registerDialog])
  if (!display || display.dialogId !== id || !display.notice) return null
  return <Notification notice={display.notice} onClose={display.dismiss} modal />
}

function Notification({
  notice,
  onClose,
  modal = false,
}: {
  notice: Notice
  onClose: () => void
  modal?: boolean
}) {
  const { t } = useTranslation()
  return (
    <div
      role={notice.error ? 'alert' : 'status'}
      className={cn(
        'flex min-w-0 items-center gap-2 rounded-xl border bg-card px-3 py-2 text-sm shadow-lg',
        modal && 'sticky top-0 z-10',
        !modal &&
          'fixed right-4 bottom-4 z-50 max-w-[min(420px,calc(100vw-2rem))]',
        notice.error
          ? 'border-destructive/30 text-destructive'
          : 'border-border text-foreground',
      )}
    >
      <span className="min-w-0 flex-1">{t(notice.key, notice.values)}</span>
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        onClick={onClose}
        aria-label={t('common.close')}
      >
        <XIcon />
      </Button>
    </div>
  )
}
