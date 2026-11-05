import { useEffect, useId, useRef, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { XIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

// Floating right panel without an overlay: the list behind it stays usable.
// Escape closes it unless a modal layer (Radix dialog) already handled the key,
// and focus returns to the element that was focused when it opened.
export function SidePanel({
  title,
  subtitle,
  onClose,
  children,
  className,
}: {
  title: ReactNode
  subtitle?: ReactNode
  onClose: () => void
  children: ReactNode
  className?: string
}) {
  const { t } = useTranslation()
  const id = useId()
  const panel = useRef<HTMLElement>(null)
  const close = useRef(onClose)
  useEffect(() => {
    close.current = onClose
  })
  useEffect(() => {
    const opener =
      document.activeElement instanceof HTMLElement &&
      document.activeElement !== document.body
        ? document.activeElement
        : null
    panel.current?.focus()
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !event.defaultPrevented) close.current()
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      if (opener?.isConnected) opener.focus()
    }
  }, [])
  return (
    <aside
      ref={panel}
      tabIndex={-1}
      aria-labelledby={id}
      className={cn(
        'fixed top-16 right-3 bottom-3 z-30 flex w-[calc(100%-24px)] flex-col overflow-hidden rounded-2xl border bg-popover text-popover-foreground shadow-[0_24px_60px_rgb(20_22_30/0.20),0_2px_8px_rgb(20_22_30/0.06)] outline-none backdrop-blur sm:w-[420px]',
        className,
      )}
    >
      <header className="flex items-start gap-2.5 border-b border-border-subtle py-3 pr-3 pl-4">
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <h2
            id={id}
            className="font-mono text-[15px] font-medium break-all"
          >
            {title}
          </h2>
          {subtitle && (
            <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
              {subtitle}
            </div>
          )}
        </div>
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={onClose}
          aria-label={t('common.close')}
        >
          <XIcon />
        </Button>
      </header>
      <div className="flex min-h-0 flex-1 flex-col gap-[18px] overflow-y-auto px-4 pt-3.5 pb-[18px]">
        {children}
      </div>
    </aside>
  )
}

export function PanelSection({
  title,
  children,
  className,
}: {
  title?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={cn('flex min-w-0 flex-col gap-2', className)}>
      {title && (
        <h3 className="text-xs font-medium text-muted-foreground">{title}</h3>
      )}
      {children}
    </section>
  )
}
