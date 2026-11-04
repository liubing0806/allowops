import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { TriangleAlertIcon } from 'lucide-react'

// Host output and reported labels come from the host and are untrusted input.
export function UntrustedBanner({ children }: { children?: ReactNode }) {
  const { t } = useTranslation()
  return (
    <p
      role="note"
      className="flex items-start gap-2 rounded-lg bg-warning-soft px-3 py-2 text-sm text-warning"
    >
      <TriangleAlertIcon aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
      <span className="min-w-0">
        {children ?? t('job.untrusted')}
      </span>
    </p>
  )
}
