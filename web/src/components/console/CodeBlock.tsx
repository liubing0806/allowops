import { useTranslation } from 'react-i18next'
import { CheckIcon, CopyIcon } from 'lucide-react'
import { useCopy } from '@/components/console/useCopy'
import { cn } from '@/lib/utils'

export function CodeBlock({
  code,
  label,
  className,
}: {
  code: string
  // Names the block in the copy button's accessible name.
  label?: string
  className?: string
}) {
  const { t } = useTranslation()
  const { copied, copy } = useCopy()
  const name = label ? t('common.copyNamed', { name: label }) : t('common.copy')
  return (
    <div
      className={cn(
        'relative min-w-0 rounded-lg bg-zinc-950 text-zinc-100 ring-1 ring-zinc-800 dark:bg-black',
        className,
      )}
    >
      <pre className="overflow-x-auto p-3 pr-11 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap">
        <code>{code}</code>
      </pre>
      <button
        type="button"
        onClick={() => void copy(code)}
        aria-label={name}
        title={name}
        className="absolute top-1.5 right-1.5 grid size-7 place-items-center rounded-md text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
      >
        {copied ? (
          <CheckIcon aria-hidden="true" className="size-3.5" />
        ) : (
          <CopyIcon aria-hidden="true" className="size-3.5" />
        )}
      </button>
      <span aria-live="polite" className="sr-only">
        {copied ? t('common.copied') : ''}
      </span>
    </div>
  )
}
