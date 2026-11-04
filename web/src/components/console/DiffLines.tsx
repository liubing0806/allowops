import { useTranslation } from 'react-i18next'
import type { DiffLine } from '@/lib/label-diff'
import { cn } from '@/lib/utils'

export function DiffLines({ lines }: { lines: DiffLine[] }) {
  const { t } = useTranslation()
  if (!lines.length)
    return (
      <div className="px-1.5 font-mono text-xs text-muted-foreground">
        {t('host.diffNone')}
      </div>
    )
  return (
    <ul className="flex flex-col gap-px font-mono text-xs">
      {lines.map((line, index) => (
        <li
          key={index}
          className={cn(
            'rounded px-1.5',
            line.kind === 'add'
              ? 'bg-success-soft text-success'
              : 'bg-destructive-soft text-destructive',
          )}
        >
          <span aria-hidden="true">{line.kind === 'add' ? '+ ' : '- '}</span>
          <span className="sr-only">
            {t(line.kind === 'add' ? 'host.diffAdd' : 'host.diffRemove')}
          </span>
          {line.text}
        </li>
      ))}
    </ul>
  )
}
