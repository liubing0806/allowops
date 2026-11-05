import { cn } from '@/lib/utils'

// Authorization labels use a filled pill; reported labels are untrusted input
// and use a dashed outline with the reported. prefix (README §3.4).
export function LabelPill({
  name,
  value,
  reported = false,
  tone = 'plain',
  className,
}: {
  name: string
  value?: string
  reported?: boolean
  tone?: 'plain' | 'accent'
  className?: string
}) {
  const text = `${reported ? 'reported.' : ''}${name}${value === undefined ? '' : `=${value}`}`
  return (
    <span
      title={text}
      className={cn(
        'inline-block max-w-full truncate rounded-full px-[7px] py-px align-middle font-mono text-[11px] leading-[18px]',
        reported
          ? 'border border-dashed border-border text-foreground-2'
          : tone === 'accent'
            ? 'bg-accent text-accent-foreground'
            : 'bg-muted text-foreground-2 shadow-[inset_0_0_0_1px_var(--border-subtle)]',
        className,
      )}
    >
      {text}
    </span>
  )
}

export function LabelPills({
  labels,
  reported = false,
}: {
  labels: Record<string, string>
  reported?: boolean
}) {
  return (
    <span className="flex min-w-0 flex-wrap gap-1">
      {Object.entries(labels).map(([name, value]) => (
        <LabelPill key={name} name={name} value={value} reported={reported} />
      ))}
    </span>
  )
}
