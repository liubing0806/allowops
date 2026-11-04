import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { StatusDot } from '@/components/console/StatusDot'
import type { Tone } from '@/components/console/tone'

export interface Segment<T extends string> {
  value: T
  label: ReactNode
  count?: number | string
  tone?: Tone
}

export function SegmentedControl<T extends string>({
  label,
  value,
  options,
  onChange,
  className,
}: {
  label: string
  value: T
  options: Segment<T>[]
  onChange: (value: T) => void
  className?: string
}) {
  return (
    <div
      role="group"
      aria-label={label}
      className={cn(
        'inline-flex max-w-full flex-wrap gap-0.5 rounded-[10px] bg-muted p-[3px]',
        className,
      )}
    >
      {options.map((option) => {
        const active = option.value === value
        return (
          <button
            key={option.value}
            type="button"
            aria-pressed={active}
            onClick={() => onChange(option.value)}
            className={cn(
              'flex h-7 items-center gap-1.5 rounded-[7px] px-2.5 text-sm font-medium text-foreground-2 hover:text-foreground',
              active &&
                'bg-card text-foreground shadow-[0_1px_2px_rgb(0_0_0/0.10),0_0_0_0.5px_rgb(0_0_0/0.06)]',
            )}
          >
            {option.tone && <StatusDot tone={option.tone} size={6} />}
            {option.label}
            {option.count !== undefined && (
              <span className="font-mono text-[11px] text-muted-foreground">
                {option.count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}
