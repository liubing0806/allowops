import { cn } from '@/lib/utils'
import type { Tone } from '@/components/console/tone'

const dotTone: Record<Tone, string> = {
  success: 'bg-dot-success',
  warning: 'bg-dot-warning',
  info: 'bg-dot-info',
  destructive: 'bg-dot-destructive',
  neutral: 'bg-dot-neutral',
}

// The dot is decorative; callers always render the state as text next to it.
export function StatusDot({
  tone,
  pulse = false,
  size = 7,
  className,
}: {
  tone: Tone
  pulse?: boolean
  size?: 6 | 7
  className?: string
}) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        'inline-block shrink-0 rounded-full',
        size === 6 ? 'size-1.5' : 'size-[7px]',
        dotTone[tone],
        pulse && 'ao-pulse',
        className,
      )}
    />
  )
}
