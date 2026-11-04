import type { ComponentProps, ReactNode } from 'react'
import { cn } from '@/lib/utils'

// Bottom-centred bar shown while rows are selected. `above` holds an expanded
// tool (for example a label diff preview) that belongs to the selection.
export function FloatingActionBar({
  label,
  summary,
  children,
  above,
}: {
  label: string
  summary: ReactNode
  children: ReactNode
  above?: ReactNode
}) {
  return (
    <div className="fixed bottom-5 left-1/2 z-20 flex w-[min(620px,calc(100%-32px))] -translate-x-1/2 flex-col gap-2">
      {above}
      <div
        role="toolbar"
        aria-label={label}
        className="flex flex-wrap items-center gap-1 rounded-xl bg-zinc-900 py-1.5 pr-1.5 pl-3.5 text-zinc-50 shadow-[0_16px_44px_rgb(0_0_0/0.28)] ring-1 ring-white/10 dark:bg-zinc-800"
      >
        <span className="font-medium">{summary}</span>
        <span className="flex-1" />
        {children}
      </div>
    </div>
  )
}

export function BarButton({
  primary = false,
  className,
  ...props
}: ComponentProps<'button'> & { primary?: boolean }) {
  return (
    <button
      type="button"
      className={cn(
        'flex h-8 items-center gap-1.5 rounded-lg px-3 text-sm text-zinc-200 hover:bg-zinc-700 hover:text-white disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-3.5',
        primary && 'bg-zinc-700 text-zinc-50 hover:bg-zinc-600',
        className,
      )}
      {...props}
    />
  )
}
