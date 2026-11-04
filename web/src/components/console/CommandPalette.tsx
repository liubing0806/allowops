import { useId, useMemo, useState, type KeyboardEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { SearchIcon } from 'lucide-react'
import { api, formatLabels } from '@/api'
import { navigation } from '@/components/console/navigation'
import { StatusDot } from '@/components/console/StatusDot'
import {
  Dialog,
  DialogContent,
  DialogTitle,
} from '@/components/ui/dialog'
import { cn } from '@/lib/utils'

interface Item {
  id: string
  group: 'hosts' | 'pages' | 'commands'
  label: string
  mono?: boolean
  hint?: string
  dot?: 'success' | 'neutral'
  run: () => void
}

const HOST_LIMIT = 6

// ⌘K / Ctrl+K. Radix Dialog supplies Escape, the focus trap and focus return.
export function CommandPalette({
  open,
  onOpenChange,
  onToggleTheme,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onToggleTheme: () => void
}) {
  const { t } = useTranslation()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        aria-describedby={undefined}
        showCloseButton={false}
        className="top-24 max-w-[min(560px,calc(100%-32px))] translate-y-0 gap-0 overflow-hidden rounded-2xl p-0 shadow-[0_24px_60px_rgb(0_0_0/0.25)] sm:max-w-[560px]"
      >
        <DialogTitle className="sr-only">{t('palette.title')}</DialogTitle>
        {open && (
          <PaletteBody
            onClose={() => onOpenChange(false)}
            onToggleTheme={onToggleTheme}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

function PaletteBody({
  onClose,
  onToggleTheme,
}: {
  onClose: () => void
  onToggleTheme: () => void
}) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const listId = useId()
  const [text, setText] = useState('')
  const [active, setActive] = useState(0)
  const hosts = useQuery({
    queryKey: ['hostOptions'],
    queryFn: () => api.listHosts(),
  })
  const query = text.trim().toLowerCase()
  const go = (path: string) => () => {
    onClose()
    navigate(path)
  }
  const items = useMemo<Item[]>(() => {
    const matches = (label: string) => !query || label.toLowerCase().includes(query)
    const hostItems: Item[] = (hosts.data?.hosts ?? [])
      .filter((host) => matches(host.hostname))
      .slice(0, HOST_LIMIT)
      .map((host) => ({
        id: `host-${host.hostId}`,
        group: 'hosts',
        label: host.hostname,
        mono: true,
        hint:
          formatLabels(host.authorizationLabels) || t('host.unlabeledShort'),
        dot: host.online ? 'success' : 'neutral',
        run: go(`/hosts/${encodeURIComponent(host.hostname)}`),
      }))
    const pageItems: Item[] = navigation
      .filter((item) => matches(t(item.key)))
      .map((item) => ({
        id: `page-${item.path}`,
        group: 'pages',
        label: t(item.key),
        run: go(item.path),
      }))
    const commandItems: Item[] = [
      {
        id: 'cmd-unlabeled',
        group: 'commands' as const,
        label: t('palette.unlabeled'),
        run: go('/hosts?status=unlabeled'),
      },
      {
        id: 'cmd-outdated',
        group: 'commands' as const,
        label: t('palette.outdated'),
        run: go('/hosts?status=outdated'),
      },
      {
        id: 'cmd-theme',
        group: 'commands' as const,
        label: t('palette.toggleTheme'),
        run: () => {
          onClose()
          onToggleTheme()
        },
      },
    ].filter((item) => matches(item.label))
    return [...hostItems, ...pageItems, ...commandItems]
    // go closes over stable navigate/onClose.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hosts.data, query, t])
  const current = Math.min(active, Math.max(items.length - 1, 0))
  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault()
      if (!items.length) return
      const step = event.key === 'ArrowDown' ? 1 : -1
      setActive((current + step + items.length) % items.length)
    } else if (event.key === 'Enter') {
      event.preventDefault()
      items[current]?.run()
    }
  }
  const groups: { key: Item['group']; label: string }[] = [
    { key: 'hosts', label: t('palette.hosts') },
    { key: 'pages', label: t('palette.pages') },
    { key: 'commands', label: t('palette.commands') },
  ]
  return (
    <>
      <label className="flex items-center gap-2.5 border-b border-border-subtle px-3.5 py-3">
        <SearchIcon aria-hidden="true" className="size-4 text-muted-foreground" />
        <span className="sr-only">{t('palette.title')}</span>
        <input
          autoFocus
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={items[current] ? `${listId}-${items[current].id}` : undefined}
          value={text}
          onChange={(event) => {
            setText(event.target.value)
            setActive(0)
          }}
          onKeyDown={onKeyDown}
          placeholder={t('palette.placeholder')}
          className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
        />
        <kbd className="rounded border px-1.5 font-mono text-[11px] text-muted-foreground">
          esc
        </kbd>
      </label>
      <div
        id={listId}
        role="listbox"
        aria-label={t('palette.title')}
        className="flex max-h-[340px] flex-col gap-px overflow-y-auto p-1.5"
      >
        {!items.length && (
          <p className="px-2 py-6 text-center text-sm text-muted-foreground">
            {t('common.empty')}
          </p>
        )}
        {groups.map((group) => {
          const entries = items.filter((item) => item.group === group.key)
          if (!entries.length) return null
          return (
            <div key={group.key} role="group" aria-label={group.label}>
              <div
                aria-hidden="true"
                className="px-2 pt-2 pb-1 text-[11px] text-muted-foreground"
              >
                {group.label}
              </div>
              {entries.map((item) => {
                const index = items.indexOf(item)
                return (
                  <button
                    key={item.id}
                    id={`${listId}-${item.id}`}
                    type="button"
                    role="option"
                    tabIndex={-1}
                    aria-selected={index === current}
                    onMouseMove={() => setActive(index)}
                    onClick={item.run}
                    className={cn(
                      'flex h-[34px] w-full items-center gap-2.5 rounded-lg px-2.5 text-left text-sm',
                      index === current && 'bg-muted',
                    )}
                  >
                    {item.dot && <StatusDot tone={item.dot} />}
                    <span className={cn('min-w-0 flex-1 truncate', item.mono && 'font-mono')}>
                      {item.label}
                    </span>
                    {item.hint && (
                      <span className="max-w-[45%] truncate font-mono text-[11px] text-muted-foreground">
                        {item.hint}
                      </span>
                    )}
                  </button>
                )
              })}
            </div>
          )
        })}
      </div>
    </>
  )
}
