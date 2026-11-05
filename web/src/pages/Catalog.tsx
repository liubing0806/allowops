import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { BookOpenIcon, CopyIcon, SearchIcon } from 'lucide-react'
import {
  api,
  fromBase64,
  type ActionDefinition,
  type ActionSummary,
  type CatalogRef,
  type CatalogVersion,
} from '@/api'
import {
  DataTable,
  PageTitle,
  QueryState,
  Time,
} from '@/components/console/common'
import { SegmentedControl } from '@/components/console/SegmentedControl'
import { PanelSection, SidePanel } from '@/components/console/SidePanel'
import { softTone, type Tone } from '@/components/console/tone'
import { useCopy } from '@/components/console/useCopy'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { relativeTime } from '@/lib/time'
import { cn } from '@/lib/utils'

const WARNING_HOURS = 14 * 24
const EXAMPLE_HOSTS = 3

const risks = ['all', 'read', 'write', 'dangerous'] as const
type RiskFilter = (typeof risks)[number]

const riskTone: Record<string, Tone> = {
  read: 'success',
  write: 'warning',
  dangerous: 'destructive',
}

// The catalog JSON carries output filters; the console model leaves them out.
type Definition = ActionDefinition & { filters?: string[] }

const sameRef = (a: CatalogRef, b: CatalogRef) =>
  a.catalogId === b.catalogId && a.version === b.version

function formatBytes(value: string) {
  const bytes = Number(value)
  if (!Number.isFinite(bytes)) return value
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`
}

function useNow() {
  const [now, setNow] = useState(Date.now)
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 60000)
    return () => window.clearInterval(timer)
  }, [])
  return now
}

function RiskPill({ risk }: { risk: string }) {
  const { t } = useTranslation()
  return (
    <span
      className={cn(
        'inline-flex rounded-full px-2 py-px text-xs whitespace-nowrap',
        softTone[riskTone[risk] ?? 'neutral'],
      )}
    >
      {t(`risk.${risk}`, { defaultValue: risk })}
    </span>
  )
}

export default function Catalog() {
  const { t } = useTranslation()
  const catalogs = useQuery({
    queryKey: ['catalogs'],
    queryFn: () => api.listCatalogs(),
  })
  const current = catalogs.data?.catalogs.find((c) => c.current)
  const [version, setVersion] = useState<CatalogRef | null>(null)
  const selected =
    catalogs.data?.catalogs.find((c) => version && sameRef(c.catalog, version)) ??
    current
  const actions = useQuery({
    queryKey: ['actions', selected?.catalog],
    queryFn: () => api.listActions({ catalog: selected!.catalog }),
    enabled: !!selected,
  })
  const [view, setView] = useState<'actions' | 'history'>('actions')
  const [risk, setRisk] = useState<RiskFilter>('all')
  const [search, setSearch] = useState('')
  const [action, setAction] = useState<string | null>(null)
  const publish = useCopy('catalog.publishCopied')
  const publishCommand = `allowops catalog publish -f catalog.dsse.json --gateway ${window.location.origin} --token-env ALLOWOPS_PUBLISHER_TOKEN`

  const all = actions.data?.actions ?? []
  const needle = search.trim().toLowerCase()
  const shown = all.filter(
    (a) =>
      (risk === 'all' || a.risk === risk) &&
      (!needle ||
        `${a.name} ${t(a.description)}`.toLowerCase().includes(needle)),
  )

  return (
    <div className="flex flex-col gap-3.5">
      <PageTitle
        title={t('nav.catalog')}
        description={t('catalog.description')}
        action={
          <Button
            variant="outline"
            onClick={() => void publish.copy(publishCommand)}
          >
            <CopyIcon />
            {t('catalog.copyPublish')}
          </Button>
        }
      />
      <QueryState pending={catalogs.isPending} error={catalogs.error} />
      {selected && (
        <>
          <div className="grid grid-cols-1 gap-3.5 lg:grid-cols-2">
            <CatalogCard
              catalog={selected}
              onReset={
                selected.current ? undefined : () => setVersion(null)
              }
            />
            <Distribution
              catalogId={selected.catalog.catalogId}
              currentVersion={
                catalogs.data?.catalogs.find(
                  (c) =>
                    c.current &&
                    c.catalog.catalogId === selected.catalog.catalogId,
                )?.catalog.version
              }
            />
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            <SegmentedControl
              label={t('catalog.view')}
              value={view}
              onChange={setView}
              options={[
                { value: 'actions', label: t('catalog.actions') },
                { value: 'history', label: t('common.history') },
              ]}
            />
            {view === 'actions' && (
              <>
                <SegmentedControl
                  label={t('catalog.riskFilter')}
                  value={risk}
                  onChange={setRisk}
                  options={risks.map((value) => ({
                    value,
                    label:
                      value === 'all' ? t('host.all') : t(`risk.${value}`),
                    tone: value === 'all' ? undefined : riskTone[value],
                    count:
                      value === 'all'
                        ? all.length
                        : all.filter((a) => a.risk === value).length,
                  }))}
                />
                <span className="hidden flex-1 md:block" />
                <label className="relative block w-full md:w-64">
                  <span className="sr-only">{t('catalog.search')}</span>
                  <SearchIcon
                    aria-hidden="true"
                    className="absolute top-2 left-2.5 size-3.5 text-muted-foreground"
                  />
                  <Input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder={t('catalog.searchPlaceholder')}
                    className="pl-8"
                  />
                </label>
              </>
            )}
          </div>
          {view === 'actions' ? (
            <section
              aria-label={t('catalog.actions')}
              className="min-w-0 overflow-hidden rounded-xl border bg-card"
            >
              <div className="px-4">
                <QueryState pending={actions.isPending} error={actions.error} />
              </div>
              {actions.data && (
                <>
                  <div className="overflow-x-auto px-2">
                    <DataTable<ActionSummary>
                      data={shown}
                      pageSize={50}
                      rowClassName={(row) =>
                        row.name === action
                          ? 'bg-selection shadow-[inset_2px_0_0_var(--primary)]'
                          : undefined
                      }
                      columns={[
                        {
                          accessorKey: 'name',
                          header: 'Action',
                          cell: ({ row }) => (
                            <button
                              type="button"
                              className="text-left font-mono text-sm font-medium hover:text-primary"
                              onClick={() => setAction(row.original.name)}
                            >
                              {row.original.name}
                            </button>
                          ),
                        },
                        {
                          accessorKey: 'description',
                          header: t('common.description'),
                          cell: ({ row }) => (
                            <span className="text-foreground-2">
                              {t(row.original.description)}
                            </span>
                          ),
                        },
                        {
                          accessorKey: 'risk',
                          header: t('catalog.risk'),
                          cell: ({ row }) => <RiskPill risk={row.original.risk} />,
                        },
                        {
                          id: 'mode',
                          header: t('catalog.mode'),
                          cell: ({ row }) => (
                            <span className="font-mono text-xs text-foreground-2">
                              {row.original.builtin
                                ? `builtin: ${row.original.builtin}`
                                : row.original.executionMode}
                            </span>
                          ),
                        },
                      ]}
                    />
                  </div>
                  <p className="px-4 py-2.5 text-xs text-muted-foreground">
                    {t('catalog.shown', {
                      shown: shown.length,
                      total: all.length,
                    })}
                  </p>
                </>
              )}
            </section>
          ) : (
            <History
              catalogs={catalogs.data?.catalogs ?? []}
              selected={selected.catalog}
              onSelect={(ref) => {
                setVersion(ref)
                setAction(null)
              }}
            />
          )}
        </>
      )}
      {action && selected && (
        <ActionPanel
          key={action}
          action={action}
          catalog={selected.catalog}
          onClose={() => setAction(null)}
        />
      )}
    </div>
  )
}

function CatalogCard({
  catalog,
  onReset,
}: {
  catalog: CatalogVersion
  onReset?: () => void
}) {
  const { t, i18n } = useTranslation()
  const now = useNow()
  const expires = Date.parse(catalog.expiresAt)
  const left = expires - now
  const hours = Math.max(0, Math.floor(left / 3600000))
  const span = expires - Date.parse(catalog.createdAt)
  const fraction = span > 0 ? Math.min(1, Math.max(0, left / span)) : 0
  const warning = hours <= WARNING_HOURS
  const label = catalog.current
    ? t('catalog.current')
    : t('catalog.olderVersion')
  return (
    <section
      aria-label={label}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card px-[18px] py-4"
    >
      <div className="flex flex-wrap items-center gap-2.5">
        <span
          aria-hidden="true"
          className="grid size-8 place-items-center rounded-[9px] bg-accent text-accent-foreground"
        >
          <BookOpenIcon className="size-4" />
        </span>
        <span className="flex min-w-0 flex-col leading-tight">
          <span className="font-mono text-base font-medium break-all">
            {catalog.catalog.catalogId}{' '}
            <span className="text-muted-foreground">
              {catalog.catalog.version}
            </span>
          </span>
          <span className="text-xs text-muted-foreground">
            {label} ·{' '}
            {t('catalog.summary', {
              date: new Intl.DateTimeFormat(i18n.language, {
                dateStyle: 'medium',
              }).format(new Date(catalog.publishedAt || catalog.createdAt)),
              count: catalog.actionCount,
            })}
          </span>
        </span>
        <span className="flex-1" />
        {onReset && (
          <Button variant="outline" size="sm" onClick={onReset}>
            {t('catalog.backToCurrent')}
          </Button>
        )}
      </div>
      <div className="flex flex-col gap-1.5">
        <span className="flex justify-between gap-3 text-xs">
          <span className="text-muted-foreground">{t('catalog.countdown')}</span>
          <span
            className={cn(
              'font-mono font-medium',
              warning ? 'text-warning' : 'text-foreground',
            )}
          >
            {left <= 0
              ? t('common.expired')
              : t('catalog.remaining', {
                  days: Math.floor(hours / 24),
                  hours: hours % 24,
                })}
          </span>
        </span>
        <span
          aria-hidden="true"
          className="flex h-1.5 overflow-hidden rounded-full bg-muted"
        >
          <span
            className={cn(
              'rounded-full',
              warning ? 'bg-dot-warning' : 'bg-primary',
            )}
            style={{ width: `${Math.round(fraction * 100)}%` }}
          />
        </span>
        <span className="text-xs text-muted-foreground">
          <Time value={catalog.expiresAt} />
        </span>
        {warning && (
          <p role="note" className="text-xs text-warning">
            {t('catalog.expiryWarning')}
          </p>
        )}
      </div>
      <dl className="grid grid-cols-3 gap-2 text-xs">
        <div className="min-w-0">
          <dt className="text-muted-foreground">{t('catalog.schema')}</dt>
          <dd className="font-mono">{catalog.schemaVersion}</dd>
        </div>
        <div className="min-w-0">
          <dt className="text-muted-foreground">{t('catalog.commit')}</dt>
          <dd
            title={catalog.gitCommit || undefined}
            className="truncate font-mono"
          >
            {catalog.gitCommit || t('common.none')}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-muted-foreground">{t('catalog.envelopeSize')}</dt>
          <dd className="font-mono">{formatBytes(catalog.envelopeSizeBytes)}</dd>
        </div>
      </dl>
      {/* ListCatalogs returns no signature status, so none is shown. */}
    </section>
  )
}

function Distribution({
  catalogId,
  currentVersion,
}: {
  catalogId: string
  currentVersion?: string
}) {
  const { t } = useTranslation()
  const distribution = useQuery({
    queryKey: ['catalogDistribution', catalogId],
    queryFn: () => api.getCatalogDistribution({ catalogId }),
  })
  const hosts = useQuery({
    queryKey: ['hostOptions'],
    queryFn: () => api.listHosts(),
  })
  const examples = (match: (refs: CatalogRef[]) => boolean) =>
    (hosts.data?.hosts ?? [])
      .filter((host) => match(host.loadedCatalogs))
      .slice(0, EXAMPLE_HOSTS)
      .map((host) => host.hostname)
  const rows = distribution.data
    ? [
        ...distribution.data.versions.map((entry) => ({
          key: entry.catalog.version,
          label: entry.catalog.version,
          count: Number(entry.hostCount),
          // Hosts on the current version are expected; any other version is behind.
          color:
            entry.catalog.version === currentVersion
              ? 'bg-primary'
              : 'bg-dot-warning',
          hosts: examples((refs) =>
            refs.some((ref) => sameRef(ref, entry.catalog)),
          ),
        })),
        {
          key: 'none',
          label: t('catalog.notLoaded'),
          count: Number(distribution.data.notLoadedHostCount),
          color: 'bg-dot-neutral',
          hosts: examples(
            (refs) => !refs.some((ref) => ref.catalogId === catalogId),
          ),
        },
      ]
    : []
  const total = rows.reduce((sum, row) => sum + row.count, 0)
  return (
    <section
      aria-labelledby="catalog-distribution-title"
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card px-[18px] py-4"
    >
      <h2 id="catalog-distribution-title" className="text-sm font-semibold">
        {t('catalog.distribution')}
      </h2>
      <QueryState pending={distribution.isPending} error={distribution.error} />
      {distribution.data && (
        <>
          {total > 0 && (
            <span aria-hidden="true" className="flex h-2.5 gap-0.5 overflow-hidden rounded-full">
              {rows
                .filter((row) => row.count > 0)
                .map((row) => (
                  <span
                    key={row.key}
                    className={row.color}
                    style={{ width: `${(row.count / total) * 100}%` }}
                  />
                ))}
            </span>
          )}
          <ul className="flex flex-col gap-1.5">
            {rows.map((row) => (
              <li key={row.key} className="flex items-center gap-2">
                <span
                  aria-hidden="true"
                  className={cn('size-2 shrink-0 rounded-[2px]', row.color)}
                />
                <span className="min-w-16 shrink-0 font-mono text-sm">
                  {row.label}
                </span>
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground">
                  {row.hosts.join(', ')}
                </span>
                <span className="font-mono text-sm">{row.count}</span>
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted-foreground">{t('host.catalogHint')}</p>
        </>
      )}
    </section>
  )
}

function History({
  catalogs,
  selected,
  onSelect,
}: {
  catalogs: CatalogVersion[]
  selected: CatalogRef
  onSelect: (ref: CatalogRef) => void
}) {
  const { t, i18n } = useTranslation()
  const now = useNow()
  const date = (value: string) =>
    new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium' }).format(
      new Date(value),
    )
  return (
    <section
      aria-label={t('common.history')}
      className="min-w-0 overflow-hidden rounded-xl border bg-card"
    >
      <ul>
        {catalogs.map((entry) => {
          const expired = Date.parse(entry.expiresAt) <= now
          const active = sameRef(entry.catalog, selected)
          return (
            <li
              key={`${entry.catalog.catalogId}/${entry.catalog.version}`}
              className="border-b border-border-subtle last:border-b-0"
            >
              <button
                type="button"
                aria-pressed={active}
                onClick={() => onSelect(entry.catalog)}
                className={cn(
                  'flex w-full flex-wrap items-center gap-3.5 px-4 py-3.5 text-left hover:bg-muted/60',
                  active && 'bg-selection',
                )}
              >
                <span
                  aria-hidden="true"
                  className={cn(
                    'size-2.5 shrink-0 rounded-full border-2',
                    entry.current ? 'border-primary bg-primary' : 'border-border',
                  )}
                />
                <span className="min-w-32 font-mono font-medium">
                  {entry.catalog.catalogId} {entry.catalog.version}
                </span>
                {entry.current && (
                  <span className="rounded-full bg-accent px-1.5 text-[11px] text-accent-foreground">
                    {t('catalog.currentTag')}
                  </span>
                )}
                <span className="min-w-0 flex-[1_1_200px] text-xs text-foreground-2">
                  {t('catalog.summary', {
                    date: date(entry.publishedAt || entry.createdAt),
                    count: entry.actionCount,
                  })}{' '}
                  · {t('catalog.commit')}{' '}
                  <span className="font-mono">{entry.gitCommit || t('common.none')}</span>
                </span>
                <span
                  className={cn(
                    'text-xs',
                    !expired &&
                      Date.parse(entry.expiresAt) - now <= WARNING_HOURS * 3600000
                      ? 'text-warning'
                      : 'text-muted-foreground',
                  )}
                >
                  {expired
                    ? t('catalog.expiredOn', { date: date(entry.expiresAt) })
                    : t('catalog.expiresIn', {
                        date: date(entry.expiresAt),
                        relative: relativeTime(
                          entry.expiresAt,
                          i18n.language,
                          t('common.justNow'),
                          now,
                        ),
                      })}
                </span>
              </button>
            </li>
          )
        })}
      </ul>
    </section>
  )
}

function ActionPanel({
  action,
  catalog,
  onClose,
}: {
  action: string
  catalog: CatalogRef
  onClose: () => void
}) {
  const { t } = useTranslation()
  const query = useQuery({
    queryKey: ['action', catalog, action],
    queryFn: () => api.getAction({ catalog, action }),
  })
  const definition = query.data
    ? (JSON.parse(fromBase64(query.data.definitionJson)) as Definition)
    : null
  const summary = query.data?.action
  const params = Object.entries(definition?.params ?? {})
  const commandTitle = definition?.exec
    ? t('catalog.commandFixed')
    : definition?.builtin
      ? t('catalog.builtin')
      : t('catalog.command')

  return (
    <SidePanel
      title={action}
      onClose={onClose}
      subtitle={
        summary && (
          <>
            <RiskPill risk={summary.risk} />
            <span>{t(summary.description)}</span>
          </>
        )
      }
    >
      <QueryState pending={query.isPending} error={query.error} />
      {definition && summary && (
        <>
          <PanelSection title={t('catalog.params')}>
            {params.length ? (
              <ul className="flex flex-col gap-1.5">
                {params.map(([name, { type, description, ...constraints }]) => (
                  <li
                    key={name}
                    className="flex flex-col gap-0.5 rounded-lg border bg-card px-2.5 py-2"
                  >
                    <span className="flex items-center gap-2">
                      <span className="font-mono font-medium">{name}</span>
                      <span className="rounded bg-muted px-1.5 font-mono text-[11px] text-foreground-2">
                        {type}
                      </span>
                    </span>
                    {description && (
                      <span className="text-xs text-foreground-2">
                        {t(description)}
                      </span>
                    )}
                    {Object.keys(constraints).length > 0 && (
                      <code className="font-mono text-xs break-all text-muted-foreground">
                        {JSON.stringify(constraints)}
                      </code>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-muted-foreground">{t('catalog.noParams')}</p>
            )}
          </PanelSection>
          <PanelSection title={commandTitle}>
            <pre className="overflow-x-auto rounded-lg bg-zinc-950 p-3 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap text-zinc-100 ring-1 ring-zinc-800 dark:bg-black">
              {definition.exec
                ? definition.exec
                    .map((arg) =>
                      typeof arg === 'string' ? arg : JSON.stringify(arg),
                    )
                    .join(' ')
                : JSON.stringify(
                    {
                      steps: definition.steps,
                      on_error: definition.on_error,
                      script: definition.script,
                      args: definition.args,
                      builtin: definition.builtin,
                      builtin_config: definition.builtin_config,
                      exec_fallbacks: definition.exec_fallbacks,
                      allow_interpreter: definition.allow_interpreter,
                    },
                    null,
                    2,
                  )}
            </pre>
          </PanelSection>
          <dl className="grid grid-cols-[90px_minmax(0,1fr)] gap-x-2.5 gap-y-2 text-xs">
            <dt className="text-muted-foreground">{t('catalog.runAs')}</dt>
            <dd className="min-w-0 font-mono break-words">
              {definition.run_as ?? 'allowops'}
            </dd>
            <dt className="text-muted-foreground">{t('catalog.timeout')}</dt>
            <dd className="min-w-0 font-mono break-words">{definition.timeout}</dd>
            <dt className="text-muted-foreground">{t('catalog.maxOutput')}</dt>
            <dd className="min-w-0 font-mono break-words">
              {typeof definition.max_output === 'number'
                ? `${definition.max_output} B`
                : definition.max_output}
            </dd>
            <dt className="text-muted-foreground">{t('catalog.redact')}</dt>
            <dd className="min-w-0 font-mono break-words">
              {definition.redact
                ? (definition.redact.builtin?.join(', ') ??
                  JSON.stringify(definition.redact))
                : t('catalog.defaultRedact')}
              {definition.redact?.custom && (
                <pre className="mt-2 overflow-x-auto rounded-lg bg-muted p-3 font-mono text-xs break-all whitespace-pre-wrap">
                  {JSON.stringify(definition.redact.custom, null, 2)}
                </pre>
              )}
            </dd>
            <dt className="text-muted-foreground">{t('catalog.filters')}</dt>
            <dd className="min-w-0 font-mono break-words">
              {definition.filters?.length
                ? definition.filters.join(', ')
                : t('common.none')}
            </dd>
            <dt className="text-muted-foreground">{t('catalog.idempotent')}</dt>
            <dd className="min-w-0">
              {t(summary.idempotent ? 'policy.yes' : 'policy.no')}
            </dd>
          </dl>
          {/* B5: "who can call this action" goes here once the gateway returns it. */}
        </>
      )}
    </SidePanel>
  )
}
