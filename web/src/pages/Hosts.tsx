import { useEffect, useMemo, useRef, useState } from 'react'
import { useForm, useWatch } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQuery } from '@tanstack/react-query'
import {
  Link,
  useLocation,
  useNavigate,
  useParams,
  useSearchParams,
} from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  ExternalLinkIcon,
  PlusIcon,
  SearchIcon,
  TagsIcon,
  XIcon,
} from 'lucide-react'
import {
  api,
  formatLabels,
  labelsRepresentable,
  parseLabels,
  parseSelector,
  toBase64,
  type CatalogRef,
  type CatalogVersion,
  type Host,
  type HostImportRow,
  type LabelChanges,
} from '@/api'
import {
  ConfirmDialog,
  DataTable,
  Field,
  MonoId,
  PageTitle,
  Panel,
  QueryState,
  Time,
} from '@/components/console/common'
import { DiffLines } from '@/components/console/DiffLines'
import {
  BarButton,
  FloatingActionBar,
} from '@/components/console/FloatingActionBar'
import { LabelPill, LabelPills } from '@/components/console/LabelPill'
import { SegmentedControl } from '@/components/console/SegmentedControl'
import { PanelSection, SidePanel } from '@/components/console/SidePanel'
import { StatusDot } from '@/components/console/StatusDot'
import { useCopy } from '@/components/console/useCopy'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import {
  commaList,
  labelsText,
  requiredText,
  selectorText,
} from '@/lib/forms'
import { useHostsFilterStore } from '@/lib/hosts-filter-store'
import { labelDiff, labelsDelta } from '@/lib/label-diff'
import { useCommand, useNotify } from '@/lib/notifications'
import { relativeTime } from '@/lib/time'
import { cn } from '@/lib/utils'
import { compareVersions, newestVersion } from '@/lib/versions'

const labelSchema = z.object({ labels: labelsText, remove: z.string() })
const bulkSchema = labelSchema.extend({
  selector: requiredText.pipe(selectorText),
})
// Selection mode targets explicit hosts; the selector field stays unused.
const selectionSchema = labelSchema.extend({ selector: z.string() })
const csvSchema = z.object({ csv: requiredText })

const statuses = ['all', 'online', 'offline', 'unlabeled', 'outdated'] as const
type HostStatus = (typeof statuses)[number]

const SUGGESTION_LIMIT = 4
const PAGE_SIZE = 50

const unlabeled = (host: Host) => !Object.keys(host.authorizationLabels).length

function draftChanges(labels: string, remove: string): LabelChanges | null {
  try {
    return { set: parseLabels(labels), remove: commaList(remove) }
  } catch {
    return null
  }
}

function validSelector(text: string) {
  try {
    parseSelector(text)
    return true
  } catch {
    return false
  }
}

// Versions the console can compare against: the newest gateway version and the
// current catalog per catalog id. Either may be missing (no permission, "dev"
// builds), in which case no upgrade or staleness hint is shown.
function useReferenceVersions() {
  const instances = useQuery({
    queryKey: ['instances'],
    queryFn: () => api.listGatewayInstances(),
  })
  const catalogs = useQuery({
    queryKey: ['catalogs'],
    queryFn: () => api.listCatalogs(),
  })
  const gateway = newestVersion(
    instances.data?.instances.map((instance) => instance.version) ?? [],
  )
  const current = new Map<string, CatalogVersion>()
  for (const catalog of catalogs.data?.catalogs ?? [])
    if (catalog.current) current.set(catalog.catalog.catalogId, catalog)
  const agentBehind = (host: Host) =>
    !!gateway && (compareVersions(host.agentVersion, gateway) ?? 0) < 0
  const catalogBehind = (ref: CatalogRef) => {
    const latest = current.get(ref.catalogId)
    return latest
      ? BigInt(latest.catalog.version) > BigInt(ref.version)
        ? latest.catalog.version
        : undefined
      : undefined
  }
  const outdated = (host: Host) =>
    agentBehind(host) ||
    host.loadedCatalogs.some((ref) => catalogBehind(ref) !== undefined)
  return { gateway, agentBehind, catalogBehind, outdated }
}

export default function Hosts() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const location = useLocation()
  const { hostname: openHost } = useParams()
  const [params, setParams] = useSearchParams()
  const filterStore = useHostsFilterStore()
  const form = useForm<{ selector: string; hostname: string }>({
    defaultValues: { selector: '', hostname: '' },
  })
  const values = useWatch({ control: form.control })
  const selectorValid = validSelector(values.selector ?? '')
  useEffect(() => {
    // An unparsable selector stays in the input; the last valid one keeps filtering.
    if (selectorValid)
      filterStore.setFilter({ selector: (values.selector ?? '').trim() })
    filterStore.setFilter({ hostname: values.hostname ?? '' })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [values.selector, values.hostname, selectorValid])
  useEffect(
    () => () => {
      useHostsFilterStore.getState().reset()
    },
    [],
  )
  const status: HostStatus = statuses.includes(
    params.get('status') as HostStatus,
  )
    ? (params.get('status') as HostStatus)
    : 'all'
  const query = {
    selector: filterStore.selector,
    agentVersion: filterStore.agentVersion,
  }
  const hosts = useQuery({
    queryKey: ['hosts', query],
    queryFn: () => api.listHosts({ query }),
  })
  const options = useQuery({
    queryKey: ['hostOptions'],
    queryFn: () => api.listHosts(),
  })
  const versions = useReferenceVersions()
  const [tool, setTool] = useState<'bulk' | 'csv' | 'selection' | null>(null)
  const [selected, setSelected] = useState<Set<string>>(() => new Set())
  const needle = filterStore.hostname.trim().toLowerCase()
  const matched = useMemo(
    () =>
      (hosts.data?.hosts ?? []).filter(
        (host) => !needle || host.hostname.toLowerCase().includes(needle),
      ),
    [hosts.data, needle],
  )
  const tests: Record<HostStatus, (host: Host) => boolean> = {
    all: () => true,
    online: (host) => host.online,
    offline: (host) => !host.online,
    unlabeled,
    outdated: versions.outdated,
  }
  const rows = matched.filter(tests[status])
  const filterKey = `${filterStore.selector}\n${needle}\n${status}\n${filterStore.agentVersion}`
  const [selectionKey, setSelectionKey] = useState(filterKey)
  if (selectionKey !== filterKey) {
    // A selection only ever covers rows the user can see under the current filter.
    setSelectionKey(filterKey)
    setSelected(new Set())
    if (tool === 'selection') setTool(null)
  }
  const selectedHosts = rows.filter((host) => selected.has(host.hostId))
  const allSelected = rows.length > 0 && rows.every((host) => selected.has(host.hostId))
  const toggle = (host: Host) =>
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(host.hostId)) next.delete(host.hostId)
      else next.add(host.hostId)
      return next
    })
  const clearSelection = () => {
    setSelected(new Set())
    if (tool === 'selection') setTool(null)
  }
  const { copy } = useCopy('host.targetsCopied')
  const setStatus = (value: HostStatus) =>
    setParams(
      (current) => {
        const next = new URLSearchParams(current)
        if (value === 'all') next.delete('status')
        else next.set('status', value)
        return next
      },
      { replace: true },
    )
  const hostLink = (name: string) => ({
    pathname: `/hosts/${encodeURIComponent(name)}`,
    search: location.search,
  })
  const closePanel = () => navigate({ pathname: '/hosts', search: location.search })
  const suggestions = (hosts.data?.authorizationLabelCounts ?? [])
    .slice()
    .sort((a, b) => Number(b.count) - Number(a.count))
    .slice(0, SUGGESTION_LIMIT)
  const conditions = filterStore.selector
    ? Object.entries(parseSelector(filterStore.selector))
    : []
  const online = matched.filter((host) => host.online).length
  const counts: Record<HostStatus, number> = {
    all: matched.length,
    online,
    offline: matched.length - online,
    unlabeled: matched.filter(unlabeled).length,
    outdated: matched.filter(versions.outdated).length,
  }
  const statusOptions = [
    { value: 'all' as const, label: t('host.all'), tone: 'neutral' as const },
    { value: 'online' as const, label: t('host.online'), tone: 'success' as const },
    { value: 'offline' as const, label: t('host.offline'), tone: 'neutral' as const },
    { value: 'unlabeled' as const, label: t('host.tabUnlabeled'), tone: 'warning' as const },
    { value: 'outdated' as const, label: t('host.tabOutdated'), tone: 'warning' as const },
  ].map((option) => ({ ...option, count: counts[option.value] }))
  const agentVersions = [
    ...new Set(options.data?.hosts.map((host) => host.agentVersion)),
  ].sort((a, b) => compareVersions(b, a) ?? b.localeCompare(a))
  return (
    <div className="flex flex-col gap-3.5">
      <PageTitle
        title={t('nav.hosts')}
        description={
          hosts.data ? (
            <span className="font-mono">
              {t('host.onlineMeta', { online, total: matched.length })}
            </span>
          ) : undefined
        }
        action={
          <div className="flex flex-wrap items-center gap-1.5">
            <Button
              variant="outline"
              aria-pressed={tool === 'csv'}
              onClick={() => setTool(tool === 'csv' ? null : 'csv')}
            >
              {t('host.csv')}
            </Button>
            <Button
              variant="outline"
              aria-pressed={tool === 'bulk'}
              onClick={() => setTool(tool === 'bulk' ? null : 'bulk')}
            >
              {t('host.bulk')}
            </Button>
            <Button asChild>
              <Link to="/join-tokens" className="hover:no-underline">
                <PlusIcon />
                {t('host.register')}
              </Link>
            </Button>
          </div>
        }
      />
      <section
        aria-label={t('host.filters')}
        className="rounded-2xl border bg-card p-1 shadow-[0_1px_2px_rgb(0_0_0/0.04),0_8px_24px_-12px_rgb(20_20_40/0.12)]"
      >
        <form
          noValidate
          className="flex flex-col sm:flex-row"
          onSubmit={(event) => event.preventDefault()}
        >
          <label className="flex min-w-0 flex-1 items-center gap-2.5 px-2.5 py-1.5">
            <SearchIcon aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
            <span className="sr-only">{t('host.hostname')}</span>
            <input
              {...form.register('hostname')}
              placeholder={t('host.searchPlaceholder')}
              className="h-8 min-w-0 flex-1 bg-transparent font-mono text-sm outline-none placeholder:font-sans placeholder:text-muted-foreground"
            />
          </label>
          <div className="flex min-w-0 flex-[1.4] items-center gap-2.5 border-t border-border-subtle px-2.5 py-1.5 sm:border-t-0 sm:border-l">
            <label className="flex min-w-0 flex-1 items-center gap-2.5">
              <TagsIcon aria-hidden="true" className="size-4 shrink-0 text-primary" />
              <span className="sr-only">{t('host.selector')}</span>
              <input
                {...form.register('selector')}
                aria-invalid={!selectorValid}
                placeholder={t('host.selectorPlaceholder')}
                className="h-8 min-w-0 flex-1 bg-transparent font-mono text-sm outline-none placeholder:font-sans placeholder:text-muted-foreground"
              />
            </label>
            {(values.selector || values.hostname) && (
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                aria-label={t('host.clearFilters')}
                onClick={() => form.reset({ selector: '', hostname: '' })}
              >
                <XIcon />
              </Button>
            )}
          </div>
        </form>
        <div className="flex min-h-9 flex-wrap items-center gap-1.5 border-t border-border-subtle px-2.5 py-2 text-xs text-muted-foreground">
          {!selectorValid ? (
            <span role="alert" className="text-destructive">
              {t('error.labels')} {t('host.selectorHint')}
            </span>
          ) : conditions.length || needle ? (
            <>
              <span>{t('host.conditions')}</span>
              {needle && (
                <LabelPill name={t('host.hostnameContains', { text: needle })} tone="accent" />
              )}
              {conditions.map(([key, value]) =>
                key.startsWith('reported.') ? (
                  <LabelPill key={key} name={key.slice(9)} value={value} reported />
                ) : (
                  <LabelPill key={key} name={key} value={value} tone="accent" />
                ),
              )}
              <span className="flex-1" />
              <span className="font-mono">
                {t('host.matchCount', { count: matched.length })}
              </span>
            </>
          ) : (
            <>
              <span>{suggestions.length ? t('host.suggestions') : t('host.selectorHint')}</span>
              {suggestions.map((label) => (
                <button
                  key={`${label.key}=${label.value}`}
                  type="button"
                  onClick={() =>
                    form.setValue('selector', `${label.key}=${label.value}`)
                  }
                  className="flex h-[26px] items-center gap-1.5 rounded-full border bg-background px-2.5 font-mono text-foreground-2 hover:border-primary/60 hover:text-foreground"
                >
                  {label.key}={label.value}
                  <span className="text-muted-foreground">{label.count}</span>
                </button>
              ))}
            </>
          )}
        </div>
      </section>
      <div className="flex flex-wrap items-center justify-between gap-2.5">
        <SegmentedControl
          label={t('host.filterStatus')}
          value={status}
          onChange={setStatus}
          options={
            versions.gateway
              ? statusOptions
              : statusOptions.filter((option) => option.value !== 'outdated' || status === 'outdated')
          }
        />
        <label className="flex items-center gap-2 text-xs text-muted-foreground">
          {t('host.agentVersion')}
          <select
            value={filterStore.agentVersion}
            onChange={(event) =>
              filterStore.setFilter({ agentVersion: event.target.value })
            }
            className="h-[30px] rounded-lg border bg-card px-2 font-mono text-xs text-foreground"
          >
            <option value="">{t('host.all')}</option>
            {agentVersions.map((version) => (
              <option key={version} value={version}>
                {version === versions.gateway
                  ? t('host.versionLatest', { version })
                  : version}
              </option>
            ))}
          </select>
        </label>
      </div>
      {tool === 'bulk' && <BulkLabels mode={{ kind: 'selector' }} />}
      {tool === 'csv' && <ImportLabels />}
      <section
        aria-label={t('host.list')}
        className="overflow-hidden rounded-xl border bg-card"
      >
        <QueryState pending={hosts.isPending} error={hosts.error} />
        {hosts.data && (
          <DataTable<Host>
            data={rows}
            pageSize={PAGE_SIZE}
            rowClassName={(host) =>
              cn(
                (selected.has(host.hostId) || host.hostname === openHost) &&
                  'bg-selection hover:bg-selection',
                host.hostname === openHost && 'shadow-[inset_2px_0_0_var(--primary)]',
              )
            }
            empty={
              <span className="flex flex-col items-center gap-2">
                {t('host.noMatch')}
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    form.reset({ selector: '', hostname: '' })
                    filterStore.setFilter({ agentVersion: '' })
                    setStatus('all')
                  }}
                >
                  {t('host.clearFilters')}
                </Button>
              </span>
            }
            columns={[
              {
                id: 'select',
                header: () => (
                  <input
                    type="checkbox"
                    checked={allSelected}
                    disabled={!rows.length}
                    onChange={() =>
                      setSelected(
                        allSelected
                          ? new Set()
                          : new Set(rows.map((host) => host.hostId)),
                      )
                    }
                    aria-label={t('host.selectAll')}
                    className="size-3.5 accent-primary"
                  />
                ),
                cell: ({ row }) => (
                  <input
                    type="checkbox"
                    checked={selected.has(row.original.hostId)}
                    onChange={() => toggle(row.original)}
                    aria-label={t('host.selectHost', {
                      name: row.original.hostname,
                    })}
                    className="size-3.5 accent-primary"
                  />
                ),
              },
              {
                accessorKey: 'hostname',
                header: t('nav.hosts'),
                cell: ({ row }) => (
                  <span className="flex min-w-0 flex-col py-1">
                    <Link
                      to={hostLink(row.original.hostname)}
                      className="self-start font-mono text-sm font-medium text-foreground hover:underline"
                    >
                      {row.original.hostname}
                    </Link>
                    <span className="max-w-64 truncate font-mono text-[11px] text-muted-foreground">
                      {formatLabels(row.original.reportedLabels) ||
                        t('common.none')}
                    </span>
                  </span>
                ),
              },
              {
                id: 'status',
                header: t('common.status'),
                cell: ({ row }) => (
                  <span className="flex flex-col leading-snug">
                    <span className="flex items-center gap-[7px]">
                      <StatusDot tone={row.original.online ? 'success' : 'neutral'} />
                      {t(row.original.online ? 'host.online' : 'host.offline')}
                    </span>
                    <span className="pl-3.5 text-[11px] text-muted-foreground">
                      {row.original.lastSeen
                        ? row.original.online
                          ? t('host.heartbeat', {
                              time: relativeTime(row.original.lastSeen, i18n.language, t('common.justNow')),
                            })
                          : relativeTime(row.original.lastSeen, i18n.language, t('common.justNow'))
                        : t('common.none')}
                    </span>
                  </span>
                ),
              },
              {
                id: 'labels',
                header: t('host.labels'),
                cell: ({ row }) =>
                  unlabeled(row.original) ? (
                    <span className="flex items-center gap-1.5 text-xs text-warning">
                      <StatusDot tone="warning" size={6} />
                      {t('host.unlabeledShort')}
                    </span>
                  ) : (
                    <span className="flex max-w-80 py-1">
                      <LabelPills labels={row.original.authorizationLabels} />
                    </span>
                  ),
              },
              // B1 ("Agent can run") and B2 ("Latest job") columns go here once
              // the gateway returns that data; nothing is inferred client-side.
              {
                accessorKey: 'agentVersion',
                header: t('common.version'),
                cell: ({ row }) => {
                  const staleCatalog = row.original.loadedCatalogs.some(
                    (ref) => versions.catalogBehind(ref) !== undefined,
                  )
                  return (
                    <span className="flex flex-col leading-snug">
                      <span className="font-mono text-xs">
                        {row.original.agentVersion || t('common.none')}
                      </span>
                      {versions.agentBehind(row.original) ? (
                        <span className="text-[11px] text-warning">
                          {t('host.upgradable', { version: versions.gateway })}
                        </span>
                      ) : (
                        staleCatalog && (
                          <span className="text-[11px] text-warning">
                            {t('host.catalogBehind')}
                          </span>
                        )
                      )}
                    </span>
                  )
                },
              },
              {
                id: 'open',
                header: () => <span className="sr-only">{t('common.actions')}</span>,
                cell: ({ row }) => (
                  <Button
                    asChild
                    variant="ghost"
                    size="icon-sm"
                    className="text-foreground-2 opacity-0 group-hover/row:opacity-100 focus-visible:opacity-100 max-md:opacity-100"
                  >
                    <Link
                      to={hostLink(row.original.hostname)}
                      aria-label={t('host.openDetail', {
                        name: row.original.hostname,
                      })}
                    >
                      <ExternalLinkIcon />
                    </Link>
                  </Button>
                ),
              },
            ]}
          />
        )}
      </section>
      <p className="text-xs text-muted-foreground">{t('host.authHint')}</p>
      {selectedHosts.length > 0 && (
        <FloatingActionBar
          label={t('host.selectionActions')}
          summary={t('host.selected', { count: selectedHosts.length })}
          above={
            tool === 'selection' && (
              <BulkLabels
                mode={{ kind: 'hosts', hosts: selectedHosts }}
                onApplied={clearSelection}
                floating
              />
            )
          }
        >
          <BarButton
            primary
            aria-pressed={tool === 'selection'}
            onClick={() => setTool(tool === 'selection' ? null : 'selection')}
          >
            {t('host.setLabels')}
          </BarButton>
          <BarButton
            onClick={() =>
              void copy(
                JSON.stringify({
                  targets: { hosts: selectedHosts.map((host) => host.hostname) },
                  expected_count: selectedHosts.length,
                }),
                { count: selectedHosts.length },
              )
            }
          >
            {t('host.copyTargets')}
          </BarButton>
          <button
            type="button"
            onClick={clearSelection}
            aria-label={t('host.clearSelection')}
            className="grid size-8 place-items-center rounded-lg text-zinc-400 hover:bg-zinc-700 hover:text-zinc-50"
          >
            <XIcon aria-hidden="true" className="size-3.5" />
          </button>
        </FloatingActionBar>
      )}
      {openHost && (
        <HostPanel
          key={openHost}
          hostname={openHost}
          versions={versions}
          onClose={closePanel}
        />
      )}
    </div>
  )
}

type BulkMode = { kind: 'selector' } | { kind: 'hosts'; hosts: Host[] }

interface BulkPreview {
  hosts: Host[]
  missing: number
  selector?: string
  changes: LabelChanges
  seq: number
  // Selection the preview was built for; a different selection hides it.
  targets: string
}

// Every bulk change is previewed against freshly read hosts and applied with
// their revisions, so a host changed in between makes the gateway reject it.
function BulkLabels({
  mode,
  onApplied,
  floating = false,
}: {
  mode: BulkMode
  onApplied?: () => void
  floating?: boolean
}) {
  const { t } = useTranslation()
  const notify = useNotify()
  const form = useForm<z.infer<typeof bulkSchema>>({
    resolver: zodResolver(mode.kind === 'selector' ? bulkSchema : selectionSchema),
    defaultValues: { selector: '', labels: '', remove: '' },
  })
  const seq = useRef(0)
  const [draftPreview, setPreview] = useState<BulkPreview | null>(null)
  const targetKey =
    mode.kind === 'hosts' ? mode.hosts.map((host) => host.hostId).join(',') : ''
  const preview = draftPreview?.targets === targetKey ? draftPreview : null
  const previewing = useCommand(async (values: z.infer<typeof bulkSchema>) => {
    const my = ++seq.current
    const changes = {
      set: parseLabels(values.labels),
      remove: commaList(values.remove),
    }
    if (mode.kind === 'selector') {
      const result = await api.listHosts({ query: { selector: values.selector } })
      if (seq.current !== my) return
      setPreview({
        hosts: result.hosts,
        missing: 0,
        selector: values.selector,
        changes,
        seq: my,
        targets: targetKey,
      })
      return
    }
    const ids = new Set(mode.hosts.map((host) => host.hostId))
    const result = await api.listHosts()
    if (seq.current !== my) return
    const fresh = result.hosts.filter((host) => ids.has(host.hostId))
    setPreview({
      hosts: fresh,
      missing: ids.size - fresh.length,
      changes,
      seq: my,
      targets: targetKey,
    })
  })
  const applying = useCommand(async () => {
    if (!preview) return
    if (preview.seq !== seq.current) {
      setPreview(null)
      return
    }
    const result = await api.setHostLabels({
      targets: preview.selector
        ? { selector: preview.selector }
        : { hosts: { names: preview.hosts.map((host) => host.hostname) } },
      expectedCount: String(preview.hosts.length),
      changes: preview.changes,
      expectedRevisions: preview.hosts.map((h) => ({
        hostId: h.hostId,
        revision: h.revision,
      })),
    })
    setPreview(null)
    notify({ key: 'host.bulkSaved', values: { count: result.updatedCount } })
    onApplied?.()
  })
  const hasChanges =
    !!preview &&
    (Object.keys(preview.changes.set).length > 0 ||
      preview.changes.remove.length > 0)
  const body = (
    <>
      <p className="text-xs text-muted-foreground">{t('host.bulkHint')}</p>
      <form
        noValidate
        className={cn(
          'grid grid-cols-1 gap-3',
          mode.kind === 'selector' ? 'md:grid-cols-3' : 'sm:grid-cols-2',
        )}
        onChange={() => {
          seq.current += 1
          setPreview(null)
        }}
        onSubmit={form.handleSubmit((values) => previewing.mutate(values))}
      >
        {mode.kind === 'selector' && (
          <Field
            label={t('host.selector')}
            error={form.formState.errors.selector?.message}
          >
            <Input className="font-mono" {...form.register('selector')} />
          </Field>
        )}
        <Field
          label={t('host.labels')}
          error={form.formState.errors.labels?.message}
        >
          <Textarea
            rows={3}
            className="font-mono"
            placeholder={t('host.labelsPlaceholder')}
            {...form.register('labels')}
          />
        </Field>
        <Field label={t('host.removeKeys')}>
          <Input className="font-mono" {...form.register('remove')} />
        </Field>
        <div className={mode.kind === 'selector' ? 'md:col-span-3' : 'sm:col-span-2'}>
          <Button type="submit" variant="outline" disabled={previewing.isPending}>
            {t('host.bulkPreview')}
          </Button>
        </div>
      </form>
      {preview && (
        <div className="flex flex-col gap-2 border-t border-border-subtle pt-3">
          {preview.missing > 0 && (
            <p role="note" className="text-xs text-warning">
              {t('host.previewMissing', { count: preview.missing })}
            </p>
          )}
          {preview.hosts.length ? (
            <ul className="max-h-48 overflow-y-auto rounded-lg border bg-card">
              {preview.hosts.map((host) => (
                <li
                  key={host.hostId}
                  className="flex flex-col gap-1 border-b border-border-subtle px-2.5 py-1.5 last:border-b-0"
                >
                  <span className="font-mono text-xs font-medium">
                    {host.hostname}
                  </span>
                  <DiffLines
                    lines={labelDiff(host.authorizationLabels, preview.changes)}
                  />
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">{t('common.empty')}</p>
          )}
          <div>
            <Button
              disabled={!preview.hosts.length || !hasChanges || applying.isPending}
              onClick={() => applying.mutate()}
            >
              {t('host.bulkApply', { count: preview.hosts.length })}
            </Button>
          </div>
        </div>
      )}
    </>
  )
  if (!floating) return <Panel title={t('host.bulk')}>{body}</Panel>
  return (
    <section
      aria-labelledby="host-selection-labels"
      className="flex max-h-[60vh] flex-col gap-2.5 overflow-y-auto rounded-2xl border bg-popover p-3.5 text-popover-foreground shadow-[0_16px_44px_rgb(20_22_30/0.18),0_2px_8px_rgb(20_22_30/0.06)] backdrop-blur"
    >
      <h2 id="host-selection-labels" className="text-sm font-semibold">
        {t('host.selectionLabels', { count: mode.kind === 'hosts' ? mode.hosts.length : 0 })}
      </h2>
      {body}
    </section>
  )
}

function ImportLabels() {
  const { t } = useTranslation()
  const notify = useNotify()
  const form = useForm<z.infer<typeof csvSchema>>({
    resolver: zodResolver(csvSchema),
    defaultValues: { csv: '' },
  })
  const seq = useRef(0)
  const [preview, setPreview] = useState<
    | (Awaited<ReturnType<typeof api.getHostImportPreview>> & {
        seq: number
      })
    | null
  >(null)
  const previewing = useCommand(async (values: z.infer<typeof csvSchema>) => {
    const my = ++seq.current
    const result = await api.previewHostImport({ csv: toBase64(values.csv) })
    if (seq.current !== my) return
    const detailed = await api.getHostImportPreview({
      previewId: result.preview.previewId,
    })
    if (seq.current !== my) return
    setPreview({ ...detailed, seq: my })
  })
  const applying = useCommand(async () => {
    if (!preview) return
    if (preview.seq !== seq.current) {
      setPreview(null)
      return
    }
    const result = await api.executeHostImport({
      previewId: preview.preview.previewId,
    })
    setPreview(null)
    notify({ key: 'host.imported', values: { count: result.updatedCount } })
  })
  return (
    <Panel title={t('host.csv')}>
      <p className="text-xs text-muted-foreground">{t('host.csvHint')}</p>
      <Field label={t('host.csvFile')}>
        <Input
          type="file"
          accept=".csv,text/csv"
          onChange={(event) => {
            const file = event.target.files?.[0]
            seq.current += 1
            setPreview(null)
            if (!file) return
            if (file.size > 524288) {
              notify({ key: 'error.csvLimit', error: true })
              return
            }
            const myFile = seq.current
            const reader = new FileReader()
            reader.onload = () => {
              if (seq.current !== myFile) return
              form.setValue('csv', String(reader.result), {
                shouldValidate: true,
              })
            }
            reader.onerror = () => notify({ key: 'error.file', error: true })
            reader.readAsText(file, 'UTF-8')
          }}
        />
      </Field>
      <form
        noValidate
        className="flex flex-col gap-3"
        onChange={() => {
          seq.current += 1
          setPreview(null)
        }}
        onSubmit={form.handleSubmit((values) => previewing.mutate(values))}
      >
        <Field
          label={t('host.csvText')}
          error={form.formState.errors.csv?.message}
        >
          <Textarea
            rows={4}
            className="font-mono text-xs"
            placeholder={'hostname,set:env,remove:tier\nweb-01,prod,true'}
            {...form.register('csv')}
          />
        </Field>
        <div>
          <Button variant="outline" disabled={previewing.isPending}>
            {t('host.preview')}
          </Button>
        </div>
      </form>
      {preview && (
        <div className="flex flex-col gap-2 border-t border-border-subtle pt-3">
          <p className="text-xs text-muted-foreground">
            {t('host.previewExpiry')}:{' '}
            <Time value={preview.preview.expiresAt} />
          </p>
          <DataTable<HostImportRow>
            data={preview.rows}
            columns={[
              { accessorKey: 'line', header: t('host.row') },
              {
                accessorKey: 'hostname',
                header: t('host.hostname'),
                cell: ({ row }) => (
                  <span className="font-mono text-xs">{row.original.hostname}</span>
                ),
              },
              {
                id: 'diff',
                header: `${t('host.before')} → ${t('host.after')}`,
                cell: ({ row }) => (
                  <DiffLines
                    lines={labelsDelta(row.original.before, row.original.after)}
                  />
                ),
              },
              {
                id: 'errors',
                header: t('host.violations'),
                cell: ({ row }) =>
                  row.original.violations.length ? (
                    <span className="text-destructive">
                      {row.original.violations
                        .map((v) => t(v.description))
                        .join('; ')}
                    </span>
                  ) : (
                    t('common.none')
                  ),
              },
            ]}
          />
          <div>
            <Button
              disabled={
                preview.preview.invalidRowCount !== '0' || applying.isPending
              }
              onClick={() => applying.mutate()}
            >
              {t('host.import')}
            </Button>
          </div>
        </div>
      )}
    </Panel>
  )
}

function HostPanel({
  hostname,
  versions,
  onClose,
}: {
  hostname: string
  versions: ReturnType<typeof useReferenceVersions>
  onClose: () => void
}) {
  const { t, i18n } = useTranslation()
  const query = useQuery({
    queryKey: ['host', hostname],
    queryFn: () => api.getHost({ hostname }),
  })
  const host = query.data?.host
  return (
    <SidePanel
      title={hostname}
      onClose={onClose}
      subtitle={
        host && (
          <>
            <StatusDot tone={host.online ? 'success' : 'neutral'} />
            {t(host.online ? 'host.online' : 'host.offline')}
            {host.lastSeen && (
              <span>· {relativeTime(host.lastSeen, i18n.language, t('common.justNow'))}</span>
            )}
          </>
        )
      }
    >
      <QueryState pending={query.isPending} error={query.error} />
      {host && (
        <HostEditor
          key={host.revision}
          host={host}
          versions={versions}
          onDeleted={onClose}
        />
      )}
    </SidePanel>
  )
}

function HostEditor({
  host,
  versions,
  onDeleted,
}: {
  host: Host
  versions: ReturnType<typeof useReferenceVersions>
  onDeleted: () => void
}) {
  const { t } = useTranslation()
  const [deleting, setDeleting] = useState(false)
  // Labels written through the API or CLI may not fit one key=value per line;
  // saving the text would then store different labels.
  const representable = labelsRepresentable(host.authorizationLabels)
  const form = useForm<z.infer<typeof labelSchema>>({
    resolver: zodResolver(labelSchema),
    mode: 'onChange',
    defaultValues: {
      labels: formatLabels(host.authorizationLabels),
      remove: '',
    },
  })
  const draft = useWatch({ control: form.control })
  const pending = draftChanges(draft.labels ?? '', draft.remove ?? '')
  const saving = useCommand(async (values: z.infer<typeof labelSchema>) => {
    await api.setHostLabels({
      targets: { hosts: { names: [host.hostname] } },
      expectedCount: '1',
      changes: {
        set: parseLabels(values.labels),
        remove: commaList(values.remove),
      },
      expectedRevisions: [{ hostId: host.hostId, revision: host.revision }],
    })
  }, 'host.labelsSaved')
  const deletion = useCommand(async () => {
    await api.deleteHost({
      hostId: host.hostId,
      expectedRevision: host.revision,
    })
    onDeleted()
  }, 'host.deleted')
  const pendingLines = pending ? labelDiff(host.authorizationLabels, pending) : []
  return (
    <>
      {!Object.keys(host.authorizationLabels).length && (
        <div
          role="note"
          className="flex flex-col gap-1 rounded-[10px] bg-warning-soft px-3 py-2.5 text-warning"
        >
          <strong className="font-semibold">{t('host.noLabels')}</strong>
          <span className="text-xs">{t('host.noLabelsHint')}</span>
        </div>
      )}
      {/* B1: per-service-account actions and matching rules render here. */}
      <PanelSection>
        <form
          noValidate
          className="flex flex-col gap-2.5"
          onSubmit={form.handleSubmit((values) => saving.mutate(values))}
        >
          <Field
            label={t('host.labels')}
            error={
              representable
                ? form.formState.errors.labels?.message
                : 'error.labelsUnrepresentable'
            }
          >
            <Textarea
              rows={3}
              className="font-mono"
              placeholder={t('host.labelsPlaceholder')}
              {...form.register('labels')}
            />
          </Field>
          <Field label={t('host.removeKeys')}>
            <Input className="font-mono" {...form.register('remove')} />
          </Field>
          {pendingLines.length > 0 && <DiffLines lines={pendingLines} />}
          <div className="flex items-center gap-2">
            <Button disabled={saving.isPending || !representable}>
              {t('host.saveLabels')}
            </Button>
            <span className="text-[11px] text-muted-foreground">
              {t('host.revision')} {host.revision}
            </span>
          </div>
        </form>
      </PanelSection>
      <PanelSection title={t('host.reportedLabels')}>
        {Object.keys(host.reportedLabels).length ? (
          <LabelPills labels={host.reportedLabels} reported />
        ) : (
          <span className="text-muted-foreground">{t('common.none')}</span>
        )}
      </PanelSection>
      <PanelSection title={t('host.catalogVersion')}>
        {host.loadedCatalogs.length ? (
          <ul className="flex flex-col gap-1">
            {host.loadedCatalogs.map((ref) => {
              const latest = versions.catalogBehind(ref)
              return (
                <li
                  key={`${ref.catalogId}@${ref.version}`}
                  className="flex justify-between gap-2 text-xs"
                >
                  <span className="font-mono">
                    {ref.catalogId} {ref.version}
                  </span>
                  {latest && (
                    <span className="text-warning">
                      {t('host.catalogBehindLatest', { version: latest })}
                    </span>
                  )}
                </li>
              )
            })}
          </ul>
        ) : (
          <span className="text-xs text-muted-foreground">
            {t('catalog.notLoaded')}
          </span>
        )}
        <span className="text-[11px] text-muted-foreground">
          {t('host.catalogHint')}
        </span>
      </PanelSection>
      <PanelSection>
        <dl className="grid grid-cols-[88px_minmax(0,1fr)] gap-x-2.5 gap-y-1.5 text-xs">
          <dt className="text-muted-foreground">{t('host.id')}</dt>
          <dd className="min-w-0">
            <MonoId value={host.hostId} />
          </dd>
          <dt className="text-muted-foreground">{t('host.agentVersion')}</dt>
          <dd className="min-w-0 font-mono break-words">
            {host.agentVersion}
            {versions.agentBehind(host) && (
              <span className="ml-1.5 font-sans text-warning">
                {t('host.upgradable', { version: versions.gateway })}
              </span>
            )}
          </dd>
          <dt className="text-muted-foreground">{t('host.registeredAt')}</dt>
          <dd className="min-w-0">
            <Time value={host.registeredAt} />
          </dd>
          <dt className="text-muted-foreground">{t('host.lastSeen')}</dt>
          <dd className="min-w-0">
            <Time value={host.lastSeen} />
          </dd>
        </dl>
      </PanelSection>
      <PanelSection className="border-t border-border-subtle pt-3.5">
        <div>
          <Button
            variant="ghost"
            className="text-destructive hover:bg-destructive-soft hover:text-destructive"
            aria-label={t('host.deleteTitle', { name: host.hostname })}
            onClick={() => setDeleting(true)}
          >
            {t('host.deleteAction')}
          </Button>
        </div>
      </PanelSection>
      {deleting && (
        <ConfirmDialog
          title={t('host.deleteTitle', { name: host.hostname })}
          description={t('host.deleteHint')}
          onClose={() => setDeleting(false)}
          onConfirm={() => deletion.mutate()}
          pending={deletion.isPending}
        />
      )}
    </>
  )
}
