import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { RefreshCwIcon } from 'lucide-react'
import { api, type DependencyHealth, type SystemStatus } from '@/api'
import { Button } from '@/components/ui/button'
import {
  PageTitle,
  QueryState,
  Status,
  Time,
} from '@/components/console/common'
import { softTone } from '@/components/console/tone'
import { useCommand } from '@/lib/notifications'
import { relativeTime } from '@/lib/time'
import { displayVersion, releaseNotesUrl } from '@/lib/release'
import { cn } from '@/lib/utils'
import { compareVersions, newestVersion } from '@/lib/versions'

const card = 'rounded-xl border bg-card px-4 py-3.5'

function formatBytes(value: number | string) {
  const bytes = Number(value)
  for (const [unit, size] of [
    ['GiB', 1024 ** 3],
    ['MiB', 1024 ** 2],
    ['KiB', 1024],
  ] as const) {
    if (bytes >= size && bytes % size === 0) return `${bytes / size} ${unit}`
  }
  return `${bytes} B`
}

function Dependencies({ items }: { items: DependencyHealth[] }) {
  const { t } = useTranslation()
  return (
    <ul className="flex flex-col gap-1.5">
      {items.map((item) => (
        <li key={item.name} className="flex flex-col">
          <span className="flex items-center gap-2">
            <span className="flex-1">{t(item.name)}</span>
            <Status value={item.status} />
          </span>
          {item.reason && (
            <span className="font-mono text-xs text-foreground-2">
              {item.reason}
            </span>
          )}
        </li>
      ))}
    </ul>
  )
}

function Limits({ limits }: { limits: SystemStatus['limits'] }) {
  const { t } = useTranslation()
  const rows: [string, string][] = [
    ['system.limitMessage', formatBytes(limits.maxMessageBytes)],
    ['system.limitChunk', formatBytes(limits.maxChunkBytes)],
    ['system.limitPage', `${limits.defaultPageSize} / ${limits.maxPageSize}`],
    [
      'system.limitOutputPage',
      `${formatBytes(limits.defaultOutputPageBytes)} / ${formatBytes(limits.maxOutputPageBytes)}`,
    ],
    ['system.limitCatalog', formatBytes(limits.maxCatalogBytes)],
    ['system.limitCsv', formatBytes(limits.maxCsvBytes)],
  ]
  return (
    <dl className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-1.5 text-xs">
      {rows.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-foreground-2">{t(label)}</dt>
          <dd className="text-right font-mono">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

function UpdateCheck({ status }: { status: SystemStatus }) {
  const { t } = useTranslation()
  return (
    <>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
        <dt className="text-muted-foreground">{t('system.updateCheck')}</dt>
        <dd>
          {t(
            status.updateCheckEnabled
              ? 'system.updateCheckEnabled'
              : 'system.updateCheckDisabled',
          )}
        </dd>
        {status.updateCheckEnabled && (
          <>
            <dt className="text-muted-foreground">{t('system.lastChecked')}</dt>
            <dd>
              <Time value={status.updateCheckedAt} />
            </dd>
            <dt className="text-muted-foreground">{t('system.latestVersion')}</dt>
            <dd className="min-w-0 break-words">
              {status.gatewayUpdate ? (
                <a
                  href={releaseNotesUrl(status.gatewayUpdate.latestVersion)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-medium text-primary underline-offset-4 hover:underline"
                >
                  {t('system.releaseNotes', {
                    version: displayVersion(status.gatewayUpdate.latestVersion),
                  })}
                </a>
              ) : status.updateCheckedAt && !status.updateCheckError ? (
                t('system.upToDate')
              ) : (
                t('common.none')
              )}
            </dd>
          </>
        )}
        <dt className="text-muted-foreground">{t('nav.hosts')}</dt>
        <dd>
          {t('system.hostsBelow', {
            count: Number(status.hostsBelowGatewayVersion),
          })}
        </dd>
      </dl>
      {status.updateCheckEnabled && status.updateCheckError && (
        <p className={cn('rounded-lg px-3 py-2 text-xs', softTone.destructive)}>
          {t('system.checkError', { error: status.updateCheckError })}
        </p>
      )}
    </>
  )
}

export default function System() {
  const { t, i18n } = useTranslation()
  const status = useQuery({
    queryKey: ['systemStatus'],
    queryFn: () => api.getSystemStatus(),
  })
  const instances = useQuery({
    queryKey: ['instances'],
    queryFn: () => api.listGatewayInstances(),
  })
  const versions = useQuery({
    queryKey: ['agentVersions'],
    queryFn: () => api.getAgentVersionDistribution(),
  })
  // useCommand refetches every query on success, which is the refresh.
  const refresh = useCommand(async () => {}, 'system.refreshed')
  const instanceList = instances.data?.instances ?? []
  const instanceVersions = [
    ...new Set(instanceList.map((i) => i.version)),
  ].sort()
  const gateway = newestVersion(instanceVersions)
  const distribution = versions.data?.versions ?? []
  const totalHosts = distribution.reduce(
    (sum, version) => sum + Number(version.hostCount),
    0,
  )
  const behind = gateway
    ? distribution
        .filter((v) => (compareVersions(v.agentVersion, gateway) ?? 0) < 0)
        .reduce((sum, v) => sum + Number(v.hostCount), 0)
    : 0

  return (
    <div className="flex flex-col gap-3.5">
      <PageTitle
        title={t('nav.system')}
        description={
          <>
            {t('system.description')}
            {status.data && (
              <>
                {' · '}
                {t('system.observed')} <Time value={status.data.observedAt} />
              </>
            )}
          </>
        }
        action={
          <Button
            variant="outline"
            disabled={refresh.isPending}
            onClick={() => refresh.mutate()}
          >
            <RefreshCwIcon />
            {t('system.refresh')}
          </Button>
        }
      />
      <QueryState pending={status.isPending} error={status.error} />
      <section
        aria-labelledby="system-gateway"
        className="flex flex-wrap items-start gap-4 rounded-2xl border bg-card px-[18px] py-4 shadow-[0_1px_2px_rgb(0_0_0/0.04),0_8px_24px_-12px_rgb(20_20_40/0.12)]"
      >
        <div className="flex min-w-56 flex-col gap-2">
          <h2 id="system-gateway" className="text-xs font-normal text-muted-foreground">
            {t('system.gateway')}
          </h2>
          <span className="font-mono text-[22px] leading-none font-medium">
            {(status.data && displayVersion(status.data.gatewayVersion)) || '—'}
          </span>
          {instanceVersions.length > 1 && (
            <span
              className={cn(
                'self-start rounded-full px-2 py-0.5 text-xs',
                softTone.warning,
              )}
            >
              {t('system.versionMismatch', {
                versions: instanceVersions.join(t('system.versionSeparator')),
              })}
            </span>
          )}
          {status.data && <UpdateCheck status={status.data} />}
        </div>
        {status.data && (
          <div className="flex min-w-64 flex-1 flex-col gap-2">
            <span className="flex items-center gap-2 text-xs text-muted-foreground">
              {t('system.dependencies')}
              <Status value={status.data.status} />
            </span>
            <Dependencies items={status.data.dependencies} />
          </div>
        )}
      </section>
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-semibold">{t('system.instances')}</h2>
        {instances.data && (
          <span className="font-mono text-xs text-muted-foreground">
            {instanceList.length}
          </span>
        )}
      </div>
      <QueryState pending={instances.isPending} error={instances.error} />
      <section
        aria-label={t('system.instances')}
        className="grid grid-cols-[repeat(auto-fit,minmax(min(340px,100%),1fr))] gap-3"
      >
        {instanceList.map((instance) => (
          <article
            key={instance.instanceId}
            className={cn(card, 'flex flex-col gap-3')}
          >
            <header className="flex flex-wrap items-center gap-2.5">
              <span className="font-mono font-medium break-all">
                {instance.instanceId}
              </span>
              <span className="font-mono text-xs text-muted-foreground">
                {instance.version}
              </span>
              <span className="flex-1" />
              {instance.draining && (
                <span
                  className={cn(
                    'rounded-full px-2 py-px text-xs',
                    softTone.warning,
                  )}
                >
                  {t('system.draining')}
                </span>
              )}
            </header>
            <dl className="grid grid-cols-3 gap-2 text-xs">
              <div>
                <dt className="text-muted-foreground">{t('system.connected')}</dt>
                <dd className="font-mono text-lg">{instance.connectedHosts}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t('system.startedAt')}</dt>
                <dd className="font-mono">
                  <Time value={instance.startedAt} />
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t('system.lastSeen')}</dt>
                <dd title={instance.lastSeen}>
                  {instance.lastSeen
                    ? relativeTime(
                        instance.lastSeen,
                        i18n.language,
                        t('common.justNow'),
                      )
                    : t('common.none')}
                </dd>
              </div>
            </dl>
            {instance.dependencies.length > 0 && (
              <div className="flex flex-col gap-1.5 border-t border-border-subtle pt-2.5">
                <span className="text-[11px] text-muted-foreground">
                  {t('system.dependencies')}
                </span>
                <Dependencies items={instance.dependencies} />
              </div>
            )}
            {instance.draining && (
              <p className="text-xs text-foreground-2">
                {t('system.drainingHint')}
              </p>
            )}
          </article>
        ))}
      </section>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(340px,100%),1fr))] gap-3">
        <section
          aria-labelledby="system-distribution"
          className={cn(card, 'flex flex-col gap-2.5')}
        >
          <h2 id="system-distribution" className="text-sm font-semibold">
            {t('system.distribution')}
          </h2>
          <QueryState pending={versions.isPending} error={versions.error} />
          <ul className="flex flex-col gap-2">
            {distribution.map((version) => {
              const count = Number(version.hostCount)
              const order = gateway
                ? compareVersions(version.agentVersion, gateway)
                : null
              return (
                <li
                  key={version.agentVersion}
                  className="flex items-center gap-2.5"
                >
                  <span className="w-20 truncate font-mono" title={version.agentVersion}>
                    {version.agentVersion || '—'}
                  </span>
                  <span
                    aria-hidden="true"
                    className="flex h-2 flex-1 overflow-hidden rounded bg-muted"
                  >
                    <span
                      className={cn(
                        'rounded',
                        order === null
                          ? 'bg-dot-neutral'
                          : order < 0
                            ? 'bg-dot-warning'
                            : 'bg-primary',
                      )}
                      style={{
                        width: `${totalHosts ? (count / totalHosts) * 100 : 0}%`,
                      }}
                    />
                  </span>
                  <span className="w-28 text-right font-mono text-xs">
                    {t('system.hostCount', {
                      count,
                      online: version.onlineCount,
                    })}
                  </span>
                </li>
              )
            })}
          </ul>
          {behind > 0 && (
            <>
              <p className="text-xs text-warning">
                {t('system.behind', { count: behind, version: gateway })}
              </p>
              <Link
                to="/hosts?status=outdated"
                className="text-xs text-primary underline-offset-4 hover:underline"
              >
                {t('system.filterOutdated')}
              </Link>
            </>
          )}
        </section>
        {status.data && (
          <section
            aria-labelledby="system-limits"
            className={cn(card, 'flex flex-col gap-2')}
          >
            <h2 id="system-limits" className="text-sm font-semibold">
              {t('system.limits')}
            </h2>
            <Limits limits={status.data.limits} />
          </section>
        )}
      </div>
    </div>
  )
}
