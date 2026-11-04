import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  ArrowUpIcon,
  BanIcon,
  ClockIcon,
  KeyRoundIcon,
  SparklesIcon,
} from 'lucide-react'
import { api } from '@/api'
import { PageTitle, QueryState } from '@/components/console/common'
import { StatusDot } from '@/components/console/StatusDot'
import {
  softTone,
  statusTone,
  textTone,
  type Tone,
} from '@/components/console/tone'
import { relativeTime } from '@/lib/time'
import { cn } from '@/lib/utils'
import { compareVersions, newestVersion } from '@/lib/versions'

const card = 'rounded-xl border bg-card'

interface Attention {
  id: string
  icon: ReactNode
  tone: Tone
  title: string
  detail?: string
  // Without a call to action the title itself links to the target.
  cta?: string
  to: string
}

export default function Overview() {
  const { t, i18n } = useTranslation()
  const health = useQuery({
    queryKey: ['systemStatus'],
    queryFn: () => api.getSystemStatus(),
  })
  const jobs = useQuery({
    queryKey: ['jobs', 'recent'],
    queryFn: () => api.listJobs({ page: { pageSize: 6 } }),
  })
  const hosts = useQuery({
    queryKey: ['hostOptions'],
    queryFn: () => api.listHosts(),
  })
  const instances = useQuery({
    queryKey: ['instances'],
    queryFn: () => api.listGatewayInstances(),
  })
  const versions = useQuery({
    queryKey: ['agentVersions'],
    queryFn: () => api.getAgentVersionDistribution(),
  })
  const status = health.data
  const unlabeled = (hosts.data?.hosts ?? []).filter(
    (host) => !Object.keys(host.authorizationLabels).length,
  )
  const gateway = newestVersion(
    instances.data?.instances.map((instance) => instance.version) ?? [],
  )
  const behind = gateway
    ? (versions.data?.versions ?? []).filter(
        (v) =>
          Number(v.hostCount) > 0 &&
          (compareVersions(v.agentVersion, gateway) ?? 0) < 0,
      )
    : []
  const behindCount = behind.reduce((sum, v) => sum + Number(v.hostCount), 0)
  const online = Number(status?.onlineHosts ?? 0)
  const total = online + Number(status?.offlineHosts ?? 0)
  const when = (value: string) =>
    relativeTime(value, i18n.language, t('common.justNow'))

  const attention: Attention[] = []
  if (status && Number(status.expiringCatalogs) > 0)
    attention.push({
      id: 'catalog',
      icon: <ClockIcon />,
      tone: 'warning',
      title: t('overview.catalogAlert', { count: status.expiringCatalogs }),
      detail: t('overview.catalogAlertHint'),
      cta: t('overview.viewCatalog'),
      to: '/catalog',
    })
  if (status && Number(status.expiringServiceAccountTokens) > 0)
    attention.push({
      id: 'token',
      icon: <KeyRoundIcon />,
      tone: 'warning',
      title: t('overview.tokenAlert', {
        count: status.expiringServiceAccountTokens,
      }),
      cta: t('overview.rotateToken'),
      to: '/service-accounts',
    })
  if (unlabeled.length)
    attention.push({
      id: 'unlabeled',
      icon: <BanIcon />,
      tone: 'destructive',
      title: t('overview.unlabeledAlert', { count: unlabeled.length }),
      detail: t('overview.unlabeledAlertHint', {
        hosts: unlabeled
          .slice(0, 3)
          .map((host) => host.hostname)
          .join(', '),
        more: unlabeled.length > 3 ? ' …' : '',
      }),
      cta: t('overview.setLabels'),
      to: '/hosts?status=unlabeled',
    })
  if (behindCount)
    attention.push({
      id: 'agents',
      icon: <ArrowUpIcon />,
      tone: 'info',
      title: t('overview.agentAlert', { count: behindCount, version: gateway }),
      detail: behind
        .map((v) => `${v.agentVersion} × ${v.hostCount}`)
        .join(', '),
      cta: t('overview.viewSystem'),
      to: '/system',
    })
  if (status?.gatewayUpdate)
    attention.push({
      id: 'update',
      icon: <ArrowUpIcon />,
      tone: 'info',
      title: t('overview.updateAlert', {
        version: status.gatewayUpdate.latestVersion,
      }),
      to: '/system',
    })

  return (
    <div className="flex max-w-[1200px] flex-col gap-4">
      <PageTitle
        title={t('nav.overview')}
        description={t('overview.description')}
      />
      <QueryState pending={health.isPending} error={health.error} />
      {status && (
        <>
          <section
            aria-labelledby="overview-summary"
            className="flex items-start gap-3 rounded-2xl border bg-card px-[18px] py-4 shadow-[0_1px_2px_rgb(0_0_0/0.04),0_8px_24px_-12px_rgb(20_20_40/0.12)]"
          >
            <SparklesIcon
              aria-hidden="true"
              className="mt-0.5 size-[18px] shrink-0 text-primary"
            />
            <div className="flex flex-col gap-1">
              <h2
                id="overview-summary"
                className="text-xs font-normal text-muted-foreground"
              >
                {t('overview.summaryTitle')}
              </h2>
              {/* Built from API counts only. 24-hour call / allow / deny counts need B3. */}
              <p className="text-[15px] leading-relaxed">
                {t('overview.summaryJobs', {
                  running: status.runningJobs,
                  failed: status.failedJobsLast24Hours,
                })}{' '}
                {t('overview.summaryHosts', { online, total })}
                {unlabeled.length > 0 && (
                  <>
                    {' '}
                    {t('overview.summaryUnlabeled', {
                      count: unlabeled.length,
                    })}
                  </>
                )}
              </p>
            </div>
          </section>
          <section
            aria-label={t('overview.metrics')}
            className="grid grid-cols-[repeat(auto-fit,minmax(190px,1fr))] gap-3"
          >
            {(
              [
                {
                  label: t('host.onlineCount'),
                  value: status.onlineHosts,
                  of: ` / ${total}`,
                  hint: t('overview.hostsHint', {
                    offline: status.offlineHosts,
                    unlabeled: hosts.data ? unlabeled.length : '—',
                  }),
                  tone: 'success',
                  to: '/hosts',
                },
                {
                  label: t('job.runningCount'),
                  value: status.runningJobs,
                  tone: 'info',
                  pulse: Number(status.runningJobs) > 0,
                  to: '/jobs',
                },
                {
                  label: t('job.failedCount'),
                  value: status.failedJobsLast24Hours,
                  tone: 'warning',
                  to: '/jobs',
                },
                // B3: "denied calls in 24 hours" card goes here.
              ] as {
                label: string
                value: string
                of?: string
                hint?: string
                tone: Tone
                pulse?: boolean
                to: string
              }[]
            ).map((metric) => (
              <Link
                key={metric.label}
                to={metric.to}
                className={cn(
                  card,
                  'flex flex-col gap-1.5 px-4 py-3.5 text-foreground hover:no-underline hover:bg-muted/40',
                )}
              >
                <span className="flex items-center gap-[7px] text-xs text-muted-foreground">
                  <StatusDot tone={metric.tone} pulse={metric.pulse} />
                  {metric.label}
                </span>
                <span className="font-mono text-[26px] leading-tight font-medium tabular-nums">
                  {metric.value}
                  {metric.of && (
                    <span className="text-sm text-muted-foreground">
                      {metric.of}
                    </span>
                  )}
                </span>
                {metric.hint && (
                  <span className="text-xs text-muted-foreground">
                    {metric.hint}
                  </span>
                )}
              </Link>
            ))}
          </section>
          <section
            aria-labelledby="overview-attention"
            className={cn(card, 'overflow-hidden')}
          >
            <header className="flex items-center gap-2 border-b border-border-subtle px-4 py-3">
              <h2 id="overview-attention" className="text-sm font-semibold">
                {t('overview.attention')}
              </h2>
              {attention.length > 0 && (
                <span
                  className={cn(
                    'rounded-full px-1.5 font-mono text-[11px]',
                    softTone.warning,
                  )}
                >
                  {attention.length}
                </span>
              )}
            </header>
            {attention.length ? (
              <ul>
                {attention.map((item) => (
                  <li
                    key={item.id}
                    className="flex flex-wrap items-center gap-3 border-b border-border-subtle px-4 py-3 last:border-b-0"
                  >
                    <span
                      aria-hidden="true"
                      className={cn(
                        'grid size-7 shrink-0 place-items-center rounded-lg [&_svg]:size-[15px]',
                        item.tone === 'info'
                          ? 'bg-accent text-accent-foreground'
                          : softTone[item.tone],
                      )}
                    >
                      {item.icon}
                    </span>
                    <span className="flex min-w-0 flex-[1_1_260px] flex-col">
                      {item.cta ? (
                        <span className="font-medium">{item.title}</span>
                      ) : (
                        <Link
                          to={item.to}
                          className="self-start font-medium text-foreground hover:underline"
                        >
                          {item.title}
                        </Link>
                      )}
                      {item.detail && (
                        <span className="font-mono text-xs break-words text-muted-foreground">
                          {item.detail}
                        </span>
                      )}
                    </span>
                    {item.cta && (
                      <Link
                        to={item.to}
                        className="flex h-[30px] items-center rounded-lg border px-3 font-medium text-foreground hover:bg-muted hover:no-underline"
                      >
                        {item.cta}
                      </Link>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="px-4 py-6 text-center text-muted-foreground">
                {t('overview.noAlerts')}
              </p>
            )}
          </section>
        </>
      )}
      <section
        aria-labelledby="overview-jobs"
        className={cn(card, 'overflow-hidden')}
      >
        <header className="flex items-center border-b border-border-subtle px-4 py-3">
          <h2 id="overview-jobs" className="flex-1 text-sm font-semibold">
            {t('overview.recentJobs')}
          </h2>
          <Link
            to="/jobs"
            className="text-xs text-primary underline-offset-4 hover:underline"
          >
            {t('overview.allJobs')}
          </Link>
        </header>
        <div className="px-4">
          <QueryState pending={jobs.isPending} error={jobs.error} />
        </div>
        {jobs.data &&
          (jobs.data.jobs.length ? (
            <ul>
              {jobs.data.jobs.map((job) => {
                const tone = statusTone(job.status)
                return (
                  <li
                    key={job.jobId}
                    className="flex items-center gap-2.5 border-b border-border-subtle px-4 py-2.5 last:border-b-0"
                  >
                    <StatusDot tone={tone} pulse={tone === 'info'} />
                    <span className="flex min-w-0 flex-1 flex-col">
                      <span className="font-mono font-medium">{job.action}</span>
                      <span className="truncate text-xs text-muted-foreground">
                        <Link
                          to={`/jobs/${job.jobId}`}
                          className="font-mono text-primary underline-offset-4 hover:underline"
                        >
                          {job.jobId}
                        </Link>
                        {' · '}
                        {[
                          job.subjectId,
                          job.reason,
                          t('overview.jobHosts', { count: job.totalTasks }),
                        ]
                          .filter(Boolean)
                          .join(' · ')}
                      </span>
                    </span>
                    <span className="flex flex-col items-end">
                      <span
                        className={cn(
                          'text-xs font-medium',
                          tone === 'neutral'
                            ? 'text-muted-foreground'
                            : textTone[tone],
                        )}
                      >
                        {t(`status.${job.status}`, {
                          defaultValue: job.status,
                        })}
                      </span>
                      <span
                        className="text-[11px] text-muted-foreground"
                        title={job.createdAt}
                      >
                        {when(job.createdAt)}
                      </span>
                    </span>
                  </li>
                )
              })}
            </ul>
          ) : (
            <p className="px-4 py-6 text-center text-muted-foreground">
              {t('common.empty')}
            </p>
          ))}
      </section>
      {/* Agent activity (README §4.2) needs the newest audit events first and a
          decision filter (B6); ListAuditEvents reads from the oldest event, so
          it is left out here. */}
    </div>
  )
}
