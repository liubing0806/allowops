import { useId, useRef, useState, type ReactNode } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Code } from '@connectrpc/connect'
import { SearchIcon, XIcon } from 'lucide-react'
import { api, ApiError, type Job, type JobStatus, type Task } from '@/api'
import { jobStatuses } from '@/api/types'
import {
  ConfirmDialog,
  DataTable,
  PageTitle,
  PagerFooter,
  QueryState,
  Status,
  Time,
} from '@/components/console/common'
import {
  SegmentedControl,
  type Segment,
} from '@/components/console/SegmentedControl'
import { StatusDot } from '@/components/console/StatusDot'
import {
  softTone,
  statusTone,
  textTone,
  type Tone,
} from '@/components/console/tone'
import { UntrustedBanner } from '@/components/console/UntrustedBanner'
import { Button } from '@/components/ui/button'
import { useCommand } from '@/lib/notifications'
import { relativeTime } from '@/lib/time'
import { cn } from '@/lib/utils'

const jobsPageSize = 10

// Authentication, authorization and missing-resource errors do not recover by
// polling again.
const pollStopCodes: number[] = [
  Code.Unauthenticated,
  Code.PermissionDenied,
  Code.NotFound,
]
const stopsPolling = (error: unknown) =>
  error instanceof ApiError &&
  error.code !== undefined &&
  pollStopCodes.includes(error.code)

const pollInterval = 2000
// Output is stored asynchronously after a task ends. Keep polling for this long
// after the last change of the task list.
const storagePollWindow = 30000
const defaultOutputRetry = 1000
const activeJobStatuses = ['JOB_STATUS_QUEUED', 'JOB_STATUS_RUNNING']
const activeTaskStatuses = ['TASK_STATUS_PENDING', 'TASK_STATUS_RUNNING']
// Tasks in these states never produced output on the host.
const noOutputStatuses = ['TASK_STATUS_OFFLINE', 'TASK_STATUS_PENDING']

type Stream = 'OUTPUT_STREAM_STDOUT' | 'OUTPUT_STREAM_STDERR'

const barTone: Record<Tone, string> = {
  success: 'bg-dot-success',
  warning: 'bg-dot-warning',
  info: 'bg-dot-info',
  destructive: 'bg-dot-destructive',
  neutral: 'bg-dot-neutral',
}

// One route keeps the list mounted, with its filters and page, while the
// selected job changes.
export default function Jobs() {
  const { jobId } = useParams()
  const { t } = useTranslation()
  const [status, setStatus] = useState<JobStatus | ''>('')
  const [action, setAction] = useState('')
  // tokens[i] opens page i + 1; the first page has no token. Changing a filter
  // starts again from the first page, because a token is bound to its filters.
  const filterKey = JSON.stringify([status, action])
  const [paging, setPaging] = useState({ filterKey, tokens: [''] })
  if (paging.filterKey !== filterKey) setPaging({ filterKey, tokens: [''] })
  const tokens = paging.filterKey === filterKey ? paging.tokens : ['']
  const pageToken = tokens[tokens.length - 1]
  const query = useQuery({
    queryKey: ['jobs', { status, action }, pageToken],
    queryFn: () =>
      api.listJobs({
        statuses: status ? [status] : [],
        action,
        page: { pageSize: jobsPageSize, pageToken },
      }),
    placeholderData: keepPreviousData,
  })
  const nextPageToken = query.data?.page.nextPageToken
  const statusOptions: Segment<JobStatus | ''>[] = [
    { value: '', label: t('host.all') },
    ...jobStatuses.map((value) => ({
      value,
      label: t(`status.${value}`),
      tone: statusTone(value),
    })),
  ]

  return (
    <>
      <PageTitle
        title={t('nav.jobs')}
        description={t('job.description')}
        action={
          <label className="relative flex w-full min-w-0 items-center sm:w-64">
            <SearchIcon
              aria-hidden="true"
              className="pointer-events-none absolute left-2.5 size-3.5 text-muted-foreground"
            />
            <span className="sr-only">{t('job.action')}</span>
            <input
              value={action}
              onChange={(event) => setAction(event.target.value)}
              placeholder={t('job.actionPlaceholder')}
              className="h-8 w-full min-w-0 rounded-lg border bg-card pr-8 pl-8 font-mono text-sm outline-none placeholder:font-sans placeholder:text-muted-foreground focus-visible:border-ring"
            />
            {action && (
              <button
                type="button"
                aria-label={t('job.clearAction')}
                onClick={() => setAction('')}
                className="absolute right-1.5 grid size-6 place-items-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                <XIcon aria-hidden="true" className="size-3.5" />
              </button>
            )}
          </label>
        }
      />
      <SegmentedControl
        label={t('job.status')}
        value={status}
        onChange={setStatus}
        options={statusOptions}
        className="self-start"
      />
      <div className="flex flex-wrap items-start gap-4">
        <section
          aria-label={t('job.list')}
          className={cn(
            'max-w-full min-w-0 flex-[1_1_340px] overflow-hidden rounded-xl border bg-card',
            jobId && 'order-2 md:order-none',
          )}
        >
          <QueryState pending={query.isPending} error={query.error} />
          {query.data && (
            <>
              <ul aria-label={t('job.list')}>
                {query.data.jobs.map((job) => (
                  <JobRow key={job.jobId} job={job} selected={job.jobId === jobId} />
                ))}
              </ul>
              {!query.data.jobs.length && (
                <p className="px-4 py-8 text-center text-sm text-muted-foreground">
                  {t('job.noMatch')}
                </p>
              )}
              {(tokens.length > 1 || !!nextPageToken) && (
                <div className="px-3.5 pb-2.5">
                  <PagerFooter
                    label={t('common.page', { page: tokens.length })}
                    canPrevious={tokens.length > 1 && !query.isPlaceholderData}
                    canNext={!!nextPageToken && !query.isPlaceholderData}
                    onPrevious={() =>
                      setPaging({ filterKey, tokens: tokens.slice(0, -1) })
                    }
                    onNext={() =>
                      nextPageToken &&
                      setPaging({ filterKey, tokens: [...tokens, nextPageToken] })
                    }
                  />
                </div>
              )}
            </>
          )}
        </section>
        <section
          aria-label={t('job.detail')}
          className={cn(
            'flex min-w-0 flex-[999_1_560px] flex-col gap-3.5',
            jobId && 'order-1 md:order-none',
          )}
        >
          {jobId ? (
            <JobDetail jobId={jobId} />
          ) : (
            <p className="rounded-xl border border-dashed px-4 py-10 text-center text-sm text-muted-foreground">
              {t('job.pick')}
            </p>
          )}
        </section>
      </div>
    </>
  )
}

function countOf(job: Job, status: string) {
  return Number(job.counts.find((entry) => entry.status === status)?.count ?? 0)
}

function JobRow({ job, selected }: { job: Job; selected: boolean }) {
  const { t, i18n } = useTranslation()
  const summary = useId()
  const tone = statusTone(job.status)
  const total = Number(job.totalTasks)
  const succeeded = countOf(job, 'TASK_STATUS_SUCCEEDED')
  return (
    <li className="border-b border-border-subtle last:border-b-0">
      <Link
        to={`/jobs/${job.jobId}`}
        aria-label={job.jobId}
        aria-describedby={summary}
        aria-current={selected ? 'page' : undefined}
        className={cn(
          'flex flex-col gap-1.5 px-3.5 py-3 text-foreground hover:bg-muted/60 hover:no-underline',
          selected &&
            'bg-selection shadow-[inset_2px_0_0_var(--primary)] hover:bg-selection',
        )}
      >
        <span className="flex w-full items-center gap-2">
          <StatusDot tone={tone} pulse={tone === 'info'} />
          <span className="min-w-0 flex-1 truncate font-mono font-medium">
            {job.action}
          </span>
          <span className="shrink-0 text-[11px] text-muted-foreground">
            {relativeTime(job.createdAt, i18n.language, t('common.justNow'))}
          </span>
        </span>
        <span
          id={summary}
          className="truncate pl-[15px] text-xs text-foreground-2"
        >
          <span className="font-mono">{job.jobId}</span>
          {' · '}
          <span className="font-mono">{job.subjectId}</span>
          {' · '}
          {t(job.reason)}
        </span>
        <span className="flex w-full items-center gap-2 pl-[15px]">
          <span
            aria-hidden="true"
            className="flex h-1 flex-1 overflow-hidden rounded-sm bg-muted"
          >
            {total > 0
              ? job.counts.map((entry) => (
                  <span
                    key={entry.status}
                    style={{ width: `${(Number(entry.count) / total) * 100}%` }}
                    className={barTone[statusTone(entry.status)]}
                  />
                ))
              : job.status === 'JOB_STATUS_DENIED' && (
                  <span className="w-full bg-dot-destructive" />
                )}
          </span>
          <span
            className={cn(
              'text-[11px] font-medium whitespace-nowrap',
              textTone[tone],
            )}
          >
            {t(`status.${job.status}`)}
            {total > 0 && ` · ${succeeded}/${total}`}
          </span>
        </span>
      </Link>
    </li>
  )
}

// ProtoJSON Duration, for example "0.042s".
function formatDuration(value: string) {
  const seconds = Number.parseFloat(value)
  if (!Number.isFinite(seconds)) return value
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`
  return `${seconds.toFixed(1)}s`
}

function JobDetail({ jobId }: { jobId: string }) {
  const { t } = useTranslation()
  const titleId = useId()
  const query = useQuery({
    queryKey: ['job', jobId],
    queryFn: () => api.getJob({ jobId }),
    refetchInterval: (current) => {
      if (stopsPolling(current.state.error)) return false
      const status = (
        current.state.data as { job?: Job } | undefined
      )?.job?.status
      if (!status) return false
      return activeJobStatuses.includes(status) ? pollInterval : false
    },
  })
  const lastChange = useRef({ signature: '', at: 0 })
  const tasks = useQuery({
    queryKey: ['tasks', jobId],
    queryFn: () => api.listTasks({ jobId }),
    refetchInterval: (current) => {
      if (stopsPolling(current.state.error)) return false
      const data = current.state.data as { tasks?: Task[] } | undefined
      if (!data?.tasks) return false
      const signature = JSON.stringify([
        jobId,
        data.tasks.map((task) => [
          task.hostname,
          task.result.status,
          task.outputStored,
        ]),
      ])
      if (lastChange.current.signature !== signature) {
        lastChange.current = { signature, at: Date.now() }
      }
      if (
        data.tasks.some((task) => activeTaskStatuses.includes(task.result.status))
      )
        return pollInterval
      const awaitingStorage = data.tasks.some((task) => !task.outputStored)
      return awaitingStorage &&
        Date.now() - lastChange.current.at < storagePollWindow
        ? pollInterval
        : false
    },
  })
  const session = useQuery({
    queryKey: ['session'],
    queryFn: () => api.getCurrentSession(),
  })
  // The route element is reused when :jobId changes, so the selection is
  // bound to the job it was made for instead of being reset in an effect.
  const [selected, setSelected] = useState<{
    jobId: string
    host: string
  } | null>(null)
  const host = selected?.jobId === jobId ? selected.host : null
  const [cancel, setCancel] = useState(false)
  const cancellation = useCommand(async () => {
    await api.cancelJob({ jobId })
    setCancel(false)
  }, 'job.cancelled')
  const job = query.data?.job
  const tone = job ? statusTone(job.status) : 'neutral'
  const taskList = tasks.data?.tasks ?? []
  const openTask = taskList.find((task) => task.hostname === host)
  // Any signed-in user may try to read output; the gateway decides via the view_output ABAC policy (web README A34).
  const canOutput = !!session.data?.user
  const taskCounts = Object.entries(
    taskList.reduce<Record<string, number>>((counts, task) => {
      counts[task.result.status] = (counts[task.result.status] ?? 0) + 1
      return counts
    }, {}),
  )

  return (
    <>
      <QueryState pending={query.isPending} error={query.error} />
      {job && (
        <article
          aria-labelledby={titleId}
          className="flex flex-col gap-3.5 rounded-xl border bg-card px-[18px] py-4"
        >
          <div className="flex flex-wrap items-start gap-3">
            <div className="flex min-w-0 flex-1 flex-col gap-1">
              <span className="flex min-w-0 flex-wrap items-center gap-2">
                <span className="min-w-0 truncate font-mono text-[17px] font-medium">
                  {job.action}
                </span>
                <span
                  className={cn(
                    'inline-flex items-center gap-1.5 rounded-full px-2 py-px text-xs font-medium',
                    softTone[tone],
                  )}
                >
                  <StatusDot tone={tone} size={6} pulse={tone === 'info'} />
                  {t(`status.${job.status}`)}
                </span>
              </span>
              <div className="flex flex-wrap items-baseline gap-x-1.5 font-mono text-xs text-muted-foreground">
                <h2 id={titleId} className="font-normal">
                  {job.jobId}
                </h2>
                <span aria-hidden="true">·</span>
                <span className="font-sans">
                  {t('job.summary', { count: Number(job.totalTasks) })}
                </span>
              </div>
            </div>
            {activeJobStatuses.includes(job.status) && (
              <Button
                variant="outline"
                size="sm"
                className="text-destructive hover:text-destructive"
                onClick={() => setCancel(true)}
              >
                {t('job.cancel')}
              </Button>
            )}
          </div>
          {job.status === 'JOB_STATUS_DENIED' && (
            // The matching deny rule is recorded in the audit event; the job
            // itself does not carry it.
            <p
              role="note"
              className="rounded-lg bg-destructive-soft px-3 py-2.5 text-sm text-destructive"
            >
              {t('job.deniedHint')}
            </p>
          )}
          <dl className="grid grid-cols-[repeat(auto-fit,minmax(160px,1fr))] gap-x-4 gap-y-2.5">
            <Meta label={t('job.subject')} mono>
              {job.subjectId}
            </Meta>
            <Meta label={t('job.reason')}>{t(job.reason)}</Meta>
            <Meta label={t('nav.catalog')} mono>
              {job.catalog.catalogId} {job.catalog.version}
            </Meta>
            <Meta label={t('policy.historyVersion')} mono>
              {job.policyVersion}
            </Meta>
            <Meta label={t('common.createdAt')}>
              <Time value={job.createdAt} />
            </Meta>
            <Meta label={t('job.finishedAt')}>
              <Time value={job.finishedAt} />
            </Meta>
          </dl>
          {/* B4 slot: the "MCP call made by the agent" block needs the job's
              targets, expected_count and redacted params, which the Job
              message does not carry yet (docs/console-redesign §5 B4). */}
        </article>
      )}
      {job?.status !== 'JOB_STATUS_DENIED' && (
        <section
          aria-labelledby={`${titleId}-tasks`}
          className="overflow-hidden rounded-xl border bg-card"
        >
          <header className="flex flex-wrap items-center gap-2 border-b border-border-subtle px-3.5 py-2.5">
            <h3 id={`${titleId}-tasks`} className="flex-1 text-sm font-semibold">
              {t('job.tasks')}
            </h3>
            {taskCounts.length > 0 && (
              <span className="text-xs text-muted-foreground">
                {taskCounts
                  .map(([status, count]) => `${t(`status.${status}`)} ${count}`)
                  .join(' · ')}
              </span>
            )}
          </header>
          <QueryState pending={tasks.isPending} error={tasks.error} />
          {tasks.data && (
            <div className="overflow-x-auto px-1.5">
              <DataTable<Task>
                data={taskList}
                rowClassName={(task) =>
                  task.hostname === host ? 'bg-selection hover:bg-selection' : undefined
                }
                columns={[
                  {
                    accessorKey: 'hostname',
                    header: t('host.hostname'),
                    cell: ({ row }) => (
                      <span className="font-mono">{row.original.hostname}</span>
                    ),
                  },
                  {
                    id: 'status',
                    header: t('job.taskStatus'),
                    cell: ({ row }) => <Status value={row.original.result.status} />,
                  },
                  {
                    id: 'exitCode',
                    header: t('job.exitCode'),
                    cell: ({ row }) => (
                      <span className="font-mono">
                        {row.original.result.exitCode ?? t('common.none')}
                      </span>
                    ),
                  },
                  {
                    id: 'duration',
                    header: t('job.duration'),
                    cell: ({ row }) => (
                      <span className="font-mono text-foreground-2">
                        {row.original.startedAt
                          ? formatDuration(row.original.result.duration)
                          : t('common.none')}
                      </span>
                    ),
                  },
                  {
                    accessorKey: 'outputStored',
                    header: t('job.outputStored'),
                    cell: ({ row }) => (
                      <span className="text-foreground-2">
                        {t(row.original.outputStored ? 'policy.yes' : 'policy.no')}
                      </span>
                    ),
                  },
                  {
                    id: 'output',
                    header: t('job.outputColumn'),
                    cell: ({ row }) => {
                      const task = row.original
                      if (noOutputStatuses.includes(task.result.status))
                        return <span className="text-muted-foreground">{t('common.none')}</span>
                      const viewing = task.hostname === host
                      return (
                        <Button
                          variant="outline"
                          size="xs"
                          aria-label={t('job.output', { host: task.hostname })}
                          aria-pressed={viewing}
                          disabled={!canOutput}
                          className={cn(
                            viewing &&
                              'border-accent bg-accent text-accent-foreground hover:bg-accent',
                          )}
                          onClick={() =>
                            setSelected({ jobId, host: task.hostname })
                          }
                        >
                          {t('job.viewOutput')}
                        </Button>
                      )
                    },
                  },
                ]}
              />
            </div>
          )}
        </section>
      )}
      {openTask && (
        <OutputViewer
          key={`${jobId}/${openTask.hostname}`}
          jobId={jobId}
          task={openTask}
          onClose={() => setSelected(null)}
        />
      )}
      {cancel && (
        <ConfirmDialog
          title={t('job.cancelTitle')}
          description={t('job.cancelHint')}
          onClose={() => setCancel(false)}
          onConfirm={() => cancellation.mutate()}
          pending={cancellation.isPending}
        />
      )}
    </>
  )
}

function Meta({
  label,
  mono = false,
  children,
}: {
  label: string
  mono?: boolean
  children: ReactNode
}) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <dt className="text-[11px] text-muted-foreground">{label}</dt>
      <dd className={cn('min-w-0 truncate text-xs', mono && 'font-mono')}>
        {children}
      </dd>
    </div>
  )
}

function OutputViewer({
  jobId,
  task,
  onClose,
}: {
  jobId: string
  task: Task
  onClose: () => void
}) {
  const { t } = useTranslation()
  const titleId = useId()
  const [stream, setStream] = useState<Stream>('OUTPUT_STREAM_STDOUT')
  // Composite actions store output per step; the gateway requires step_index
  // for them and rejects it for single-command actions.
  const [step, setStep] = useState(0)
  const stepIndex = task.stepCount > 0 ? step : undefined
  const streams: Segment<Stream>[] = [
    { value: 'OUTPUT_STREAM_STDOUT', label: t('job.stdout') },
    { value: 'OUTPUT_STREAM_STDERR', label: t('job.stderr') },
  ]
  return (
    <section
      aria-labelledby={titleId}
      className="overflow-hidden rounded-xl border bg-card"
    >
      <header className="flex flex-wrap items-center gap-2.5 border-b border-border-subtle px-3.5 py-2.5">
        <h3 id={titleId} className="text-sm font-semibold">
          {t('job.outputTitle', { host: task.hostname })}
        </h3>
        {task.outputStored && (
          <span className="rounded-full bg-muted px-1.5 text-[11px] text-foreground-2">
            {t('job.outputStored')}
          </span>
        )}
        <span className="flex-1" />
        <SegmentedControl
          label={t('job.streams')}
          value={stream}
          onChange={setStream}
          options={streams}
        />
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label={t('common.close')}
          onClick={onClose}
        >
          <XIcon />
        </Button>
      </header>
      <div className="flex flex-col gap-2.5 p-3.5">
        {task.stepCount > 0 && (
          <SegmentedControl
            label={t('job.steps')}
            value={String(step)}
            onChange={(value) => setStep(Number(value))}
            options={Array.from({ length: task.stepCount }, (_, index) => ({
              value: String(index),
              label: t('job.step', { index: index + 1 }),
            }))}
            className="self-start"
          />
        )}
        <UntrustedBanner />
        {/* Both streams stay mounted so switching keeps each stream's read
            position; only the selected one is shown. */}
        {streams.map((option) => (
          <OutputStream
            key={`${option.value}/${stepIndex ?? ''}`}
            jobId={jobId}
            hostname={task.hostname}
            stream={option.value}
            stepIndex={stepIndex}
            hidden={option.value !== stream}
          />
        ))}
      </div>
    </section>
  )
}

function OutputStream({
  jobId,
  hostname,
  stream,
  stepIndex,
  hidden,
}: {
  jobId: string
  hostname: string
  stream: Stream
  stepIndex?: number
  hidden: boolean
}) {
  const { t } = useTranslation()
  const [offset, setOffset] = useState('0')
  const [previous, setPrevious] = useState<Uint8Array>(new Uint8Array())
  const system = useQuery({
    queryKey: ['systemStatus'],
    queryFn: () => api.getSystemStatus(),
  })
  const limits = system.data?.limits
  const limitBytes = limits
    ? Math.min(limits.defaultOutputPageBytes, limits.maxOutputPageBytes)
    : undefined
  const query = useQuery({
    queryKey: ['output', jobId, hostname, stream, stepIndex, offset, limitBytes],
    queryFn: () =>
      api.getJobOutput({
        jobId,
        hostname,
        stream,
        offset,
        ...(stepIndex === undefined ? {} : { stepIndex }),
        ...(limitBytes === undefined ? {} : { limitBytes }),
      }),
    staleTime: Infinity,
    refetchInterval: (current) => {
      const error = current.state.error
      if (stopsPolling(error)) return false
      if (error instanceof ApiError) {
        if (error.reason === 'OUTPUT_UNAVAILABLE') return false
        if (error.reason === 'OUTPUT_PENDING')
          // 0 would stop polling; a non-positive hint counts as not provided.
          return error.retryAfterMs && error.retryAfterMs > 0
            ? error.retryAfterMs
            : defaultOutputRetry
      }
      const data = current.state.data as { outputStored?: boolean } | undefined
      if (!data) return false
      return data.outputStored ? false : pollInterval
    },
  })
  // OUTPUT_PENDING is retried; it is a wait state, not a failure.
  const awaitingStorage =
    query.error instanceof ApiError && query.error.reason === 'OUTPUT_PENDING'
  const bytes = query.data
    ? Uint8Array.from(atob(query.data.data), (c) => c.charCodeAt(0))
    : new Uint8Array()
  const combined = new Uint8Array([...previous, ...bytes])
  const text = new TextDecoder().decode(combined, { stream: !query.data?.eof })

  return (
    <div hidden={hidden} className="flex min-w-0 flex-col gap-2.5">
      <h4 className="sr-only">
        {t(stream === 'OUTPUT_STREAM_STDOUT' ? 'job.stdout' : 'job.stderr')}
      </h4>
      <QueryState
        pending={query.isPending || awaitingStorage}
        error={awaitingStorage ? null : query.error}
      />
      <pre className="max-h-80 overflow-auto rounded-lg bg-zinc-950 p-3 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap text-zinc-200 ring-1 ring-zinc-800 dark:bg-black">
        {text || t('common.none')}
      </pre>
      <div className="flex items-center gap-2.5">
        {query.data && !query.data.eof && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setPrevious(combined)
              setOffset(query.data.nextOffset)
            }}
          >
            {t('job.loadMore')}
          </Button>
        )}
        {query.data?.eof && (
          <small className="text-xs text-muted-foreground">
            {t('job.outputEnd')}
          </small>
        )}
      </div>
    </div>
  )
}
