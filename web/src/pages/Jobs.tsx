import { useRef, useState } from 'react'
import { useForm, useWatch } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Code } from '@connectrpc/connect'
import { api, ApiError, type Job, type JobStatus, type Task } from '@/api'
import { jobStatuses } from '@/api/types'
import {
  ConfirmDialog,
  DataTable,
  Dialog,
  Field,
  MonoId,
  PageTitle,
  Panel,
  QueryState,
  Status,
  Time,
} from '@/components/console/common'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { NativeSelect } from '@/components/ui/native-select'
import { useCommand } from '@/lib/notifications'

const schema = z.object({ status: z.string(), action: z.string() })
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
const activeTaskStatuses = ['TASK_STATUS_PENDING', 'TASK_STATUS_RUNNING']

export default function Jobs() {
  const { t } = useTranslation()
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { status: '', action: '' },
  })
  const values = useWatch({ control: form.control })
  // tokens[i] opens page i + 1; the first page has no token. Changing a filter
  // starts again from the first page, because a token is bound to its filters.
  const filterKey = JSON.stringify(values)
  const [paging, setPaging] = useState({ filterKey, tokens: [''] })
  if (paging.filterKey !== filterKey) setPaging({ filterKey, tokens: [''] })
  const tokens = paging.filterKey === filterKey ? paging.tokens : ['']
  const pageToken = tokens[tokens.length - 1]
  const query = useQuery({
    queryKey: ['jobs', values, pageToken],
    queryFn: () =>
      api.listJobs({
        statuses: values.status ? [values.status as JobStatus] : [],
        action: values.action,
        page: { pageSize: jobsPageSize, pageToken },
      }),
    placeholderData: keepPreviousData,
  })
  const nextPageToken = query.data?.page.nextPageToken

  return (
    <div className="flex flex-col gap-3">
      <PageTitle title={t('nav.jobs')} description={t('job.description')} />
      <Panel>
        <form
          noValidate
          className="grid grid-cols-1 gap-3 sm:grid-cols-2"
          onSubmit={(event) => event.preventDefault()}
        >
          <Field label={t('job.status')}>
            <NativeSelect {...form.register('status')} className="w-full">
              <option value="">{t('host.all')}</option>
              {jobStatuses.map((status) => (
                <option key={status} value={status}>
                  {t(`status.${status}`)}
                </option>
              ))}
            </NativeSelect>
          </Field>
          <Field label={t('job.action')}>
            <Input {...form.register('action')} />
          </Field>
        </form>
      </Panel>
      <Panel>
        <QueryState pending={query.isPending} error={query.error} />
        {query.data && (
          <DataTable<Job>
            data={query.data.jobs}
            pager={{
              page: tokens.length,
              hasNext: !!nextPageToken,
              pending: query.isPlaceholderData,
              onPrevious: () =>
                setPaging({ filterKey, tokens: tokens.slice(0, -1) }),
              onNext: () =>
                nextPageToken &&
                setPaging({ filterKey, tokens: [...tokens, nextPageToken] }),
            }}
            columns={[
              {
                accessorKey: 'jobId',
                header: t('job.id'),
                cell: ({ row }) => (
                  <Link
                    to={`/jobs/${row.original.jobId}`}
                    className="font-medium text-primary underline-offset-4 hover:underline"
                  >
                    <MonoId value={row.original.jobId} />
                  </Link>
                ),
              },
              { accessorKey: 'action', header: t('job.action') },
              {
                accessorKey: 'subjectId',
                header: t('job.subject'),
                cell: ({ row }) => <MonoId value={row.original.subjectId} />,
              },
              {
                accessorKey: 'status',
                header: t('job.status'),
                cell: ({ row }) => <Status value={row.original.status} />,
              },
              { accessorKey: 'totalTasks', header: t('common.count') },
              {
                accessorKey: 'createdAt',
                header: t('common.createdAt'),
                cell: ({ row }) => <Time value={row.original.createdAt} />,
              },
            ]}
          />
        )}
      </Panel>
    </div>
  )
}

export function JobDetail() {
  const { jobId = '' } = useParams()
  const { t } = useTranslation()
  const query = useQuery({
    queryKey: ['job', jobId],
    queryFn: () => api.getJob({ jobId }),
    refetchInterval: (current) => {
      if (stopsPolling(current.state.error)) return false
      const status = (
        current.state.data as { job?: Job } | undefined
      )?.job?.status
      if (!status) return false
      return ['JOB_STATUS_QUEUED', 'JOB_STATUS_RUNNING'].includes(status)
        ? 2000
        : false
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
  const [host, setHost] = useState<string | null>(null)
  const [cancel, setCancel] = useState(false)
  const cancellation = useCommand(async () => {
    await api.cancelJob({ jobId })
    setCancel(false)
  }, 'job.cancelled')
  const job = query.data?.job
  // A34: the gateway evaluates view_output using the current ABAC policy.
  const canOutput = (status: string) =>
    !!session.data?.user &&
    !['TASK_STATUS_OFFLINE', 'TASK_STATUS_PENDING'].includes(status)

  return (
    <div className="flex flex-col gap-3">
      <Link
        to="/jobs"
        className="text-sm text-muted-foreground hover:text-foreground hover:no-underline"
      >
        {t('common.back')}
      </Link>
      <PageTitle
        title={jobId}
        action={
          job &&
          ['JOB_STATUS_QUEUED', 'JOB_STATUS_RUNNING'].includes(job.status) && (
            <Button variant="destructive" size="sm" onClick={() => setCancel(true)}>
              {t('job.cancel')}
            </Button>
          )
        }
      />
      <QueryState pending={query.isPending} error={query.error} />
      {job && (
        <Panel>
          <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
            <Status value={job.status} />
            <span>{t('job.summary', { count: job.totalTasks })}</span>
          </div>
          <dl className="grid grid-cols-[88px_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm">
            <dt className="text-muted-foreground">{t('job.action')}</dt>
            <dd className="min-w-0 break-words">{job.action}</dd>
            <dt className="text-muted-foreground">{t('job.subject')}</dt>
            <dd className="min-w-0">
              <MonoId value={job.subjectId} />
            </dd>
            <dt className="text-muted-foreground">{t('job.reason')}</dt>
            <dd className="min-w-0 break-words">{t(job.reason)}</dd>
            <dt className="text-muted-foreground">{t('host.catalogVersion')}</dt>
            <dd className="min-w-0 break-words">{job.catalog.version}</dd>
            <dt className="text-muted-foreground">{t('policy.historyVersion')}</dt>
            <dd className="min-w-0 break-words">{job.policyVersion}</dd>
          </dl>
        </Panel>
      )}
      <Panel title={t('job.tasks')}>
        <QueryState pending={tasks.isPending} error={tasks.error} />
        {tasks.data && (
          <DataTable<Task>
            data={tasks.data.tasks}
            columns={[
              { accessorKey: 'hostname', header: t('host.hostname') },
              {
                id: 'status',
                header: t('job.taskStatus'),
                cell: ({ row }) => (
                  <Status value={row.original.result.status} />
                ),
              },
              {
                id: 'exitCode',
                header: t('job.exitCode'),
                cell: ({ row }) =>
                  row.original.result.exitCode ?? t('common.none'),
              },
              {
                id: 'duration',
                header: t('job.duration'),
                cell: ({ row }) => row.original.result.duration,
              },
              {
                accessorKey: 'outputStored',
                header: t('job.outputStored'),
                cell: ({ row }) => (
                  <Badge variant="secondary">
                    {t(row.original.outputStored ? 'policy.yes' : 'policy.no')}
                  </Badge>
                ),
              },
              {
                id: 'output',
                header: t('common.actions'),
                cell: ({ row }) => (
                  <Button
                    variant="link"
                    size="sm"
                    className="h-auto p-0"
                    disabled={!canOutput(row.original.result.status)}
                    onClick={() => setHost(row.original.hostname)}
                  >
                    {t('job.output', { host: row.original.hostname })}
                  </Button>
                ),
              },
            ]}
          />
        )}
      </Panel>
      {cancel && (
        <ConfirmDialog
          title={t('job.cancelTitle')}
          description={t('job.cancelHint')}
          onClose={() => setCancel(false)}
          onConfirm={() => cancellation.mutate()}
          pending={cancellation.isPending}
        />
      )}{' '}
      {host && (
        <Dialog
          title={t('job.outputTitle', { host })}
          onClose={() => setHost(null)}
        >
          <p
            role="note"
            className="rounded-lg bg-secondary px-3 py-2 text-sm text-secondary-foreground"
          >
            {t('job.untrusted')}
          </p>
          <OutputStream
            jobId={jobId}
            hostname={host}
            stream="OUTPUT_STREAM_STDOUT"
          />
          <OutputStream
            jobId={jobId}
            hostname={host}
            stream="OUTPUT_STREAM_STDERR"
          />
        </Dialog>
      )}
    </div>
  )
}

function OutputStream({
  jobId,
  hostname,
  stream,
}: {
  jobId: string
  hostname: string
  stream: 'OUTPUT_STREAM_STDOUT' | 'OUTPUT_STREAM_STDERR'
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
    queryKey: ['output', jobId, hostname, stream, offset, limitBytes],
    queryFn: () =>
      api.getJobOutput({
        jobId,
        hostname,
        stream,
        offset,
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
    <section className="output flex min-w-0 flex-col gap-2">
      <h3 className="text-xs font-semibold text-muted-foreground">
        {t(stream === 'OUTPUT_STREAM_STDOUT' ? 'job.stdout' : 'job.stderr')}
      </h3>
      <QueryState
        pending={query.isPending || awaitingStorage}
        error={awaitingStorage ? null : query.error}
      />
      <pre className="overflow-x-auto rounded-lg bg-muted p-3 font-mono text-xs break-all whitespace-pre-wrap">
        {text || t('common.none')}
      </pre>
      {query.data && !query.data.eof && (
        <div>
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
        </div>
      )}
      {query.data?.eof && (
        <small className="text-xs text-muted-foreground">
          {t('job.outputEnd')}
        </small>
      )}
    </section>
  )
}
