import { useEffect, useMemo, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Link2Icon } from 'lucide-react'
import {
  api,
  type AuditEvent,
  type AuditQuery,
  type VerifyAuditResponse,
} from '@/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  DataTable,
  PageTitle,
  QueryState,
  Time,
} from '@/components/console/common'
import { PanelSection, SidePanel } from '@/components/console/SidePanel'
import { softTone, type Tone } from '@/components/console/tone'
import { useCommand, useNotify } from '@/lib/notifications'
import { cn } from '@/lib/utils'

const schema = z
  .object({
    from: z.string(),
    to: z.string(),
    subjectId: z.string(),
    hostname: z.string(),
    action: z.string(),
  })
  .refine((v) => !v.from || !v.to || v.from < v.to, {
    message: 'error.timeRange',
    path: ['to'],
  })
const verifySchema = z.object({
  fromSeq: z.string().regex(/^[1-9]\d*$/, 'error.positiveInteger'),
  toSeq: z.string().regex(/^[1-9]\d*$/, 'error.positiveInteger'),
})

const decisionTone = (decision: string): Tone =>
  decision === 'allow'
    ? 'success'
    : decision === 'deny'
      ? 'destructive'
      : 'neutral'

const shortHash = (hash: string) =>
  hash.length > 8 ? `${hash.slice(0, 8)}…` : hash

const inputClass = 'h-[34px] font-mono text-xs'

export default function Audit() {
  const { t, i18n } = useTranslation()
  const notify = useNotify()
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: {
      from: '',
      to: '',
      subjectId: '',
      hostname: '',
      action: '',
    },
  })
  const verificationForm = useForm<z.infer<typeof verifySchema>>({
    resolver: zodResolver(verifySchema),
    defaultValues: { fromSeq: '1', toSeq: '' },
  })
  const [filter, setFilter] = useState<AuditQuery>({})
  const [result, setResult] = useState<VerifyAuditResponse | null>(null)
  const [verifyOpen, setVerifyOpen] = useState(false)
  const [selectedSeq, setSelectedSeq] = useState<string | null>(null)
  const query = useQuery({
    queryKey: ['audit', filter],
    queryFn: () => api.listAuditEvents({ query: filter }),
  })
  // The API returns events in ascending sequence order; the newest come first here.
  const events = useMemo(
    () => [...(query.data?.events ?? [])].reverse(),
    [query.data],
  )
  const bySeq = useMemo(
    () => new Map(events.map((event) => [event.seq, event])),
    [events],
  )
  const selected = selectedSeq ? bySeq.get(selectedSeq) : undefined
  const verification = useCommand(
    async (values: z.infer<typeof verifySchema>) => {
      const result = await api.verifyAudit(values)
      setResult(result)
      notify({
        key: result.valid ? 'audit.verified' : 'audit.invalid',
        values: { count: result.checkedCount },
        error: !result.valid,
      })
    },
  )
  // Default verification range: from the first event to the newest one loaded.
  const latest = events[0]?.seq
  useEffect(() => {
    if (latest && !verificationForm.getValues('toSeq'))
      verificationForm.setValue('toSeq', latest)
  }, [latest, verificationForm])
  const toggleVerify = () => {
    if (!verifyOpen) {
      verificationForm.reset({ fromSeq: '1', toSeq: latest ?? '' })
      setResult(null)
    }
    setVerifyOpen(!verifyOpen)
  }
  const formErrors = form.formState.errors
  const decisionText = (decision: string) =>
    t(`policy.${decision}`, { defaultValue: decision || t('common.none') })

  return (
    <div className="flex flex-col gap-3">
      <PageTitle
        title={t('nav.audit')}
        description={t('audit.description')}
        action={
          <Button aria-expanded={verifyOpen} onClick={toggleVerify}>
            <Link2Icon />
            {t('audit.verify')}
          </Button>
        }
      />
      {verifyOpen && (
        <section
          aria-label={t('audit.verify')}
          className="flex flex-col gap-2.5 rounded-xl border bg-card px-4 py-3.5"
        >
          <form
            noValidate
            className="flex flex-wrap items-end gap-2.5"
            onSubmit={verificationForm.handleSubmit((v) =>
              verification.mutate(v),
            )}
          >
            <label className="flex w-40 flex-col gap-1 text-xs text-muted-foreground">
              {t('audit.fromSeq')}
              <Input
                inputMode="numeric"
                className={inputClass}
                {...verificationForm.register('fromSeq')}
              />
              {verificationForm.formState.errors.fromSeq?.message && (
                <small role="alert" className="text-destructive">
                  {t(verificationForm.formState.errors.fromSeq.message)}
                </small>
              )}
            </label>
            <label className="flex w-40 flex-col gap-1 text-xs text-muted-foreground">
              {t('audit.toSeq')}
              <Input
                inputMode="numeric"
                className={inputClass}
                {...verificationForm.register('toSeq')}
              />
              {verificationForm.formState.errors.toSeq?.message && (
                <small role="alert" className="text-destructive">
                  {t(verificationForm.formState.errors.toSeq.message)}
                </small>
              )}
            </label>
            <Button className="h-[34px]" disabled={verification.isPending}>
              {t('audit.verifyStart')}
            </Button>
          </form>
          {result && (
            <div
              className={cn(
                'flex flex-col gap-0.5 rounded-[10px] px-3 py-2.5',
                softTone[result.valid ? 'success' : 'destructive'],
              )}
            >
              <strong className="font-semibold">
                {t(result.valid ? 'audit.verified' : 'audit.invalid', {
                  count: result.checkedCount,
                })}
              </strong>
              {!result.valid && result.firstInvalidSeq && (
                <span className="font-mono text-xs">
                  {t('audit.firstInvalid', { seq: result.firstInvalidSeq })}
                </span>
              )}
            </div>
          )}
          <p className="text-xs text-muted-foreground">
            {t('audit.internalOnly')}
          </p>
        </section>
      )}
      <section aria-label={t('audit.filters')}>
        <form
          noValidate
          className="flex flex-wrap items-start gap-2"
          onSubmit={form.handleSubmit((v) =>
            setFilter({
              time: {
                from: v.from ? new Date(v.from).toISOString() : undefined,
                to: v.to ? new Date(v.to).toISOString() : undefined,
              },
              subjectId: v.subjectId,
              hostname: v.hostname,
              action: v.action,
            }),
          )}
        >
          {/* B6 (decision filter: all / allow / deny) goes here once AuditQuery supports it. */}
          {(
            [
              ['subjectId', 'audit.subject'],
              ['hostname', 'audit.host'],
              ['action', 'audit.action'],
            ] as const
          ).map(([name, label]) => (
            <label key={name} className="block w-full sm:w-44">
              <span className="sr-only">{t(label)}</span>
              <Input
                placeholder={t(label)}
                className={cn(inputClass, 'bg-card')}
                {...form.register(name)}
              />
            </label>
          ))}
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
            {t('audit.from')}
            <Input
              type="datetime-local"
              className={cn(inputClass, 'w-auto bg-card')}
              {...form.register('from')}
            />
          </label>
          <label className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
            {t('audit.to')}
            <Input
              type="datetime-local"
              className={cn(inputClass, 'w-auto bg-card')}
              {...form.register('to')}
            />
            {formErrors.to?.message && (
              <small role="alert" className="w-full text-destructive">
                {t(formErrors.to.message)}
              </small>
            )}
          </label>
          <div className="flex gap-1.5">
            <Button className="h-[34px]">{t('common.query')}</Button>
            <Button
              type="button"
              variant="outline"
              className="h-[34px]"
              onClick={() => {
                form.reset()
                setFilter({})
              }}
            >
              {t('common.reset')}
            </Button>
          </div>
        </form>
      </section>
      <section
        aria-label={t('audit.events')}
        className="min-w-0 overflow-hidden rounded-xl border bg-card px-2 pb-2"
      >
        <QueryState pending={query.isPending} error={query.error} />
        {query.data && (
          <div className="overflow-x-auto">
            <DataTable<AuditEvent>
              data={events}
              pageSize={50}
              rowClassName={(event) =>
                event.seq === selectedSeq
                  ? 'bg-selection shadow-[inset_2px_0_0_var(--primary)] hover:bg-selection'
                  : undefined
              }
              columns={[
                {
                  accessorKey: 'seq',
                  header: t('audit.seq'),
                  enableSorting: false,
                  cell: ({ row }) => (
                    <button
                      type="button"
                      aria-label={t('audit.openDetail', {
                        seq: row.original.seq,
                      })}
                      aria-pressed={row.original.seq === selectedSeq}
                      onClick={() => setSelectedSeq(row.original.seq)}
                      className="font-mono text-primary underline-offset-4 hover:underline"
                    >
                      {row.original.seq}
                    </button>
                  ),
                },
                {
                  accessorKey: 'at',
                  header: t('audit.at'),
                  enableSorting: false,
                  cell: ({ row }) => (
                    <span className="font-mono text-xs whitespace-nowrap text-foreground-2">
                      <Time value={row.original.at} />
                    </span>
                  ),
                },
                {
                  accessorKey: 'subjectId',
                  header: t('audit.subject'),
                  enableSorting: false,
                  cell: ({ row }) => (
                    <span className="font-mono text-xs">
                      {row.original.subjectId}
                    </span>
                  ),
                },
                {
                  accessorKey: 'operation',
                  header: t('audit.operation'),
                  enableSorting: false,
                  cell: ({ row }) => (
                    <span className="font-mono text-xs text-foreground-2">
                      {row.original.operation}
                    </span>
                  ),
                },
                {
                  accessorKey: 'hostname',
                  header: t('audit.host'),
                  enableSorting: false,
                  cell: ({ row }) => (
                    <span className="font-mono text-xs">
                      {row.original.hostname}
                    </span>
                  ),
                },
                {
                  accessorKey: 'action',
                  header: t('audit.action'),
                  enableSorting: false,
                  cell: ({ row }) => (
                    <span className="font-mono text-xs">
                      {row.original.action}
                    </span>
                  ),
                },
                {
                  accessorKey: 'decision',
                  header: t('audit.decision'),
                  enableSorting: false,
                  cell: ({ row }) => (
                    <span
                      className={cn(
                        'rounded-full px-2 py-px text-xs whitespace-nowrap',
                        softTone[decisionTone(row.original.decision)],
                      )}
                    >
                      {decisionText(row.original.decision)}
                    </span>
                  ),
                },
                {
                  id: 'matchedRules',
                  header: t('policy.matched'),
                  cell: ({ row }) => (
                    <span
                      title={row.original.matchedRules.join(', ')}
                      className="inline-block max-w-48 truncate align-bottom font-mono text-[11px] text-foreground-2"
                    >
                      {row.original.matchedRules.join(', ') || '—'}
                    </span>
                  ),
                },
                {
                  accessorKey: 'hash',
                  header: t('audit.hash'),
                  enableSorting: false,
                  cell: ({ row }) => (
                    <code
                      title={row.original.hash}
                      className="font-mono text-[11px] text-muted-foreground"
                    >
                      {shortHash(row.original.hash)}
                    </code>
                  ),
                },
              ]}
            />
          </div>
        )}
      </section>
      {selected && (
        <AuditDetail
          key={selected.seq}
          event={selected}
          bySeq={bySeq}
          decisionText={decisionText}
          locale={i18n.language}
          onClose={() => setSelectedSeq(null)}
        />
      )}
    </div>
  )
}

function AuditDetail({
  event,
  bySeq,
  decisionText,
  locale,
  onClose,
}: {
  event: AuditEvent
  bySeq: Map<string, AuditEvent>
  decisionText: (decision: string) => string
  locale: string
  onClose: () => void
}) {
  const { t } = useTranslation()
  const seq = BigInt(event.seq)
  const previousSeq = seq > 1n ? String(seq - 1n) : undefined
  const nextSeq = String(seq + 1n)
  // Neighbours come from the loaded result. A previous event outside it is
  // still shown by the hash this event records for it.
  const chain: {
    seq: string
    prevHash?: string
    hash: string
    current?: boolean
    loaded: boolean
  }[] = []
  if (previousSeq) {
    const previous = bySeq.get(previousSeq)
    chain.push(
      previous
        ? { seq: previous.seq, prevHash: previous.prevHash, hash: previous.hash, loaded: true }
        : { seq: previousSeq, hash: event.prevHash, loaded: false },
    )
  }
  chain.push({
    seq: event.seq,
    prevHash: event.prevHash,
    hash: event.hash,
    current: true,
    loaded: true,
  })
  const next = bySeq.get(nextSeq)
  if (next)
    chain.push({ seq: next.seq, prevHash: next.prevHash, hash: next.hash, loaded: true })
  const tone = decisionTone(event.decision)
  const dash = (value: string) => value || '—'
  return (
    <SidePanel
      title={`#${event.seq}`}
      subtitle={
        <span>
          {new Intl.DateTimeFormat(locale, {
            dateStyle: 'medium',
            timeStyle: 'medium',
          }).format(new Date(event.at))}
        </span>
      }
      onClose={onClose}
    >
      <p className={cn('rounded-[10px] p-3 break-words', softTone[tone])}>
        <strong className="font-semibold">{decisionText(event.decision)}</strong>
        {' · '}
        <span className="font-mono">{dash(event.subjectId)}</span>{' '}
        {event.operation}{' '}
        {event.action && <span className="font-mono">{event.action}</span>}
        {event.hostname && (
          <>
            {' → '}
            <span className="font-mono">{event.hostname}</span>
          </>
        )}
      </p>
      <dl className="grid grid-cols-[76px_minmax(0,1fr)] gap-x-2.5 gap-y-1.5 text-xs">
        <dt className="text-muted-foreground">{t('policy.matched')}</dt>
        <dd className="font-mono break-all">
          {dash(event.matchedRules.join(', '))}
        </dd>
        <dt className="text-muted-foreground">{t('audit.policyVersion')}</dt>
        <dd className="font-mono">{dash(event.policyVersion)}</dd>
        <dt className="text-muted-foreground">Job</dt>
        <dd className="font-mono break-all">
          {event.jobId ? (
            <Link
              to={`/jobs/${event.jobId}`}
              className="text-primary underline-offset-4 hover:underline"
            >
              {event.jobId}
            </Link>
          ) : (
            '—'
          )}
        </dd>
        <dt className="text-muted-foreground">Task</dt>
        <dd className="font-mono break-all">{dash(event.taskId)}</dd>
        <dt className="text-muted-foreground">{t('audit.outputs')}</dt>
        <dd className="flex flex-col gap-1 font-mono break-all">
          {event.outputs.length
            ? event.outputs.map((output) => (
                <span key={`${output.objectPath}/${output.stream}/${output.stepIndex ?? ''}`}>
                  {output.objectPath}
                  <span className="text-muted-foreground">
                    {' · '}
                    {t(
                      output.stream === 'OUTPUT_STREAM_STDERR'
                        ? 'job.stderr'
                        : 'job.stdout',
                    )}
                    {output.stepIndex !== undefined &&
                      ` · ${t('audit.step', { step: output.stepIndex })}`}
                  </span>
                </span>
              ))
            : '—'}
        </dd>
      </dl>
      <PanelSection title={t('audit.chain')}>
        <ol className="flex flex-col">
          {chain.map((link, index) => (
            <li key={link.seq} className="flex flex-col items-stretch">
              <div
                aria-current={link.current ? 'true' : undefined}
                className={cn(
                  'flex flex-col gap-0.5 rounded-lg border px-2.5 py-2',
                  link.current ? 'border-primary bg-selection' : 'bg-card',
                )}
              >
                <span className="font-mono text-xs font-medium">
                  #{link.seq}
                  {!link.loaded && (
                    <span className="ml-2 font-sans font-normal text-muted-foreground">
                      {t('audit.notLoaded')}
                    </span>
                  )}
                </span>
                {link.prevHash !== undefined && (
                  <span className="font-mono text-[11px] break-all text-muted-foreground">
                    prev {link.prevHash}
                  </span>
                )}
                <span className="font-mono text-[11px] break-all text-foreground-2">
                  hash {link.hash}
                </span>
              </div>
              {index < chain.length - 1 && (
                <span aria-hidden="true" className="h-3.5 w-px self-center bg-border" />
              )}
            </li>
          ))}
        </ol>
        <p className="text-xs text-muted-foreground">{t('audit.chainHint')}</p>
      </PanelSection>
    </SidePanel>
  )
}
