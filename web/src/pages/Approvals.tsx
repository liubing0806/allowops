import { useEffect, useState, type ReactNode } from 'react'
import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query'
import { Code } from '@connectrpc/connect'
import { CopyIcon, RefreshCwIcon, ShieldCheckIcon } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import {
  api,
  ApiError,
  approvalStatuses,
  formatApprovalRoleSets,
  fromBase64,
  type ApprovalRequest,
  type ApprovalStatus,
} from '@/api'
import {
  ConfirmDialog,
  Field,
  MonoId,
  PageTitle,
  PagerFooter,
  QueryState,
  Status,
  Time,
} from '@/components/console/common'
import { StatusDot } from '@/components/console/StatusDot'
import { softTone } from '@/components/console/tone'
import { UntrustedBanner } from '@/components/console/UntrustedBanner'
import { useCopy } from '@/components/console/useCopy'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { NativeSelect } from '@/components/ui/native-select'
import { Textarea } from '@/components/ui/textarea'
import { useCommand } from '@/lib/notifications'
import { relativeTime } from '@/lib/time'
import { cn } from '@/lib/utils'

const pendingStatus = 'APPROVAL_STATUS_PENDING'
const pollInterval = 5000
const literalText = 'whitespace-pre-wrap [overflow-wrap:anywhere]'
const panel = 'min-w-0 space-y-3 rounded-xl border bg-card px-4 py-3.5'
const evidenceJobId = /^job-[0-9]{8}-[0-9]{1,20}$/
const notifyStatuses = ['skipped', 'sent', 'partial_failed', 'failed']

function stopsPolling(error: Error | null) {
  return error instanceof ApiError &&
    (error.code === Code.PermissionDenied ||
      error.code === Code.Unauthenticated ||
      error.code === Code.NotFound)
}

interface QueueFilters {
  status: ApprovalStatus | ''
  action: string
  onlyActionable: boolean
}

export default function Approvals() {
  const { approvalId } = useParams()
  const { t } = useTranslation()
  const client = useQueryClient()
  const [filters, setFilters] = useState<QueueFilters>({
    status: pendingStatus,
    action: '',
    onlyActionable: false,
  })
  const [tokens, setTokens] = useState([''])
  const filter = (patch: Partial<QueueFilters>) => {
    setFilters({ ...filters, ...patch })
    setTokens([''])
  }
  const [now, setNow] = useState(Date.now)
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), pollInterval)
    return () => window.clearInterval(timer)
  }, [])

  const { status, action, onlyActionable } = filters
  const pageToken = tokens[tokens.length - 1]
  const queue = useQuery({
    queryKey: ['approvals', filters, pageToken],
    queryFn: () => api.listApprovals({
      statuses: status ? [status] : [],
      action: action.trim(),
      onlyActionable,
      page: { pageSize: 10, pageToken },
    }),
    placeholderData: keepPreviousData,
    refetchInterval: ({ state }) =>
      !stopsPolling(state.error) && (!status || status === pendingStatus || onlyActionable)
        ? pollInterval
        : false,
  })
  const nextPageToken = queue.data?.page.nextPageToken

  return (
    <>
      <PageTitle
        title={t('nav.approvals')}
        description={t('approvals.description')}
        action={
          <Button
            variant="outline"
            size="sm"
            disabled={queue.isFetching}
            onClick={() => {
              void queue.refetch()
              if (approvalId) void client.invalidateQueries({ queryKey: ['approval', approvalId] })
            }}
          >
            <RefreshCwIcon aria-hidden="true" />
            {t('approvals.refresh')}
          </Button>
        }
      />
      <div className="flex flex-wrap items-end gap-3">
        <Field label={t('approvals.status')}>
          <NativeSelect
            value={status}
            onChange={(event) => filter({ status: event.target.value as QueueFilters['status'] })}
          >
            <option value="">{t('host.all')}</option>
            {approvalStatuses.map((value) => (
              <option key={value} value={value}>{t(`status.${value}`)}</option>
            ))}
          </NativeSelect>
        </Field>
        <Field label={t('job.action')}>
          <Input
            value={action}
            onChange={(event) => filter({ action: event.target.value })}
            placeholder={t('job.actionPlaceholder')}
            className="font-mono"
          />
        </Field>
        <label className="flex h-9 items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={onlyActionable}
            onChange={(event) => filter({ onlyActionable: event.target.checked })}
            className="accent-primary"
          />
          {t('approvals.onlyActionable')}
        </label>
      </div>
      <div className="flex flex-wrap items-start gap-4">
        <section
          aria-label={t('approvals.queue')}
          className={cn(
            'max-w-full min-w-0 flex-[1_1_340px] overflow-hidden rounded-xl border bg-card',
            approvalId && 'order-2 md:order-none',
          )}
        >
          {(queue.error || queue.isPending) && (
            <div className="p-3.5">
              <QueryState pending={queue.isPending} error={queue.error} />
            </div>
          )}
          {!queue.error && queue.data && (
            <>
              <ul>
                {queue.data.approvals.map((approval) => (
                  <ApprovalRow key={approval.approvalId} approval={approval}
                    selected={approval.approvalId === approvalId} now={now} />
                ))}
              </ul>
              {!queue.data.approvals.length && (
                <p className="px-4 py-8 text-center text-sm text-muted-foreground">
                  {t('approvals.empty')}
                </p>
              )}
              {(tokens.length > 1 || !!nextPageToken) && (
                <div className="px-3.5 py-2.5">
                  <PagerFooter
                    label={t('common.page', { page: tokens.length })}
                    canPrevious={tokens.length > 1 && !queue.isPlaceholderData}
                    canNext={!!nextPageToken && !queue.isPlaceholderData}
                    onPrevious={() => setTokens(tokens.slice(0, -1))}
                    onNext={() => nextPageToken && setTokens([...tokens, nextPageToken])}
                  />
                </div>
              )}
            </>
          )}
        </section>
        <section
          aria-label={t('approvals.detail')}
          className={cn(
            'flex min-w-0 flex-[999_1_560px] flex-col gap-3.5',
            approvalId && 'order-1 md:order-none',
          )}
        >
          {approvalId ? <ApprovalDetail key={approvalId} approvalId={approvalId} now={now} /> : (
            <p className="rounded-xl border border-dashed px-4 py-10 text-center text-sm text-muted-foreground">
              {t('approvals.pick')}
            </p>
          )}
        </section>
      </div>
    </>
  )
}

function RiskBadge({ risk }: { risk: string }) {
  const { t } = useTranslation()
  const tone = risk === 'dangerous' ? 'destructive' : risk === 'write' ? 'warning' : 'neutral'
  return (
    <span className={cn('rounded-full px-2 py-px text-xs font-medium', softTone[tone])}>
      {risk === 'read' || risk === 'write' || risk === 'dangerous' ? t(`risk.${risk}`) : risk || t('common.none')}
    </span>
  )
}

function ApprovalTime({ approval, now }: { approval: ApprovalRequest; now: number }) {
  const { t, i18n } = useTranslation()
  if (approval.status !== pendingStatus) {
    return <>{t('approvals.decidedAt')} <Time value={approval.decidedAt} /></>
  }
  if (!approval.expiresAt) return null
  const expired = Date.parse(approval.expiresAt) <= now
  return (
    <span title={approval.expiresAt}>
      {expired
        ? t('approvals.deadlinePassed')
        : t('approvals.expiresIn', {
            time: relativeTime(approval.expiresAt, i18n.language, t('approvals.soon'), now),
          })}
    </span>
  )
}

function ApprovalRow({
  approval,
  selected,
  now,
}: {
  approval: ApprovalRequest
  selected: boolean
  now: number
}) {
  return (
    <li className="border-b border-border-subtle last:border-b-0">
      <Link
        to={`/approvals/${encodeURIComponent(approval.approvalId)}`}
        aria-label={approval.approvalId}
        aria-current={selected ? 'page' : undefined}
        className={cn(
          'flex flex-col gap-1.5 px-3.5 py-3 text-foreground hover:bg-muted/60 hover:no-underline',
          selected && 'bg-selection shadow-[inset_2px_0_0_var(--primary)] hover:bg-selection',
        )}
      >
        <span className="flex flex-wrap items-center gap-2">
          <Status value={approval.status} />
          <RiskBadge risk={approval.actionRisk} />
          <span className="ml-auto font-mono text-xs">{approval.approvedCount}/{approval.minApprovals}</span>
        </span>
        <span className="break-all font-mono text-sm font-medium">{approval.action}</span>
        <span className="flex flex-wrap gap-x-2 gap-y-0.5 break-all font-mono text-xs text-foreground-2">
          <span>{approval.approvalId}</span>
          <span>{approval.requesterSubjectId} ({approval.requesterKind})</span>
          <span>{approval.jobId}</span>
        </span>
        <span className="text-xs text-muted-foreground">
          <ApprovalTime approval={approval} now={now} />
        </span>
      </Link>
    </li>
  )
}

function ApprovalDetail({ approvalId, now }: { approvalId: string; now: number }) {
  const { t } = useTranslation()
  const query = useQuery({
    queryKey: ['approval', approvalId],
    queryFn: () => api.getApproval({ approvalId }),
    refetchInterval: ({ state }) =>
      !stopsPolling(state.error) && state.data?.approval.status === pendingStatus
        ? pollInterval
        : false,
  })
  const approval = query.data?.approval
  if (query.error || !approval) {
    return <QueryState pending={query.isPending} error={query.error} />
  }
  return (
    <>
      <article className={panel}>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <h2 className="min-w-0 flex-1 break-all font-mono text-base font-medium">{approval.approvalId}</h2>
          <Status value={approval.status} />
          <RiskBadge risk={approval.actionRisk} />
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>{t('approvals.progress', { approved: approval.approvedCount, required: approval.minApprovals })}</span>
          <ApprovalTime approval={approval} now={now} />
          <Link to={`/jobs/${encodeURIComponent(approval.jobId)}`} className="font-mono">
            {approval.jobId}
          </Link>
        </div>
        {approval.notifyStatus && (
          <p className={cn('text-xs text-foreground-2', literalText)}>
            {t('approvals.notification')}{' '}
            {notifyStatuses.includes(approval.notifyStatus)
              ? t(`approvals.notification.${approval.notifyStatus}`)
              : approval.notifyStatus}
            {approval.notifyError && <> · {approval.notifyError}</>}
          </p>
        )}
        {approval.status === 'APPROVAL_STATUS_EXECUTION_DENIED' && approval.recheckError && (
          <p className={cn('rounded-lg bg-destructive-soft px-3 py-2 text-sm text-destructive', literalText)}>
            {t('approvals.recheckError')} {approval.recheckError}
          </p>
        )}
        <ApprovalActions approval={approval} />
      </article>
      <ExecutionPlan approval={approval} />
      <RequesterContext approval={approval} />
      <DecisionHistory approval={approval} />
    </>
  )
}

function DetailField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0 space-y-0.5">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className={cn('text-sm', literalText)}>{children}</dd>
    </div>
  )
}

function Digest({ label, value }: { label: string; value: string }) {
  const { t } = useTranslation()
  const { copy, copied } = useCopy()
  return (
    <DetailField label={label}>
      <span className="flex min-w-0 items-center gap-1.5">
        <MonoId value={value} className="hash" />
        <Button variant="ghost" size="icon-xs" type="button"
          aria-label={t('common.copyNamed', { name: label })} onClick={() => void copy(value)}>
          <CopyIcon aria-hidden="true" />
        </Button>
        {copied && <span role="status" className="text-xs text-muted-foreground">{t('common.copied')}</span>}
      </span>
    </DetailField>
  )
}

function ExecutionPlan({ approval }: { approval: ApprovalRequest }) {
  const { t } = useTranslation()
  // Host presence is current inventory data. The request determines the list and order.
  const inventory = useQuery({
    queryKey: ['hostOptions'],
    queryFn: () => api.listHosts(),
    enabled: approval.targets.length > 0,
    retry: false,
  })
  const hostsById = new Map(inventory.data?.hosts.map((host) => [host.hostId, host.online]))
  const roleSets = formatApprovalRoleSets(approval.requiredApproverRoleSets)

  return (
    <section aria-label={t('approvals.plan')} className={panel}>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold">{t('approvals.plan')}</h3>
        <span className="inline-flex items-center gap-1 rounded-full bg-success-soft px-2 py-px text-xs text-success">
          <ShieldCheckIcon className="size-3.5" aria-hidden="true" />
          {t('approvals.verified')}
        </span>
      </div>
      <dl className="grid grid-cols-[repeat(auto-fit,minmax(165px,1fr))] gap-x-4 gap-y-3">
        <DetailField label={t('job.action')}>{approval.action}</DetailField>
        <DetailField label={t('approvals.risk')}><RiskBadge risk={approval.actionRisk} /></DetailField>
        <DetailField label={t('nav.catalog')}>
          {approval.catalog ? `${approval.catalog.catalogId}@${approval.catalog.version}` : t('common.none')}
        </DetailField>
        <DetailField label={t('policy.historyVersion')}>{approval.policyVersion}</DetailField>
        <Digest label={t('approvals.actionDigest')} value={approval.actionSha256} />
        <Digest label={t('approvals.requestDigest')} value={approval.requestDigest} />
        <DetailField label={t('approvals.requester')}>
          {approval.requesterSubjectId} ({approval.requesterKind})
        </DetailField>
        {approval.requesterKind === 'service_account' && approval.requesterOwnerId && (
          <DetailField label={t('approvals.requesterOwner')}>{approval.requesterOwnerId}</DetailField>
        )}
        <DetailField label={t('approvals.batchSize')}>{approval.batchSize}</DetailField>
        <DetailField label={t('approvals.maxFailures')}>{approval.maxFailures}</DetailField>
        <DetailField label={t('policy.approvalMin')}>{approval.minApprovals}</DetailField>
        <DetailField label={t('policy.approvalOwner')}>
          {t(approval.allowOwnerApprove ? 'policy.yes' : 'policy.no')}
        </DetailField>
        <DetailField label={t('policy.approvalRoleSets')}>{roleSets || t('common.none')}</DetailField>
        {approval.targetSelector && (
          <DetailField label={t('policy.targetSelector')}>{approval.targetSelector}</DetailField>
        )}
      </dl>
      <div className="space-y-1.5">
        <h4 className="text-xs font-medium">{t('approvals.targets', { count: approval.targets.length })}</h4>
        <ol className="divide-y divide-border-subtle rounded-lg border">
          {approval.targets.map((target) => {
            const online = hostsById.get(target.hostId)
            return (
              <li key={target.hostId} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-2.5 py-1.5 text-xs">
                <span className="min-w-0 break-all font-mono">{target.hostname}</span>
                <span className="min-w-0 break-all font-mono text-muted-foreground">{target.hostId}</span>
                <span className="ml-auto inline-flex items-center gap-1.5 text-muted-foreground">
                  <StatusDot size={6} tone={online ? 'success' : 'neutral'} />
                  {t(online === undefined ? 'approvals.presenceUnknown' : online ? 'host.online' : 'host.offline')}
                </span>
              </li>
            )
          })}
        </ol>
      </div>
      <dl className="grid grid-cols-[repeat(auto-fit,minmax(165px,1fr))] gap-3">
        <DetailField label={t('approvals.params')}>
          <pre className={cn('rounded bg-muted px-2 py-1.5 text-xs', literalText)}>
            {fromBase64(approval.paramsJson) || t('common.none')}
          </pre>
        </DetailField>
        <DetailField label={t('approvals.filters')}>
          <pre className={cn('rounded bg-muted px-2 py-1.5 text-xs', literalText)}>
            {fromBase64(approval.filtersJson) || t('common.none')}
          </pre>
        </DetailField>
      </dl>
    </section>
  )
}

function RequesterContext({ approval }: { approval: ApprovalRequest }) {
  const { t } = useTranslation()
  const evidence = approval.evidence
  return (
    <section aria-label={t('approvals.context')} className={panel}>
      <h3 className="text-sm font-semibold">{t('approvals.context')}</h3>
      <UntrustedBanner>
        {t(approval.contextTrust === 'OUTPUT_TRUST_UNTRUSTED'
          ? 'approvals.untrusted'
          : 'approvals.unverifiedContext')}
      </UntrustedBanner>
      <dl className="space-y-2">
        <DetailField label={t('approvals.reason')}>
          <span>{approval.reason || t('common.none')}</span>
        </DetailField>
        {evidence?.summary && (
          <DetailField label={t('approvals.evidenceSummary')}>
            <span>{evidence.summary}</span>
          </DetailField>
        )}
        {!!evidence?.jobIds.length && (
          <DetailField label={t('approvals.evidenceJobs')}>
            <ul className="flex flex-wrap gap-x-3 gap-y-1">
              {evidence.jobIds.map((id) => (
                <li key={id} className="font-mono">
                  {evidenceJobId.test(id) ? <Link to={`/jobs/${id}`}>{id}</Link> : id}
                </li>
              ))}
            </ul>
          </DetailField>
        )}
      </dl>
    </section>
  )
}

function DecisionHistory({ approval }: { approval: ApprovalRequest }) {
  const { t } = useTranslation()
  return (
    <section aria-label={t('approvals.history')} className={panel}>
      <h3 className="text-sm font-semibold">{t('approvals.history')}</h3>
      {(approval.decisions.length > 0 || approval.decisionReason) && (
        <UntrustedBanner>{t('approvals.untrustedDecisions')}</UntrustedBanner>
      )}
      {approval.decisionReason && (
        <p className={cn('text-sm text-foreground-2', literalText)}>{approval.decisionReason}</p>
      )}
      {approval.decisions.length ? (
        <ol className="divide-y divide-border-subtle">
          {approval.decisions.map((decision) => (
            <li key={decision.actorId} className="space-y-1.5 py-2">
              <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <Status value={decision.vote} />
                <span className="break-all font-mono text-xs">{decision.actorId}</span>
                <span className="break-all text-xs text-muted-foreground">{decision.actorEmail}</span>
                <span className="ml-auto text-xs text-muted-foreground"><Time value={decision.decidedAt} /></span>
              </div>
              {decision.reason && <p className={cn('text-sm text-foreground-2', literalText)}>{decision.reason}</p>}
            </li>
          ))}
        </ol>
      ) : (
        <p className="text-sm text-muted-foreground">{t('approvals.noDecisions')}</p>
      )}
    </section>
  )
}

const cannotApproveKeys: Record<string, string> = {
  HUMAN_APPROVER_REQUIRED: 'human',
  SELF_APPROVAL_FORBIDDEN: 'self',
  SO_D_SELF_APPROVAL: 'self',
  SO_D_OWNER_APPROVAL: 'owner',
  SO_D_SAME_PERSON: 'samePerson',
  ALREADY_VOTED: 'voted',
  ALREADY_APPROVED_BY_ACTOR: 'voted',
  ROLE_MISMATCH: 'roles',
  APPROVER_ROLES_REQUIRED: 'roles',
  NO_APPROVE_PERMISSION: 'permission',
  APPROVE_JOBS_DENIED: 'permission',
  APPROVAL_EXPIRED: 'expired',
  APPROVAL_NOT_PENDING: 'notPending',
}

function cannotApproveKey(reason: string) {
  return `cannotApproveReason.${Object.hasOwn(cannotApproveKeys, reason) ? cannotApproveKeys[reason] : 'unknown'}`
}

type Operation = 'approve' | 'reject' | 'withdraw'

function ApprovalActions({ approval }: { approval: ApprovalRequest }) {
  const { t } = useTranslation()
  const client = useQueryClient()
  const session = useQuery({ queryKey: ['session'], queryFn: () => api.getCurrentSession() })
  const [dialog, setDialog] = useState<{ operation: Operation; snapshot: ApprovalRequest } | null>(null)
  const [reason, setReason] = useState('')
  const open = (operation: Operation) => {
    setReason('')
    setDialog({ operation, snapshot: approval })
  }
  const command = useCommand(async () => {
    if (!dialog) return
    const { operation, snapshot } = dialog
    const { approvalId } = snapshot
    try {
      if (operation === 'approve') {
        await api.approveRequest({ approvalId, expectedRequestDigest: snapshot.requestDigest, reason })
      } else if (operation === 'reject') {
        await api.rejectRequest({ approvalId, reason })
      } else {
        await api.cancelApproval({ approvalId })
      }
      setDialog(null)
    } catch (error) {
      void client.invalidateQueries({ queryKey: ['approvals'] })
      void client.invalidateQueries({ queryKey: ['approval', approvalId] })
      void client.invalidateQueries({ queryKey: ['job', snapshot.jobId] })
      void client.invalidateQueries({ queryKey: ['jobs'] })
      if (error instanceof ApiError && error.reason) {
        if (error.reason === 'APPROVAL_DIGEST_MISMATCH') {
          setDialog(null)
          throw new ApiError('approvals.digestMismatch', error.code, error.reason)
        }
        if (Object.hasOwn(cannotApproveKeys, error.reason)) {
          setDialog(null)
          throw new ApiError(cannotApproveKey(error.reason), error.code, error.reason)
        }
      }
      throw error
    }
  }, dialog ? `approvals.${dialog.operation}Success` : undefined)

  const pending = approval.status === pendingStatus
  const canDecide = pending && approval.canApprove === true
  const isRequester = session.data?.user.userId === approval.requesterSubjectId
  const withdrawLabel = isRequester ? 'approvals.withdraw' : 'approvals.cancel'
  const label = (operation: Operation) => operation === 'withdraw' ? withdrawLabel : `approvals.${operation}`

  return (
    <>
      {pending && (
        <div className="space-y-2 border-t border-border-subtle pt-3">
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" disabled={!canDecide || command.isPending} onClick={() => open('approve')}>
              {t('approvals.approve')}
            </Button>
            <Button size="sm" variant="outline" disabled={!canDecide || command.isPending} onClick={() => open('reject')}>
              {t('approvals.reject')}
            </Button>
            {/* The gateway evaluates cancel permission separately from vote eligibility. */}
            {session.data && (
              <Button size="sm" variant="outline" disabled={command.isPending} onClick={() => open('withdraw')}>
                {t(withdrawLabel)}
              </Button>
            )}
          </div>
          {!canDecide && <p className="text-xs text-muted-foreground">{t(cannotApproveKey(approval.cannotApproveReason))}</p>}
        </div>
      )}
      {dialog && (
        <ConfirmDialog
          title={t(label(dialog.operation))}
          description={t(dialog.operation === 'withdraw' ? 'approvals.withdrawConfirm' : 'approvals.decisionConfirm')}
          onClose={() => setDialog(null)}
          onConfirm={() => command.mutate()}
          pending={command.isPending}
          confirmDisabled={!pending || (dialog.operation !== 'withdraw' && !canDecide) ||
            (dialog.operation === 'reject' && !reason.trim())}
          confirmVariant={dialog.operation === 'approve' ? 'default' : 'destructive'}
        >
          <dl className="grid grid-cols-2 gap-2.5">
            <DetailField label={t('job.action')}>{dialog.snapshot.action}</DetailField>
            <DetailField label={t('approvals.targetCount')}>{dialog.snapshot.targets.length}</DetailField>
            {dialog.operation === 'approve' && (
              <div className="col-span-full">
                <DetailField label={t('approvals.requestDigest')}>
                  <code className="break-all text-xs">{dialog.snapshot.requestDigest}</code>
                </DetailField>
              </div>
            )}
          </dl>
          {dialog.operation !== 'withdraw' && (
            <Field label={t(dialog.operation === 'reject' ? 'approvals.rejectReason' : 'approvals.comment')}>
              <Textarea rows={3} maxLength={1024} value={reason} onChange={(event) => setReason(event.target.value)} />
            </Field>
          )}
          {!pending && <p className="text-sm text-warning">{t('cannotApproveReason.notPending')}</p>}
        </ConfirmDialog>
      )}
    </>
  )
}
