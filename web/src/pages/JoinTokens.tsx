import { useEffect, useState, type ReactNode } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { api, type CreateJoinTokenResponse, type JoinToken } from '@/api'
import {
  ConfirmDialog,
  DataTable,
  Field,
  PageTitle,
  QueryState,
  Time,
} from '@/components/console/common'
import { CodeBlock } from '@/components/console/CodeBlock'
import { OnceSecretDialog } from '@/components/console/OnceSecretDialog'
import { StatusDot } from '@/components/console/StatusDot'
import { textTone, type Tone } from '@/components/console/tone'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { positiveInteger } from '@/lib/forms'
import { useCommand } from '@/lib/notifications'
import { relativeTime } from '@/lib/time'
import { cn } from '@/lib/utils'

const schema = z.object({ maxUses: positiveInteger, ttlHours: positiveInteger })

// Join tokens live for hours, so the 7-day window used for service account
// tokens would mark every one of them as expiring.
const EXPIRING_MS = 4 * 3600000

type JoinState = 'active' | 'expiring' | 'exhausted' | 'expired' | 'revoked'

const stateKey: Record<JoinState, string> = {
  active: 'common.active',
  expiring: 'common.expiring',
  exhausted: 'join.exhausted',
  expired: 'common.expired',
  revoked: 'common.revoked',
}

const stateTone: Record<JoinState, Tone> = {
  active: 'success',
  expiring: 'warning',
  exhausted: 'neutral',
  expired: 'neutral',
  revoked: 'neutral',
}

// States and relative times move on without a refetch.
function useNow() {
  const [now, setNow] = useState(Date.now)
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 60000)
    return () => window.clearInterval(timer)
  }, [])
  return now
}

function joinState(token: JoinToken, now: number): JoinState {
  if (token.revokedAt) return 'revoked'
  const left = Date.parse(token.expiresAt) - now
  if (left <= 0) return 'expired'
  if (token.usedCount >= token.maxUses) return 'exhausted'
  return left <= EXPIRING_MS ? 'expiring' : 'active'
}

export default function JoinTokens() {
  const { t, i18n } = useTranslation()
  const tokens = useQuery({
    queryKey: ['joinTokens'],
    queryFn: () => api.listJoinTokens(),
  })
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { maxUses: 1, ttlHours: 24 },
  })
  const [created, setCreated] = useState<CreateJoinTokenResponse | null>(null)
  const [lastCreated, setLastCreated] = useState<string | null>(null)
  const [revoking, setRevoking] = useState<JoinToken | null>(null)
  const creation = useCommand(async (values: z.infer<typeof schema>) => {
    const result = await api.createJoinToken({
      maxUses: values.maxUses,
      ttl: `${values.ttlHours * 3600}s`,
    })
    setCreated(result)
    setLastCreated(result.token.tokenId)
  })
  const revocation = useCommand(async () => {
    if (revoking) {
      await api.revokeJoinToken({ tokenId: revoking.tokenId })
      setRevoking(null)
    }
  }, 'token.revoked')
  const now = useNow()
  const relative = (value: string) =>
    relativeTime(value, i18n.language, t('common.justNow'), now)

  return (
    <div className="flex flex-col gap-3.5">
      <PageTitle
        title={t('nav.joinTokens')}
        description={t('join.description')}
      />
      <section
        aria-labelledby="join-create-title"
        className="flex flex-col gap-3 rounded-2xl border bg-card px-[18px] py-4 shadow-[0_1px_2px_rgb(0_0_0/0.04),0_8px_24px_-12px_rgb(20_20_40/0.12)]"
      >
        <h2 id="join-create-title" className="text-sm font-semibold">
          {t('join.register')}
        </h2>
        <form
          noValidate
          className="flex flex-wrap items-end gap-2.5"
          onSubmit={form.handleSubmit((values) => creation.mutate(values))}
        >
          <div className="w-full sm:w-44">
            <Field
              label={t('join.uses')}
              error={form.formState.errors.maxUses?.message}
            >
              <Input
                type="number"
                min={1}
                className="font-mono"
                {...form.register('maxUses', { valueAsNumber: true })}
              />
            </Field>
          </div>
          <div className="w-full sm:w-44">
            <Field
              label={t('join.ttl')}
              error={form.formState.errors.ttlHours?.message}
            >
              <Input
                type="number"
                min={1}
                className="font-mono"
                {...form.register('ttlHours', { valueAsNumber: true })}
              />
            </Field>
          </div>
          <span className="hidden flex-1 sm:block" />
          <Button disabled={creation.isPending}>{t('join.create')}</Button>
        </form>
        <p className="text-xs text-muted-foreground">{t('join.defaultDeny')}</p>
      </section>
      <section
        aria-label={t('join.list')}
        className="min-w-0 overflow-hidden rounded-xl border bg-card"
      >
        <div className="px-4 py-1">
          <QueryState pending={tokens.isPending} error={tokens.error} />
        </div>
        {tokens.data && (
          <div className="overflow-x-auto px-2 pb-2">
            <DataTable<JoinToken>
              data={tokens.data.tokens}
              pageSize={20}
              rowClassName={(row) =>
                row.tokenId === lastCreated ? 'bg-selection' : undefined
              }
              columns={[
                {
                  accessorKey: 'tokenId',
                  header: 'Token',
                  cell: ({ row }) => (
                    <code
                      title={row.original.tokenId}
                      className="inline-block max-w-56 truncate align-bottom font-mono text-sm font-medium"
                    >
                      {row.original.tokenId}
                    </code>
                  ),
                },
                {
                  id: 'usage',
                  header: t('join.usage'),
                  cell: ({ row }) => (
                    <span className="font-mono text-xs">
                      {t('join.usageValue', {
                        used: row.original.usedCount,
                        max: row.original.maxUses,
                      })}
                    </span>
                  ),
                },
                {
                  accessorKey: 'createdAt',
                  header: t('common.createdAt'),
                  cell: ({ row }) => (
                    <span className="text-xs text-foreground-2">
                      <Time value={row.original.createdAt} />
                    </span>
                  ),
                },
                {
                  accessorKey: 'expiresAt',
                  header: t('common.expiresAt'),
                  cell: ({ row }) => {
                    const state = joinState(row.original, now)
                    return (
                      <span className="flex flex-col leading-tight">
                        <span className="text-xs">
                          <Time value={row.original.expiresAt} />
                        </span>
                        <span
                          className={cn(
                            'text-[11px]',
                            state === 'expiring'
                              ? 'text-warning'
                              : 'text-muted-foreground',
                          )}
                        >
                          {row.original.revokedAt
                            ? t('join.revokedAt', {
                                time: relative(row.original.revokedAt),
                              })
                            : relative(row.original.expiresAt)}
                        </span>
                      </span>
                    )
                  },
                },
                {
                  id: 'status',
                  header: t('common.status'),
                  cell: ({ row }) => (
                    <JoinStatus state={joinState(row.original, now)} />
                  ),
                },
                {
                  id: 'actions',
                  header: () => (
                    <span className="sr-only">{t('common.actions')}</span>
                  ),
                  cell: ({ row }) => {
                    const state = joinState(row.original, now)
                    return (
                      (state === 'active' || state === 'expiring') && (
                        <div className="flex justify-end">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-destructive hover:bg-destructive-soft hover:text-destructive"
                            onClick={() => setRevoking(row.original)}
                          >
                            {t('common.revoke')}
                          </Button>
                        </div>
                      )
                    )
                  },
                },
              ]}
            />
          </div>
        )}
      </section>
      {created && (
        <JoinSecretDialog created={created} onClose={() => setCreated(null)} />
      )}
      {revoking && (
        <ConfirmDialog
          title={t('join.revokeTitle')}
          description={t('join.revokeHint')}
          onClose={() => setRevoking(null)}
          onConfirm={() => revocation.mutate()}
          pending={revocation.isPending}
        />
      )}
    </div>
  )
}

function JoinStatus({ state }: { state: JoinState }) {
  const { t } = useTranslation()
  const tone = stateTone[state]
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 text-sm whitespace-nowrap',
        tone === 'neutral' ? 'text-foreground-2' : textTone[tone],
      )}
    >
      <StatusDot tone={tone} />
      {t(stateKey[state])}
    </span>
  )
}

// The secret appears only in the dialog's own block. The install command reads
// it from a file so it never lands in argv or shell history.
function JoinSecretDialog({
  created,
  onClose,
}: {
  created: CreateJoinTokenResponse
  onClose: () => void
}) {
  const { t } = useTranslation()
  const install = `allowops-agent join --upstream ${created.upstream} --token-file /absolute/path/join-token.txt --ca-pin ${created.caPin}`
  return (
    <OnceSecretDialog secret={created.secret} onClose={onClose}>
      <p className="font-mono text-xs text-muted-foreground">
        {created.token.tokenId} ·{' '}
        {t('join.secretMeta', { uses: created.token.maxUses })} ·{' '}
        <Time value={created.token.expiresAt} />
      </p>
      <ol className="flex flex-col gap-3">
        <Step n={1} title={t('join.stepSave')}>
          <p className="text-xs text-muted-foreground">
            {t('join.tokenFileHint')}
          </p>
        </Step>
        <Step n={2} title={t('join.install')}>
          <CodeBlock code={install} label={t('join.install')} />
        </Step>
        <Step n={3} title={t('join.stepLabels')}>
          <p className="text-xs text-muted-foreground">
            {t('join.stepLabelsHint')}
          </p>
        </Step>
      </ol>
    </OnceSecretDialog>
  )
}

function Step({
  n,
  title,
  children,
}: {
  n: number
  title: string
  children: ReactNode
}) {
  return (
    <li className="flex gap-3">
      <span
        aria-hidden="true"
        className="grid size-[22px] shrink-0 place-items-center rounded-full bg-accent text-xs font-semibold text-accent-foreground"
      >
        {n}
      </span>
      <div className="flex min-w-0 flex-1 flex-col gap-1.5">
        <h3 className="text-sm font-medium">{title}</h3>
        {children}
      </div>
    </li>
  )
}
