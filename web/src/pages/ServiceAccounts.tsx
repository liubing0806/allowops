import { useId, useState } from 'react'
import { Controller, useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQueries, useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { BotIcon, InfoIcon, PlusIcon } from 'lucide-react'
import {
  api,
  type ServiceAccount,
  type ServiceAccountToken,
  type User,
} from '@/api'
import {
  ConfirmDialog,
  Field,
  PageTitle,
  Panel,
  QueryState,
  Time,
  TokenStatus,
} from '@/components/console/common'
import { CodeBlock } from '@/components/console/CodeBlock'
import { OnceSecretDialog } from '@/components/console/OnceSecretDialog'
import { PanelSection, SidePanel } from '@/components/console/SidePanel'
import { StatusDot } from '@/components/console/StatusDot'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { NativeSelect } from '@/components/ui/native-select'
import { requiredText } from '@/lib/forms'
import { useCommand } from '@/lib/notifications'
import { relativeTime } from '@/lib/time'
import { cn } from '@/lib/utils'

const schema = z.object({
  name: requiredText,
  ownerUserId: requiredText,
  description: z.string(),
  roles: z.array(z.string()).min(1, 'error.roles'),
})
const tokenSchema = z.object({
  validDays: z
    .number({ error: 'error.tokenTtl' })
    .int('error.tokenTtl')
    .min(1, 'error.tokenTtl')
    .max(365, 'error.tokenTtl'),
  description: z.string(),
})

const WEEK_MS = 7 * 86400000
// "Calling now" is polled; the gateway has no push channel for job starts.
const RUNNING_POLL_MS = 15000

const live = (token: ServiceAccountToken, now: number) =>
  !token.revokedAt && Date.parse(token.expiresAt) > now

export default function ServiceAccounts() {
  const { t } = useTranslation()
  const accounts = useQuery({
    queryKey: ['accounts'],
    queryFn: () => api.listServiceAccounts(),
  })
  const users = useQuery({
    queryKey: ['users'],
    queryFn: () => api.listUsers(),
  })
  const tokens = useQuery({
    queryKey: [
      'accountTokens',
      accounts.data?.accounts.map((a) => a.accountId),
    ],
    queryFn: async () =>
      (
        await Promise.all(
          accounts.data!.accounts.map((a) =>
            api.listServiceAccountTokens({ accountId: a.accountId }),
          ),
        )
      ).flatMap((r) => r.tokens),
    enabled: !!accounts.data,
  })
  const running = useQueries({
    queries: (accounts.data?.accounts ?? []).map((account) => ({
      queryKey: ['accountRunning', account.accountId],
      queryFn: () =>
        api.listJobs({
          statuses: ['JOB_STATUS_RUNNING'],
          subjectId: account.accountId,
          page: { pageSize: 1 },
        }),
      refetchInterval: RUNNING_POLL_MS,
    })),
  })
  const [creating, setCreating] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)
  const selectedAccount = accounts.data?.accounts.find(
    (a) => a.accountId === selected,
  )
  const [now] = useState(Date.now)

  return (
    <div className="flex flex-col gap-3.5">
      <PageTitle
        title={t('nav.accounts')}
        description={t('account.description')}
        action={
          <Button
            aria-expanded={creating}
            onClick={() => setCreating(!creating)}
          >
            <PlusIcon />
            {t('account.create')}
          </Button>
        }
      />
      <p
        role="note"
        className="flex items-center gap-2 rounded-[10px] bg-accent px-3.5 py-2.5 text-xs text-accent-foreground"
      >
        <InfoIcon aria-hidden="true" className="size-3.5 shrink-0" />
        {t('account.notice')}
      </p>
      {creating && (
        <CreateAccount
          users={users.data?.users ?? []}
          onDone={() => setCreating(false)}
        />
      )}
      <QueryState pending={accounts.isPending} error={accounts.error} />
      {accounts.data && (
        <section
          aria-label={t('nav.accounts')}
          className="grid grid-cols-[repeat(auto-fill,minmax(300px,1fr))] gap-3"
        >
          {accounts.data.accounts.map((account, index) => (
            <AccountCard
              key={account.accountId}
              account={account}
              owner={ownerName(users.data?.users, account.ownerUserId)}
              tokens={tokens.data?.filter(
                (token) => token.accountId === account.accountId,
              )}
              running={(running[index]?.data?.jobs.length ?? 0) > 0}
              active={account.accountId === selected}
              now={now}
              onOpen={() => setSelected(account.accountId)}
            />
          ))}
          {!accounts.data.accounts.length && (
            <p className="text-sm text-muted-foreground">{t('common.empty')}</p>
          )}
        </section>
      )}
      {selectedAccount && (
        <AccountPanel
          key={selectedAccount.accountId}
          account={selectedAccount}
          owner={ownerName(users.data?.users, selectedAccount.ownerUserId)}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  )
}

function ownerName(users: User[] | undefined, userId: string) {
  return users?.find((u) => u.userId === userId)?.username ?? userId
}

function CreateAccount({
  users,
  onDone,
}: {
  users: User[]
  onDone: () => void
}) {
  const { t } = useTranslation()
  const roles = useQuery({
    queryKey: ['roles'],
    queryFn: () => api.listRoles(),
  })
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: {
      name: '',
      ownerUserId: '',
      description: '',
      roles: ['auditor'],
    },
  })
  const creation = useCommand(async (values: z.infer<typeof schema>) => {
    await api.createServiceAccount({ ...values, teams: [] })
    form.reset()
    onDone()
  }, 'account.created')
  return (
    <Panel title={t('account.create')}>
      <form
        noValidate
        className="flex flex-col gap-3"
        onSubmit={form.handleSubmit((values) => creation.mutate(values))}
      >
        <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
          <Field
            label={t('common.name')}
            error={form.formState.errors.name?.message}
          >
            <Input className="font-mono" {...form.register('name')} />
          </Field>
          <Field label={t('common.description')}>
            <Input {...form.register('description')} />
          </Field>
          <Field
            label={t('account.owner')}
            error={form.formState.errors.ownerUserId?.message}
          >
            <NativeSelect {...form.register('ownerUserId')} className="w-full">
              <option value="">{t('common.none')}</option>
              {users.map((u) => (
                <option key={u.userId} value={u.userId}>
                  {u.username}
                </option>
              ))}
            </NativeSelect>
          </Field>
        </div>
        <Controller
          control={form.control}
          name="roles"
          render={({ field, fieldState }) => (
            <div className="flex flex-col gap-1.5">
              <span
                id="account-roles-label"
                className="text-xs font-medium text-muted-foreground"
              >
                {t('common.role')}
              </span>
              <div
                role="group"
                aria-labelledby="account-roles-label"
                className="flex flex-wrap gap-1.5"
              >
                {(roles.data?.roles ?? []).map((role) => {
                  const on = field.value.includes(role.name)
                  return (
                    <button
                      key={role.name}
                      type="button"
                      aria-pressed={on}
                      title={t(role.description)}
                      onClick={() =>
                        field.onChange(
                          on
                            ? field.value.filter((r) => r !== role.name)
                            : [...field.value, role.name],
                        )
                      }
                      className={cn(
                        'h-7 rounded-full border px-2.5 font-mono text-xs',
                        on
                          ? 'border-primary bg-accent text-accent-foreground'
                          : 'text-foreground-2 hover:bg-muted',
                      )}
                    >
                      {role.name}
                    </button>
                  )
                })}
              </div>
              {fieldState.error?.message && (
                <small role="alert" className="text-xs text-destructive">
                  {t(fieldState.error.message)}
                </small>
              )}
            </div>
          )}
        />
        <div className="flex gap-2">
          <Button disabled={creation.isPending}>{t('account.create')}</Button>
          <Button type="button" variant="outline" onClick={onDone}>
            {t('common.cancel')}
          </Button>
        </div>
      </form>
    </Panel>
  )
}

function AccountCard({
  account,
  owner,
  tokens,
  running,
  active,
  now,
  onOpen,
}: {
  account: ServiceAccount
  owner: string
  tokens?: ServiceAccountToken[]
  running: boolean
  active: boolean
  now: number
  onOpen: () => void
}) {
  const { t, i18n } = useTranslation()
  const details = useId()
  const valid = tokens?.filter((token) => live(token, now)) ?? []
  const expiring = valid.some(
    (token) => Date.parse(token.expiresAt) - now <= WEEK_MS,
  )
  const lastUsed = tokens
    ?.map((token) => token.lastUsedAt)
    .filter((value): value is string => !!value)
    .sort()
    .at(-1)
  return (
    <button
      type="button"
      onClick={onOpen}
      aria-label={t('account.manage', { name: account.name })}
      aria-describedby={details}
      aria-pressed={active}
      className={cn(
        'flex flex-col gap-2.5 rounded-xl border bg-card px-4 py-3.5 text-left hover:border-foreground/20',
        active &&
          'border-primary shadow-[0_0_0_3px_color-mix(in_oklab,var(--primary)_14%,transparent)] hover:border-primary',
      )}
    >
      <span className="flex w-full items-center gap-2.5">
        <span
          aria-hidden="true"
          className="grid size-8 shrink-0 place-items-center rounded-[9px] bg-accent text-accent-foreground"
        >
          <BotIcon className="size-4" />
        </span>
        <span className="flex min-w-0 flex-1 flex-col leading-tight">
          <span className="font-mono font-medium">{account.name}</span>
          <span className="truncate text-xs text-muted-foreground">
            {account.description ? t(account.description) : t('common.none')}
          </span>
        </span>
        {running && (
          <span className="flex items-center gap-1.5 text-xs text-info">
            <StatusDot tone="info" pulse />
            {t('account.running')}
          </span>
        )}
      </span>
      <span id={details} className="flex w-full flex-col gap-2.5">
        <span className="flex flex-wrap gap-1">
          {account.roles.map((role) => (
            <span
              key={role}
              className="rounded-full bg-muted px-1.5 py-px font-mono text-[11px] text-foreground-2"
            >
              {role}
            </span>
          ))}
        </span>
        {/* B3: 24h call count goes here once the gateway returns audit stats. */}
        <span className="grid w-full grid-cols-2 gap-1.5 text-xs">
          <span className="flex flex-col">
            <span className="text-[11px] text-muted-foreground">
              {t('account.validTokens')}
            </span>
            <span className="flex items-center gap-1.5">
              <span className="font-mono">{tokens ? valid.length : t('common.none')}</span>
              {expiring && (
                <span className="text-warning">{t('common.expiring')}</span>
              )}
            </span>
          </span>
          <span className="flex flex-col">
            <span className="text-[11px] text-muted-foreground">
              {t('token.lastUsed')}
            </span>
            <span>
              {lastUsed
                ? relativeTime(lastUsed, i18n.language, t('common.justNow'), now)
                : t('common.none')}
            </span>
          </span>
        </span>
        <span className="text-xs text-muted-foreground">
          {t('account.owner')}{' '}
          <span className="font-mono text-foreground-2">{owner}</span> ·{' '}
          {t('account.teams')}{' '}
          {account.teams.length ? account.teams.join(', ') : t('common.none')}
        </span>
      </span>
    </button>
  )
}

function AccountPanel({
  account,
  owner,
  onClose,
}: {
  account: ServiceAccount
  owner: string
  onClose: () => void
}) {
  const { t, i18n } = useTranslation()
  const query = useQuery({
    queryKey: ['tokens', account.accountId],
    queryFn: () =>
      api.listServiceAccountTokens({ accountId: account.accountId }),
  })
  const form = useForm<z.infer<typeof tokenSchema>>({
    resolver: zodResolver(tokenSchema),
    defaultValues: { validDays: 30, description: '' },
  })
  const [secret, setSecret] = useState<string | null>(null)
  const [revoking, setRevoking] = useState<ServiceAccountToken | null>(null)
  const [now] = useState(Date.now)
  const creation = useCommand(async (values: z.infer<typeof tokenSchema>) => {
    const result = await api.createServiceAccountToken({
      accountId: account.accountId,
      ...values,
    })
    setSecret(result.secret)
  })
  const revocation = useCommand(async () => {
    if (revoking) {
      await api.revokeServiceAccountToken({
        accountId: account.accountId,
        tokenId: revoking.tokenId,
      })
      setRevoking(null)
    }
  }, 'token.revoked')
  const date = (value?: string) =>
    value
      ? new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium' }).format(
          new Date(value),
        )
      : t('common.none')
  const mcp = JSON.stringify(
    {
      mcpServers: {
        allowops: {
          type: 'http',
          url: `${window.location.origin}/mcp`,
          headers: { Authorization: 'Bearer ${ALLOWOPS_MCP_TOKEN}' },
        },
      },
    },
    null,
    2,
  )

  return (
    <SidePanel
      title={account.name}
      subtitle={account.description ? t(account.description) : undefined}
      onClose={onClose}
      className="sm:w-[460px]"
    >
      <dl className="grid grid-cols-[70px_minmax(0,1fr)] gap-x-2.5 gap-y-1.5 text-xs">
        <dt className="text-muted-foreground">{t('account.owner')}</dt>
        <dd className="font-mono">{owner}</dd>
        <dt className="text-muted-foreground">{t('common.role')}</dt>
        <dd className="font-mono">{account.roles.join(', ')}</dd>
        <dt className="text-muted-foreground">{t('account.teams')}</dt>
        <dd className="font-mono">
          {account.teams.length ? account.teams.join(', ') : t('common.none')}
        </dd>
        <dt className="text-muted-foreground">{t('common.createdAt')}</dt>
        <dd>
          <Time value={account.createdAt} />
        </dd>
      </dl>
      {/* B5: "what this agent can do" summary goes here once the gateway returns it. */}
      <PanelSection title={t('account.tokens')}>
        <form
          noValidate
          className="flex flex-wrap items-end gap-2 rounded-[10px] border bg-background p-2.5"
          onSubmit={form.handleSubmit((values) => creation.mutate(values))}
        >
          <div className="min-w-40 flex-[2_1_160px]">
            <Field label={t('token.description')}>
              <Input {...form.register('description')} />
            </Field>
          </div>
          <div className="min-w-24 flex-[1_1_90px]">
            <Field
              label={t('account.ttl')}
              error={form.formState.errors.validDays?.message}
            >
              <Input
                type="number"
                min={1}
                max={365}
                className="font-mono"
                {...form.register('validDays', { valueAsNumber: true })}
              />
            </Field>
          </div>
          <Button disabled={creation.isPending}>{t('account.createToken')}</Button>
        </form>
        <QueryState pending={query.isPending} error={query.error} />
        {query.data && (
          <ul className="flex flex-col gap-1.5">
            {query.data.tokens.map((token) => (
              <li
                key={token.tokenId}
                className="flex flex-col gap-1 rounded-[10px] border bg-card px-3 py-2.5"
              >
                <span className="flex items-center gap-2">
                  <span className="truncate font-mono font-medium">
                    {token.tokenId}
                  </span>
                  <TokenStatus {...token} />
                  <span className="flex-1" />
                  {live(token, now) && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-destructive hover:bg-destructive-soft hover:text-destructive"
                      onClick={() => setRevoking(token)}
                    >
                      {t('common.revoke')}
                    </Button>
                  )}
                </span>
                {token.description && (
                  <span className="text-xs text-foreground-2">
                    {t(token.description)}
                  </span>
                )}
                <span className="text-[11px] text-muted-foreground">
                  {t('account.tokenMeta', {
                    created: date(token.createdAt),
                    expires: date(token.expiresAt),
                    used: token.lastUsedAt
                      ? relativeTime(
                          token.lastUsedAt,
                          i18n.language,
                          t('common.justNow'),
                          now,
                        )
                      : t('common.none'),
                  })}
                </span>
              </li>
            ))}
            {!query.data.tokens.length && (
              <li className="text-xs text-muted-foreground">{t('common.empty')}</li>
            )}
          </ul>
        )}
      </PanelSection>
      <PanelSection title={t('account.mcp')}>
        <CodeBlock code={mcp} label=".mcp.json" />
        <p className="text-[11px] text-muted-foreground">{t('account.mcpEnvHint')}</p>
      </PanelSection>
      {secret && (
        <OnceSecretDialog secret={secret} onClose={() => setSecret(null)}>
          <p className="text-xs text-muted-foreground">{t('account.exportHint')}</p>
          <CodeBlock
            code={`export ALLOWOPS_MCP_TOKEN='${secret}'`}
            label="ALLOWOPS_MCP_TOKEN"
          />
        </OnceSecretDialog>
      )}
      {revoking && (
        <ConfirmDialog
          title={t('token.revokeTitle')}
          description={t('token.revokeHint')}
          onClose={() => setRevoking(null)}
          onConfirm={() => revocation.mutate()}
          pending={revocation.isPending}
        />
      )}
    </SidePanel>
  )
}
