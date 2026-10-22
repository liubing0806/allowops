import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { api, type ServiceAccount, type ServiceAccountToken } from '@/api'
import {
  ConfirmDialog,
  DataTable,
  Field,
  MonoId,
  PageTitle,
  Panel,
  QueryState,
  SecretDialog,
  Time,
  TokenStatus,
} from '@/components/console/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { NativeSelect } from '@/components/ui/native-select'
import { commaList, requiredText } from '@/lib/forms'
import { useCommand } from '@/lib/notifications'

const schema = z.object({
  name: requiredText,
  ownerUserId: requiredText,
  description: z.string(),
  roles: requiredText,
})
const tokenSchema = z.object({
  validDays: z
    .number({ error: 'error.tokenTtl' })
    .int('error.tokenTtl')
    .min(1, 'error.tokenTtl')
    .max(365, 'error.tokenTtl'),
  description: z.string(),
})

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
  const [creating, setCreating] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: {
      name: '',
      ownerUserId: '',
      description: '',
      roles: 'auditor',
    },
  })
  const creation = useCommand(async (values: z.infer<typeof schema>) => {
    await api.createServiceAccount({
      ...values,
      roles: commaList(values.roles),
      teams: [],
    })
    form.reset()
    setCreating(false)
  }, 'account.created')
  const selectedAccount = accounts.data?.accounts.find(
    (a) => a.accountId === selected,
  )

  return (
    <div className="flex flex-col gap-3">
      <PageTitle
        title={t('nav.accounts')}
        description={t('account.description')}
        action={
          <Button
            variant="outline"
            size="sm"
            onClick={() => setCreating(!creating)}
          >
            {t('account.create')}
          </Button>
        }
      />
      {creating && (
        <Panel title={t('account.create')}>
          <form
            noValidate
            className="grid grid-cols-1 gap-3 sm:grid-cols-2"
            onSubmit={form.handleSubmit((values) => creation.mutate(values))}
          >
            <Field
              label={t('common.name')}
              error={form.formState.errors.name?.message}
            >
              <Input {...form.register('name')} />
            </Field>
            <Field
              label={t('account.owner')}
              error={form.formState.errors.ownerUserId?.message}
            >
              <NativeSelect
                {...form.register('ownerUserId')}
                className="w-full"
              >
                <option value="">{t('common.none')}</option>
                {users.data?.users.map((u) => (
                  <option key={u.userId} value={u.userId}>
                    {u.username}
                  </option>
                ))}
              </NativeSelect>
            </Field>
            <Field label={t('common.description')}>
              <Input {...form.register('description')} />
            </Field>
            <Field
              label={t('policy.roles')}
              error={form.formState.errors.roles?.message}
            >
              <Input {...form.register('roles')} />
            </Field>
            <div className="sm:col-span-2">
              <Button size="sm" disabled={creation.isPending}>
                {t('account.create')}
              </Button>
            </div>
          </form>
        </Panel>
      )}
      <Panel>
        <QueryState pending={accounts.isPending} error={accounts.error} />
        {accounts.data && (
          <DataTable<ServiceAccount>
            data={accounts.data.accounts}
            columns={[
              { accessorKey: 'name', header: t('common.name') },
              {
                accessorKey: 'ownerUserId',
                header: t('account.owner'),
                cell: ({ row }) =>
                  users.data?.users.find(
                    (u) => u.userId === row.original.ownerUserId,
                  )?.username ?? (
                    <MonoId value={row.original.ownerUserId} />
                  ),
              },
              {
                id: 'roles',
                header: t('common.role'),
                cell: ({ row }) => row.original.roles.join(', '),
              },
              {
                accessorKey: 'description',
                header: t('common.description'),
                cell: ({ row }) => t(row.original.description),
              },
              {
                id: 'expiry',
                header: t('common.status'),
                cell: ({ row }) => {
                  const token = tokens.data?.find(
                    (token) =>
                      token.accountId === row.original.accountId &&
                      !token.revokedAt,
                  )
                  return token ? <TokenStatus {...token} /> : t('common.none')
                },
              },
              {
                id: 'manage',
                header: t('common.actions'),
                cell: ({ row }) => (
                  <Button
                    variant="link"
                    size="sm"
                    className="h-auto p-0"
                    onClick={() => setSelected(row.original.accountId)}
                  >
                    {t('account.manage', { name: row.original.name })}
                  </Button>
                ),
              },
            ]}
          />
        )}
      </Panel>
      {selectedAccount && (
        <AccountTokens
          key={selectedAccount.accountId}
          account={selectedAccount}
        />
      )}
      <Panel title={t('account.mcp')}>
        <p className="text-sm text-muted-foreground">{t('account.mcpHint')}</p>
        <pre className="overflow-x-auto rounded-lg bg-muted p-3 font-mono text-xs break-all whitespace-pre-wrap">
          {JSON.stringify(
            {
              mcpServers: {
                allowops: {
                  type: 'http',
                  url: 'https://gateway.example/mcp',
                  headers: { Authorization: 'Bearer <TOKEN>' },
                },
              },
            },
            null,
            2,
          )}
        </pre>
      </Panel>
    </div>
  )
}

function AccountTokens({ account }: { account: ServiceAccount }) {
  const { t } = useTranslation()
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

  return (
    <Panel title={t('account.manage', { name: account.name })}>
      <form
        noValidate
        className="grid grid-cols-1 gap-3 sm:grid-cols-2"
        onSubmit={form.handleSubmit((values) => creation.mutate(values))}
      >
        <Field
          label={t('account.ttl')}
          error={form.formState.errors.validDays?.message}
        >
          <Input
            type="number"
            min={1}
            max={365}
            {...form.register('validDays', { valueAsNumber: true })}
          />
        </Field>
        <Field label={t('token.description')}>
          <Input {...form.register('description')} />
        </Field>
        <div className="sm:col-span-2">
          <Button size="sm" disabled={creation.isPending}>
            {t('account.createToken')}
          </Button>
        </div>
      </form>
      <QueryState pending={query.isPending} error={query.error} />
      {query.data && (
        <DataTable<ServiceAccountToken>
          data={query.data.tokens}
          columns={[
            {
              accessorKey: 'tokenId',
              header: t('common.name'),
              cell: ({ row }) => <MonoId value={row.original.tokenId} />,
            },
            {
              accessorKey: 'description',
              header: t('token.description'),
              cell: ({ row }) => t(row.original.description),
            },
            {
              accessorKey: 'expiresAt',
              header: t('common.expiresAt'),
              cell: ({ row }) => <Time value={row.original.expiresAt} />,
            },
            {
              accessorKey: 'lastUsedAt',
              header: t('token.lastUsed'),
              cell: ({ row }) => <Time value={row.original.lastUsedAt} />,
            },
            {
              id: 'status',
              header: t('common.status'),
              cell: ({ row }) => <TokenStatus {...row.original} />,
            },
            {
              id: 'revoke',
              header: t('common.actions'),
              cell: ({ row }) => (
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-muted-foreground hover:text-destructive"
                  disabled={!!row.original.revokedAt}
                  onClick={() => setRevoking(row.original)}
                >
                  {t('common.revoke')}
                </Button>
              ),
            },
          ]}
        />
      )}{' '}
      {secret && (
        <SecretDialog secret={secret} onClose={() => setSecret(null)} />
      )}{' '}
      {revoking && (
        <ConfirmDialog
          title={t('token.revokeTitle')}
          description={t('token.revokeHint')}
          onClose={() => setRevoking(null)}
          onConfirm={() => revocation.mutate()}
          pending={revocation.isPending}
        />
      )}
    </Panel>
  )
}
