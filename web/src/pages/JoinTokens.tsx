import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Trash2Icon } from 'lucide-react'
import { api, type JoinToken } from '@/api'
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
import { positiveInteger } from '@/lib/forms'
import { useCommand } from '@/lib/notifications'

const schema = z.object({ maxUses: positiveInteger, ttlHours: positiveInteger })

export default function JoinTokens() {
  const { t } = useTranslation()
  const tokens = useQuery({
    queryKey: ['joinTokens'],
    queryFn: () => api.listJoinTokens(),
  })
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { maxUses: 1, ttlHours: 24 },
  })
  const [secret, setSecret] = useState<{
    value: string
    install: string
  } | null>(null)
  const [revoking, setRevoking] = useState<JoinToken | null>(null)
  const creation = useCommand(async (values: z.infer<typeof schema>) => {
    const result = await api.createJoinToken({
      maxUses: values.maxUses,
      ttl: `${values.ttlHours * 3600}s`,
    })
    setSecret({
      value: result.secret,
      install: `allowops-agent join --upstream ${result.upstream} --token-file /absolute/path/join-token.txt --ca-pin ${result.caPin}`,
    })
  })
  const revocation = useCommand(async () => {
    if (revoking) {
      await api.revokeJoinToken({ tokenId: revoking.tokenId })
      setRevoking(null)
    }
  }, 'token.revoked')

  return (
    <div className="flex flex-col gap-3">
      <PageTitle
        title={t('nav.joinTokens')}
        description={t('join.description')}
      />
      <Panel>
        <form
          noValidate
          className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3"
          onSubmit={form.handleSubmit((values) => creation.mutate(values))}
        >
          <Field
            label={t('join.uses')}
            error={form.formState.errors.maxUses?.message}
          >
            <Input
              type="number"
              min={1}
              {...form.register('maxUses', { valueAsNumber: true })}
            />
          </Field>
          <Field
            label={t('join.ttl')}
            error={form.formState.errors.ttlHours?.message}
          >
            <Input
              type="number"
              min={1}
              {...form.register('ttlHours', { valueAsNumber: true })}
            />
          </Field>
          <div className="flex items-end">
            <Button disabled={creation.isPending}>{t('join.create')}</Button>
          </div>
        </form>
      </Panel>
      <Panel>
        <QueryState pending={tokens.isPending} error={tokens.error} />
        {tokens.data && (
          <DataTable<JoinToken>
            data={tokens.data.tokens}
            columns={[
              {
                accessorKey: 'tokenId',
                header: t('common.name'),
                cell: ({ row }) => <MonoId value={row.original.tokenId} />,
              },
              { accessorKey: 'maxUses', header: t('join.uses') },
              { accessorKey: 'usedCount', header: t('join.used') },
              {
                accessorKey: 'expiresAt',
                header: t('common.expiresAt'),
                cell: ({ row }) => <Time value={row.original.expiresAt} />,
              },
              {
                id: 'status',
                header: t('common.status'),
                cell: ({ row }) => <TokenStatus {...row.original} />,
              },
              {
                id: 'actions',
                header: t('common.actions'),
                cell: ({ row }) => (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-muted-foreground hover:text-destructive"
                    disabled={!!row.original.revokedAt}
                    onClick={() => setRevoking(row.original)}
                  >
                    <Trash2Icon />
                    {t('common.revoke')}
                  </Button>
                ),
              },
            ]}
          />
        )}
      </Panel>
      {secret && (
        <SecretDialog
          secret={secret.value}
          install={secret.install}
          installHint={t('join.tokenFileHint')}
          onClose={() => setSecret(null)}
        />
      )}{' '}
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
