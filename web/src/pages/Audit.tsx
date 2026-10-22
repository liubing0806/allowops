import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  api,
  type AuditEvent,
  type AuditQuery,
  type VerifyAuditResponse,
} from '@/api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  DataTable,
  Field,
  MonoId,
  PageTitle,
  Panel,
  QueryState,
  Time,
} from '@/components/console/common'
import { useCommand, useNotify } from '@/lib/notifications'

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

export default function Audit() {
  const { t } = useTranslation()
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
    defaultValues: { fromSeq: '1', toSeq: '3' },
  })
  const [filter, setFilter] = useState<AuditQuery>({})
  const [result, setResult] = useState<VerifyAuditResponse | null>(null)
  const query = useQuery({
    queryKey: ['audit', filter],
    queryFn: () => api.listAuditEvents({ query: filter }),
  })
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

  return (
    <div className="flex flex-col gap-3">
      <PageTitle title={t('nav.audit')} description={t('audit.description')} />
      <Panel>
        <form
          noValidate
          className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3"
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
          <Field label={t('audit.from')}>
            <Input type="datetime-local" {...form.register('from')} />
          </Field>
          <Field
            label={t('audit.to')}
            error={form.formState.errors.to?.message}
          >
            <Input type="datetime-local" {...form.register('to')} />
          </Field>
          <Field label={t('audit.subject')}>
            <Input {...form.register('subjectId')} />
          </Field>
          <Field label={t('audit.host')}>
            <Input {...form.register('hostname')} />
          </Field>
          <Field label={t('audit.action')}>
            <Input {...form.register('action')} />
          </Field>
          <div className="flex items-end gap-2 sm:col-span-2 lg:col-span-3">
            <Button size="sm">{t('common.query')}</Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                form.reset()
                setFilter({})
              }}
            >
              {t('common.reset')}
            </Button>
          </div>
        </form>
      </Panel>
      <Panel>
        <QueryState pending={query.isPending} error={query.error} />
        {query.data && (
          <DataTable<AuditEvent>
            data={query.data.events}
            columns={[
              { accessorKey: 'seq', header: t('audit.seq') },
              {
                accessorKey: 'at',
                header: t('audit.at'),
                cell: ({ row }) => <Time value={row.original.at} />,
              },
              {
                accessorKey: 'subjectId',
                header: t('audit.subject'),
                cell: ({ row }) => <MonoId value={row.original.subjectId} />,
              },
              { accessorKey: 'hostname', header: t('audit.host') },
              { accessorKey: 'action', header: t('audit.action') },
              {
                accessorKey: 'decision',
                header: t('audit.decision'),
                cell: ({ row }) => (
                  <Badge
                    variant={
                      row.original.decision === 'allow'
                        ? 'default'
                        : row.original.decision === 'deny'
                          ? 'destructive'
                          : 'secondary'
                    }
                  >
                    {t(`policy.${row.original.decision}`)}
                  </Badge>
                ),
              },
              {
                accessorKey: 'hash',
                header: t('audit.hash'),
                cell: ({ row }) => (
                  <MonoId
                    value={row.original.hash}
                    className="hash"
                  />
                ),
              },
            ]}
          />
        )}
      </Panel>
      <Panel title={t('audit.verify')}>
        <form
          noValidate
          className="grid grid-cols-1 gap-3 sm:grid-cols-3"
          onSubmit={verificationForm.handleSubmit((v) =>
            verification.mutate(v),
          )}
        >
          <Field
            label={t('audit.fromSeq')}
            error={verificationForm.formState.errors.fromSeq?.message}
          >
            <Input
              inputMode="numeric"
              {...verificationForm.register('fromSeq')}
            />
          </Field>
          <Field
            label={t('audit.toSeq')}
            error={verificationForm.formState.errors.toSeq?.message}
          >
            <Input
              inputMode="numeric"
              {...verificationForm.register('toSeq')}
            />
          </Field>
          <div className="flex items-end">
            <Button size="sm" disabled={verification.isPending}>
              {t('audit.verify')}
            </Button>
          </div>
        </form>
        {result && (
          <p
            className={
              result.valid
                ? 'rounded-lg bg-secondary px-3 py-2 text-sm text-secondary-foreground'
                : 'rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive'
            }
          >
            {t(result.valid ? 'audit.verified' : 'audit.invalid', {
              count: result.checkedCount,
            })}
          </p>
        )}
        <p className="text-xs text-muted-foreground">{t('audit.internalOnly')}</p>
      </Panel>
    </div>
  )
}
