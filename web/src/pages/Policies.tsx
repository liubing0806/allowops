import { useEffect, useState } from 'react'
import { useForm, useWatch } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  api,
  formatLabels,
  labelsRepresentable,
  parseLabels,
  type PolicyRule,
  type PolicyVersion,
} from '@/api'
import {
  ConfirmDialog,
  DataTable,
  Field,
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
import { Textarea } from '@/components/ui/textarea'
import { commaList, labelsText, requiredText } from '@/lib/forms'
import { useCommand } from '@/lib/notifications'

const nonemptyList = requiredText.refine(
  (value) => commaList(value).length > 0,
  'error.required',
)
const schema = z
  .object({
    name: requiredText,
    roles: nonemptyList,
    operations: nonemptyList,
    actions: z.string(),
    risks: z
      .string()
      .refine(
        (value) =>
          commaList(value).every((risk) =>
            ['read', 'write', 'dangerous'].includes(risk),
          ),
        'error.risks',
      ),
    labels: labelsText,
    teams: z.string(),
    owners: z.string(),
    sourceCidrs: z.string(),
    hoursFrom: z.string(),
    hoursTo: z.string(),
    timezone: requiredText.refine((value) => {
      try {
        new Intl.DateTimeFormat('en', { timeZone: value })
        return true
      } catch {
        return false
      }
    }, 'error.timezone'),
    effect: z.enum(['POLICY_EFFECT_ALLOW', 'POLICY_EFFECT_DENY']),
  })
  .refine(
    (value) =>
      (!value.hoursFrom && !value.hoursTo) ||
      (value.hoursFrom !== '' &&
        value.hoursTo !== '' &&
        Number.isInteger(Number(value.hoursFrom)) &&
        Number.isInteger(Number(value.hoursTo)) &&
        Number(value.hoursFrom) >= 0 &&
        Number(value.hoursFrom) < Number(value.hoursTo) &&
        Number(value.hoursTo) <= 24),
    { message: 'error.hours', path: ['hoursTo'] },
  )

export default function Policies() {
  const { t } = useTranslation()
  const query = useQuery({
    queryKey: ['policies'],
    queryFn: () => api.listPolicyHistory(),
  })

  return (
    <div className="flex flex-col gap-3">
      <PageTitle
        title={t('nav.policies')}
        description={t('policy.description')}
      />
      <QueryState pending={query.isPending} error={query.error} />
      {query.data && (
        <PolicyEditor
          key={query.data.policies[0].version}
          policy={query.data.policies[0]}
          history={query.data.policies}
        />
      )}
    </div>
  )
}

function PolicyEditor({
  policy,
  history,
}: {
  policy: PolicyVersion
  history: PolicyVersion[]
}) {
  const { t } = useTranslation()
  const [rules, setRules] = useState(policy.rules.rules)
  const [editing, setEditing] = useState<number | null>(null)
  const [simulation, setSimulation] = useState<{
    test: Awaited<ReturnType<typeof api.testPolicy>>['test']
    changes: Awaited<ReturnType<typeof api.getPolicyTestChanges>>['changes']
  } | null>(null)
  const [rollback, setRollback] = useState<string | null>(null)
  const [confirm, setConfirm] = useState(false)
  const reasonForm = useForm<{ reason: string }>({
    resolver: zodResolver(z.object({ reason: requiredText })),
    defaultValues: { reason: '' },
  })
  const clear = () => {
    setSimulation(null)
    setRollback(null)
  }
  const test = useCommand(async (historicalVersion?: string) => {
    const result = await api.testPolicy({
      baseVersion: policy.version,
      ...(historicalVersion ? { historicalVersion } : { rules: { rules } }),
      cases: [],
    })
    const changes = await api.getPolicyTestChanges({
      testId: result.test.testId,
    })
    setSimulation({ test: result.test, changes: changes.changes })
    setRollback(historicalVersion ?? null)
  })
  const saving = useCommand(async (values: { reason: string }) => {
    if (simulation)
      await api.savePolicy({
        baseVersion: policy.version,
        rules: { rules },
        testId: simulation.test.testId,
        reason: values.reason,
      })
  }, 'policy.saved')
  const rolling = useCommand(async () => {
    if (simulation && rollback) {
      await api.rollbackPolicy({
        baseVersion: policy.version,
        targetVersion: rollback,
        testId: simulation.test.testId,
        reason: reasonForm.getValues('reason'),
      })
      setConfirm(false)
    }
  }, 'policy.rolledBack')

  return (
    <div className="flex flex-col gap-3">
      <Panel title={t('policy.rules')}>
        <div className="flex items-center justify-between gap-2">
          <Badge variant="secondary">
            {t('policy.historyVersion')} {policy.version}
          </Badge>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              clear()
              setEditing(rules.length)
            }}
          >
            {t('policy.add')}
          </Button>
        </div>
        <DataTable<PolicyRule>
          data={rules}
          columns={[
            { accessorKey: 'name', header: t('policy.name') },
            {
              id: 'roles',
              header: t('common.role'),
              cell: ({ row }) => row.original.roles.join(', '),
            },
            {
              id: 'operations',
              header: t('common.actions'),
              cell: ({ row }) => row.original.operations.join(', '),
            },
            {
              accessorKey: 'effect',
              header: t('policy.effect'),
              cell: ({ row }) => <Status value={row.original.effect} />,
            },
            {
              id: 'edit',
              header: t('common.actions'),
              cell: ({ row }) => (
                <Button
                  variant="link"
                  size="sm"
                  className="h-auto p-0"
                  onClick={() => {
                    clear()
                    setEditing(row.index)
                  }}
                  aria-label={t('common.edit', { name: row.original.name })}
                >
                  {t('common.edit', { name: row.original.name })}
                </Button>
              ),
            },
          ]}
        />
      </Panel>
      {editing !== null && (
        <RuleForm
          key={editing}
          rule={rules[editing]}
          onSave={(rule) => {
            const next = [...rules]
            next[editing] = rule
            setRules(next)
            setEditing(null)
            clear()
          }}
          onChange={clear}
        />
      )}
      <Panel>
        <p className="text-sm text-muted-foreground">{t('policy.testHint')}</p>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={test.isPending || editing !== null}
            onClick={() => test.mutate(undefined)}
          >
            {t('policy.test')}
          </Button>
        </div>
        <form
          noValidate
          className="flex flex-col gap-3"
          onSubmit={reasonForm.handleSubmit((values) =>
            rollback ? setConfirm(true) : saving.mutate(values),
          )}
        >
          <Field
            label={t('policy.reason')}
            error={reasonForm.formState.errors.reason?.message}
          >
            <Input {...reasonForm.register('reason')} />
          </Field>
          <div>
            <Button
              size="sm"
              disabled={
                !simulation ||
                !simulation.test.retainsPolicyAdministrator ||
                saving.isPending ||
                rolling.isPending ||
                editing !== null
              }
            >
              {t(rollback ? 'policy.rollbackConfirm' : 'policy.save')}
            </Button>
          </div>
        </form>
      </Panel>
      {simulation && (
        <Panel title={t('policy.result')}>
          <p className="text-sm">
            {t('policy.administrator', {
              value: t(
                simulation.test.retainsPolicyAdministrator
                  ? 'policy.yes'
                  : 'policy.no',
              ),
            })}
          </p>
          <p className="text-sm text-muted-foreground">
            {t('host.previewExpiry')}:{' '}
            <Time value={simulation.test.expiresAt} />
          </p>
          <DataTable
            data={simulation.changes}
            columns={[
              { accessorKey: 'host', header: t('host.hostname') },
              {
                id: 'before',
                header: t('policy.before'),
                cell: ({ row }) => (
                  <Status value={row.original.before.effect} />
                ),
              },
              {
                id: 'after',
                header: t('policy.after'),
                cell: ({ row }) => (
                  <Status value={row.original.after.effect} />
                ),
              },
              {
                id: 'matched',
                header: t('policy.matched'),
                cell: ({ row }) =>
                  row.original.after.matchedRules.join(', ') ||
                  t('common.none'),
              },
            ]}
          />
        </Panel>
      )}
      <Panel title={t('common.history')}>
        <DataTable<PolicyVersion>
          data={history}
          columns={[
            { accessorKey: 'version', header: t('policy.historyVersion') },
            {
              accessorKey: 'createdAt',
              header: t('common.createdAt'),
              cell: ({ row }) => <Time value={row.original.createdAt} />,
            },
            {
              accessorKey: 'reason',
              header: t('policy.reason'),
              cell: ({ row }) => t(row.original.reason),
            },
            {
              id: 'rollback',
              header: t('common.actions'),
              cell: ({ row }) => (
                <Button
                  variant="link"
                  size="sm"
                  className="h-auto p-0"
                  disabled={
                    row.original.version === policy.version ||
                    test.isPending ||
                    editing !== null
                  }
                  onClick={() => {
                    setSimulation(null)
                    test.mutate(row.original.version)
                  }}
                >
                  {t('policy.rollback', { version: row.original.version })}
                </Button>
              ),
            },
          ]}
        />
      </Panel>
      {confirm && (
        <ConfirmDialog
          title={t('policy.rollbackTitle')}
          description={t('policy.rollbackHint')}
          onClose={() => setConfirm(false)}
          onConfirm={() => rolling.mutate()}
          pending={rolling.isPending}
        />
      )}
    </div>
  )
}

function RuleForm({
  rule,
  onSave,
  onChange,
}: {
  rule?: PolicyRule
  onSave: (rule: PolicyRule) => void
  onChange: () => void
}) {
  const { t } = useTranslation()
  const representable = labelsRepresentable(rule?.hostLabels ?? {})
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: {
      name: rule?.name ?? '',
      roles: rule?.roles.join(',') ?? '',
      operations: rule?.operations.join(',') ?? 'execute_action',
      actions: rule?.actions.join(',') ?? '',
      risks: rule?.risks.join(',') ?? '',
      labels: formatLabels(rule?.hostLabels ?? {}),
      teams: rule?.teams.join(',') ?? '',
      owners: rule?.owners.join(',') ?? '',
      sourceCidrs: rule?.sourceCidrs.join(',') ?? '',
      hoursFrom: rule?.hours ? String(rule.hours.from) : '',
      hoursTo: rule?.hours ? String(rule.hours.to) : '',
      timezone: rule?.hours?.timezone ?? 'Asia/Shanghai',
      effect:
        rule?.effect === 'POLICY_EFFECT_DENY'
          ? 'POLICY_EFFECT_DENY'
          : 'POLICY_EFFECT_ALLOW',
    },
  })

  // A new rule starts with empty risks. While the user has not edited the field,
  // a rule that includes execute_action gets the safe default `read`.
  const [risksEdited, setRisksEdited] = useState(rule !== undefined)
  const operations = useWatch({ control: form.control, name: 'operations' })
  useEffect(() => {
    if (risksEdited) return
    form.setValue(
      'risks',
      commaList(operations).includes('execute_action') ? 'read' : '',
    )
  }, [form, operations, risksEdited])

  return (
    <Panel title={t('common.edit', { name: rule?.name ?? t('policy.name') })}>
      <form
        noValidate
        className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3"
        onChange={onChange}
        onSubmit={form.handleSubmit((values) =>
          onSave({
            ...rule,
            name: values.name,
            roles: commaList(values.roles),
            operations: commaList(values.operations),
            actions: commaList(values.actions),
            risks: commaList(values.risks),
            hostLabels: parseLabels(values.labels),
            effect: values.effect,
            teams: commaList(values.teams),
            owners: commaList(values.owners),
            sourceCidrs: commaList(values.sourceCidrs),
            hours:
              values.hoursFrom !== '' && values.hoursTo !== ''
                ? {
                    from: Number(values.hoursFrom),
                    to: Number(values.hoursTo),
                    timezone: values.timezone,
                  }
                : undefined,
          }),
        )}
      >
        {(
          [
            'name',
            'roles',
            'operations',
            'actions',
            'risks',
            'teams',
            'owners',
            'sourceCidrs',
          ] as const
        ).map((key) => (
          <Field
            key={key}
            label={t(`policy.${key}`)}
            error={form.formState.errors[key]?.message}
          >
            <Input
              {...form.register(
                key,
                key === 'risks'
                  ? { onChange: () => setRisksEdited(true) }
                  : undefined,
              )}
            />
          </Field>
        ))}
        <Field
          label={t('host.labels')}
          error={
            representable
              ? form.formState.errors.labels?.message
              : 'error.labelsUnrepresentable'
          }
        >
          <Textarea
            rows={3}
            placeholder={t('host.labelsPlaceholder')}
            {...form.register('labels')}
          />
        </Field>
        <Field label={t('policy.hoursFrom')}>
          <Input
            type="number"
            min={0}
            max={23}
            {...form.register('hoursFrom')}
          />
        </Field>
        <Field
          label={t('policy.hoursTo')}
          error={form.formState.errors.hoursTo?.message}
        >
          <Input type="number" min={1} max={24} {...form.register('hoursTo')} />
        </Field>
        <Field
          label={t('policy.timezone')}
          error={form.formState.errors.timezone?.message}
        >
          <Input {...form.register('timezone')} />
        </Field>
        <Field label={t('policy.effect')}>
          <NativeSelect {...form.register('effect')} className="w-full">
            <option value="POLICY_EFFECT_ALLOW">{t('policy.allow')}</option>
            <option value="POLICY_EFFECT_DENY">{t('policy.deny')}</option>
          </NativeSelect>
        </Field>
        <div className="sm:col-span-2 lg:col-span-3">
          <Button size="sm" disabled={!representable}>
            {t('common.save')}
          </Button>
        </div>
      </form>
    </Panel>
  )
}
