import { useEffect, useId, useState } from 'react'
import { useForm, useWatch } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { HistoryIcon, PlusIcon, SparklesIcon } from 'lucide-react'
import {
  api,
  formatLabels,
  labelsRepresentable,
  parseLabels,
  type PolicyChange,
  type PolicyRule,
  type PolicyTest,
  type PolicyTestCase,
  type PolicyVersion,
} from '@/api'
import {
  ConfirmDialog,
  DataTable,
  Field,
  PageTitle,
  QueryState,
  Status,
  Time,
} from '@/components/console/common'
import { SegmentedControl } from '@/components/console/SegmentedControl'
import { SidePanel } from '@/components/console/SidePanel'
import { StatusDot } from '@/components/console/StatusDot'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { NativeSelect } from '@/components/ui/native-select'
import { Textarea } from '@/components/ui/textarea'
import { commaList, labelsText, requiredText } from '@/lib/forms'
import { useCommand } from '@/lib/notifications'
import { cn } from '@/lib/utils'

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

// Operations a test case may name; the gateway rejects any other value.
const testOperations = [
  'execute_action',
  'view_hosts',
  'view_catalog',
  'view_jobs',
  'view_output',
  'view_audit',
  'view_system',
  'manage_hosts',
  'create_join_token',
  'publish_catalog',
  'manage_service_accounts',
  'manage_user_roles',
  'modify_policy',
]

type Scope = 'all' | 'case'
interface CaseInput {
  subjectId: string
  operation: string
  action: string
  selector: string
}
// Everything a simulation result depends on. A result is stale as soon as the
// current candidate differs from the one it was computed for.
interface Candidate {
  rules: PolicyRule[]
  rollback: string | null
  scope: Scope
  testCase: CaseInput
}
interface Simulation {
  key: string
  rollback: string | null
  test: PolicyTest
  changes: PolicyChange[]
}

// Stable serialization: rules built by the form and rules returned by the API
// may list their keys in a different order.
function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) =>
    item && typeof item === 'object' && !Array.isArray(item)
      ? Object.fromEntries(
          Object.entries(item as Record<string, unknown>).sort(([a], [b]) =>
            a.localeCompare(b),
          ),
        )
      : item,
  )
}

function candidateKey(candidate: Candidate) {
  return canonical({
    ...candidate,
    testCase: candidate.scope === 'case' ? candidate.testCase : null,
  })
}

function caseReady(scope: Scope, value: CaseInput) {
  if (scope === 'all') return true
  if (!value.subjectId) return false
  return (
    value.operation !== 'execute_action' ||
    (value.action !== '' && value.selector.trim() !== '')
  )
}

function testCases(candidate: Candidate): PolicyTestCase[] {
  if (candidate.scope === 'all') return []
  const { subjectId, operation, action, selector } = candidate.testCase
  const testCase = {
    subjectId,
    operation,
    action,
    at: new Date().toISOString(),
    sourceIp: '',
  }
  // Without targets a console operation is a global check.
  return [
    (selector.trim()
      ? { ...testCase, targets: { selector: selector.trim() } }
      : testCase) as PolicyTestCase,
  ]
}

export default function Policies() {
  const { t } = useTranslation()
  const query = useQuery({
    queryKey: ['policies'],
    queryFn: () => api.listPolicyHistory(),
  })

  const [historyOpen, setHistoryOpen] = useState(false)
  const policy = query.data?.policies[0]

  return (
    <div className="flex flex-col gap-3">
      <PageTitle
        title={t('nav.policies')}
        description={
          policy ? (
            <span className="font-mono">
              {t('policy.meta', {
                version: policy.version,
                count: policy.rules.rules.length,
              })}
            </span>
          ) : (
            t('policy.description')
          )
        }
        action={
          policy && (
            <Button
              variant="outline"
              size="sm"
              aria-expanded={historyOpen}
              onClick={() => setHistoryOpen((open) => !open)}
            >
              <HistoryIcon data-icon="inline-start" />
              {t('common.history')}
            </Button>
          )
        }
      />
      <QueryState pending={query.isPending} error={query.error} />
      {query.data && policy && (
        <PolicyEditor
          key={policy.version}
          policy={policy}
          history={query.data.policies}
          historyOpen={historyOpen}
          onHistoryOpenChange={setHistoryOpen}
        />
      )}
    </div>
  )
}

function PolicyEditor({
  policy,
  history,
  historyOpen,
  onHistoryOpenChange: setHistoryOpen,
}: {
  policy: PolicyVersion
  history: PolicyVersion[]
  historyOpen: boolean
  onHistoryOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const saved = policy.rules.rules
  const [rules, setRules] = useState(saved)
  // Index of the rule in the editor; rules.length is a new rule not yet added.
  const [selected, setSelected] = useState<number | null>(
    saved.length ? 0 : null,
  )
  // Remounts the rule form and cards when the draft is replaced.
  const [generation, setGeneration] = useState(0)
  // The rule form has edits that are not in the draft yet.
  const [ruleDirty, setRuleDirty] = useState(false)
  const [rollback, setRollback] = useState<string | null>(null)
  const [scope, setScope] = useState<Scope>('all')
  const [testCase, setTestCase] = useState<CaseInput>({
    subjectId: '',
    operation: 'execute_action',
    action: '',
    selector: '',
  })
  const [simulation, setSimulation] = useState<Simulation | null>(null)
  const [confirm, setConfirm] = useState(false)
  const reasonForm = useForm<{ reason: string }>({
    resolver: zodResolver(z.object({ reason: requiredText })),
    defaultValues: { reason: '' },
  })

  const current: Candidate = { rules, rollback, scope, testCase }
  const stale =
    !!simulation && (simulation.key !== candidateKey(current) || ruleDirty)
  const fresh = !!simulation && !stale
  const dirty = rollback !== null || canonical(rules) !== canonical(saved)
  const retains = simulation?.test.retainsPolicyAdministrator ?? false

  const test = useCommand(async (candidate: Candidate) => {
    const result = await api.testPolicy({
      baseVersion: policy.version,
      ...(candidate.rollback
        ? { historicalVersion: candidate.rollback }
        : { rules: { rules: candidate.rules } }),
      cases: testCases(candidate),
    })
    const changes = await api.getPolicyTestChanges({
      testId: result.test.testId,
    })
    setSimulation({
      key: candidateKey(candidate),
      rollback: candidate.rollback,
      test: result.test,
      changes: changes.changes,
    })
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
    if (simulation?.rollback) {
      await api.rollbackPolicy({
        baseVersion: policy.version,
        targetVersion: simulation.rollback,
        testId: simulation.test.testId,
        reason: reasonForm.getValues('reason'),
      })
      setConfirm(false)
    }
  }, 'policy.rolledBack')

  // Editing the draft ends a loaded rollback: the candidate is then the edited
  // rules, saved through SavePolicy.
  const replaceRules = (next: PolicyRule[], nextSelected: number | null) => {
    setRules(next)
    setSelected(nextSelected)
    setRuleDirty(false)
    setRollback(null)
    setGeneration((value) => value + 1)
  }
  const select = (index: number) => {
    setSelected(index)
    setRuleDirty(false)
  }
  // Loads the historical rules into the draft and simulates the rollback.
  const loadRollback = (version: PolicyVersion) => {
    const candidate: Candidate = {
      rules: version.rules.rules,
      rollback: version.version,
      scope,
      testCase,
    }
    setRules(candidate.rules)
    setSelected(candidate.rules.length ? 0 : null)
    setRuleDirty(false)
    setRollback(version.version)
    setGeneration((value) => value + 1)
    setSimulation(null)
    setHistoryOpen(false)
    test.mutate(candidate)
  }

  const hint = !dirty
    ? 'policy.hintNoChanges'
    : ruleDirty
      ? 'policy.hintApplyRule'
      : !fresh
        ? 'policy.hintTest'
        : !retains
          ? 'error.policyLockout'
          : 'policy.hintReady'

  return (
    <>
      <div className="flex flex-wrap items-start gap-4">
        <section
          aria-labelledby="policy-rules"
          className="flex max-w-full min-w-0 flex-[1_1_340px] flex-col gap-2"
        >
          <div className="flex flex-wrap items-center gap-2">
            <h2 id="policy-rules" className="text-sm font-semibold">
              {t('policy.rules')}
            </h2>
            {dirty && (
              <span className="rounded-full bg-warning-soft px-2 py-px text-xs text-warning">
                {t('policy.unsaved')}
              </span>
            )}
            <span className="flex-1" />
            <span className="text-xs text-muted-foreground">
              {t('policy.semantics')}
            </span>
          </div>
          {rules.map((rule, index) => (
            <RuleCard
              key={`${generation}:${index}`}
              rule={rule}
              index={index}
              active={selected === index}
              changed={canonical(rule) !== canonical(saved[index])}
              onSelect={() => select(index)}
            />
          ))}
          <button
            type="button"
            onClick={() => select(rules.length)}
            className={cn(
              'flex h-9 items-center justify-center gap-1.5 rounded-[10px] border border-dashed text-sm text-foreground-2 hover:bg-muted hover:text-foreground',
              selected === rules.length && 'border-primary text-foreground',
            )}
          >
            <PlusIcon aria-hidden="true" className="size-3.5" />
            {t('policy.add')}
          </button>
        </section>
        <div className="flex max-w-full min-w-0 flex-[999_1_480px] flex-col gap-3.5">
          {selected !== null && (
            <RuleForm
              key={`${generation}:${selected}`}
              rule={rules[selected]}
              index={selected}
              onSave={(rule) => {
                const next = [...rules]
                next[selected] = rule
                replaceRules(next, selected)
              }}
              onDelete={
                selected < rules.length
                  ? () =>
                      replaceRules(
                        rules.filter((_, index) => index !== selected),
                        rules.length > 1 ? Math.max(0, selected - 1) : null,
                      )
                  : undefined
              }
              onChange={() => setRuleDirty(true)}
            />
          )}
          <section
            aria-labelledby="policy-test"
            className="overflow-hidden rounded-xl border bg-card"
          >
            <div className="flex flex-col gap-2.5 px-4 pt-3.5 pb-3">
              <div className="flex flex-wrap items-center gap-2">
                <SparklesIcon
                  aria-hidden="true"
                  className="size-4 text-primary"
                />
                <h2 id="policy-test" className="flex-1 text-sm font-semibold">
                  {t('policy.testTitle')}
                </h2>
                <SegmentedControl<Scope>
                  label={t('policy.scope')}
                  value={scope}
                  onChange={setScope}
                  options={[
                    { value: 'all', label: t('policy.scopeAll') },
                    { value: 'case', label: t('policy.scopeCase') },
                  ]}
                />
              </div>
              <div className="flex flex-wrap items-end gap-2">
                {scope === 'case' && (
                  <CaseFields value={testCase} onChange={setTestCase} />
                )}
                <Button
                  size="sm"
                  className="h-[34px]"
                  disabled={
                    test.isPending || ruleDirty || !caseReady(scope, testCase)
                  }
                  onClick={() => test.mutate(current)}
                >
                  {t('policy.test')}
                </Button>
              </div>
              <p className="text-[11px] text-muted-foreground">
                {t('policy.testHint')}
              </p>
            </div>
            {stale && (
              <p className="mx-4 mb-3 rounded-lg bg-warning-soft px-2.5 py-2 text-xs text-warning">
                {t('error.stalePolicy')}
              </p>
            )}
            {simulation && fresh && (
              <SimulationResult simulation={simulation} />
            )}
            <form
              noValidate
              className="flex flex-wrap items-start gap-2 border-t border-border-subtle px-4 py-3"
              onSubmit={reasonForm.handleSubmit((values) =>
                rollback ? setConfirm(true) : saving.mutate(values),
              )}
            >
              <label className="flex min-w-0 flex-[1_1_260px] flex-col gap-1">
                <span className="sr-only">{t('policy.reason')}</span>
                <Input
                  placeholder={t('policy.reasonPlaceholder')}
                  {...reasonForm.register('reason')}
                />
                {reasonForm.formState.errors.reason?.message && (
                  <small role="alert" className="text-xs text-destructive">
                    {t(reasonForm.formState.errors.reason.message)}
                  </small>
                )}
              </label>
              <Button
                size="sm"
                className="h-9"
                disabled={
                  !dirty ||
                  !fresh ||
                  !retains ||
                  saving.isPending ||
                  rolling.isPending
                }
              >
                {t(rollback ? 'policy.rollbackConfirm' : 'policy.save')}
              </Button>
              <p
                className={cn(
                  'basis-full text-[11px]',
                  hint === 'error.policyLockout'
                    ? 'text-destructive'
                    : 'text-muted-foreground',
                )}
              >
                {t(hint)}
              </p>
            </form>
          </section>
        </div>
      </div>
      {historyOpen && (
        <SidePanel
          title={<span className="font-sans">{t('common.history')}</span>}
          onClose={() => setHistoryOpen(false)}
        >
          <ol className="-mx-4 -mt-3.5 flex flex-col">
            {history.map((version) => (
              <li
                key={version.version}
                className="flex flex-col gap-1 border-b border-border-subtle px-4 py-3"
              >
                <span className="flex items-center gap-2">
                  <span className="font-mono font-medium">
                    v{version.version}
                  </span>
                  {version.version === policy.version && (
                    <span className="rounded-full bg-accent px-1.5 text-[11px] text-accent-foreground">
                      {t('policy.current')}
                    </span>
                  )}
                  <span className="flex-1" />
                  <span className="text-[11px] text-muted-foreground">
                    <Time value={version.createdAt} />
                  </span>
                </span>
                <span className="text-foreground-2">{t(version.reason)}</span>
                {version.rolledBackFrom && (
                  <span className="text-[11px] text-muted-foreground">
                    {t('policy.rolledBackFrom', {
                      version: version.rolledBackFrom,
                    })}
                  </span>
                )}
                <span className="flex items-center gap-2">
                  <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-muted-foreground">
                    {version.createdBy}
                  </span>
                  {version.version !== policy.version && (
                    <Button
                      variant="outline"
                      size="xs"
                      disabled={test.isPending || ruleDirty}
                      onClick={() => loadRollback(version)}
                    >
                      {t('policy.rollback', { version: version.version })}
                    </Button>
                  )}
                </span>
              </li>
            ))}
          </ol>
          <p className="text-[11px] text-muted-foreground">
            {t('policy.rollbackHint')}
          </p>
        </SidePanel>
      )}
      {confirm && (
        <ConfirmDialog
          title={t('policy.rollbackTitle')}
          description={t('policy.rollbackHint')}
          onClose={() => setConfirm(false)}
          onConfirm={() => rolling.mutate()}
          pending={rolling.isPending}
        />
      )}
    </>
  )
}

function RuleCard({
  rule,
  index,
  active,
  changed,
  onSelect,
}: {
  rule: PolicyRule
  index: number
  active: boolean
  changed: boolean
  onSelect: () => void
}) {
  const { t } = useTranslation()
  const id = useId()
  const deny = rule.effect === 'POLICY_EFFECT_DENY'
  const effect = t(deny ? 'policy.deny' : 'policy.allow')
  const many = (items: string[], key: string) =>
    items.length > 2 ? t(key, { count: items.length }) : items.join(', ')
  const chips: [string, string][] = [
    [t('policy.chipRoles'), rule.roles.join(', ') || t('common.none')],
  ]
  if (rule.teams.length)
    chips.push([t('policy.chipTeams'), rule.teams.join(', ')])
  if (rule.owners.length)
    chips.push([t('policy.chipOwners'), many(rule.owners, 'policy.countItems')])
  chips.push([
    t('policy.chipOperations'),
    many(rule.operations, 'policy.countItems') || t('common.none'),
  ])
  if (rule.actions.length)
    chips.push([
      t('policy.chipActions'),
      many(rule.actions, 'policy.countActions'),
    ])
  if (rule.risks.length)
    chips.push([t('policy.chipRisks'), rule.risks.join(', ')])
  if (Object.keys(rule.hostLabels).length)
    chips.push([t('policy.chipLabels'), formatLabels(rule.hostLabels)])
  if (rule.hours)
    chips.push([
      t('policy.chipHours'),
      `${rule.hours.from}–${rule.hours.to} ${rule.hours.timezone}`,
    ])
  if (rule.sourceCidrs.length)
    chips.push([
      t('policy.chipCidrs'),
      many(rule.sourceCidrs, 'policy.countItems'),
    ])
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-label={t('common.edit', { name: rule.name })}
      aria-describedby={id}
      aria-current={active ? 'true' : undefined}
      className={cn(
        'flex flex-col gap-1.5 rounded-[10px] border bg-card px-3 py-2.5 text-left hover:border-primary/50',
        active && 'border-primary shadow-[0_0_0_1px_var(--primary)]',
      )}
    >
      <span className="flex w-full items-center gap-2">
        <span className="w-[18px] font-mono text-[11px] text-muted-foreground">
          {index + 1}
        </span>
        <span
          className={cn(
            'rounded-full px-[7px] text-[11px] font-semibold',
            deny
              ? 'bg-destructive-soft text-destructive'
              : 'bg-success-soft text-success',
          )}
        >
          {effect}
        </span>
        <span className="min-w-0 flex-1 truncate font-mono font-medium">
          {rule.name}
        </span>
        {changed && <StatusDot tone="warning" size={6} />}
      </span>
      <span id={id} className="flex flex-wrap gap-1 pl-[26px]">
        <span className="sr-only">
          {changed ? `${effect}, ${t('policy.changed')}` : effect}
        </span>
        {chips.map(([name, value]) => (
          <span
            key={name}
            className="max-w-full truncate rounded-[5px] bg-muted px-1.5 font-mono text-[11px] text-foreground-2"
          >
            <span className="text-muted-foreground">{name}</span> {value}
          </span>
        ))}
      </span>
    </button>
  )
}

function CaseFields({
  value,
  onChange,
}: {
  value: CaseInput
  onChange: (value: CaseInput) => void
}) {
  const { t } = useTranslation()
  // Subject options are a convenience. Without permission to list them the
  // select only offers the placeholder.
  const users = useQuery({
    queryKey: ['users'],
    queryFn: () => api.listUsers(),
  })
  const accounts = useQuery({
    queryKey: ['accounts'],
    queryFn: () => api.listServiceAccounts(),
  })
  const set = (patch: Partial<CaseInput>) => onChange({ ...value, ...patch })
  const control = 'h-[34px] w-full font-mono text-xs'
  const accountList = accounts.data?.accounts ?? []
  const userList = users.data?.users ?? []
  return (
    <div className="grid min-w-0 flex-1 grid-cols-[repeat(auto-fit,minmax(150px,1fr))] gap-2">
      <Field label={t('policy.subject')}>
        <NativeSelect
          className={control}
          value={value.subjectId}
          onChange={(event) => set({ subjectId: event.target.value })}
        >
          <option value="">{t('policy.subjectPick')}</option>
          {accountList.length > 0 && (
            <optgroup label={t('nav.accounts')}>
              {accountList.map((account) => (
                <option key={account.accountId} value={account.accountId}>
                  {account.name}
                </option>
              ))}
            </optgroup>
          )}
          {userList.length > 0 && (
            <optgroup label={t('nav.users')}>
              {userList.map((user) => (
                <option key={user.userId} value={user.userId}>
                  {user.displayName || user.username}
                </option>
              ))}
            </optgroup>
          )}
        </NativeSelect>
      </Field>
      <Field label={t('policy.operation')}>
        <NativeSelect
          className={control}
          value={value.operation}
          onChange={(event) => set({ operation: event.target.value })}
        >
          {testOperations.map((operation) => (
            <option key={operation} value={operation}>
              {operation}
            </option>
          ))}
        </NativeSelect>
      </Field>
      <Field label={t('policy.action')}>
        <Input
          className={control}
          value={value.action}
          placeholder="disk_usage"
          onChange={(event) => set({ action: event.target.value.trim() })}
        />
      </Field>
      <Field label={t('policy.targetSelector')}>
        <Input
          className={control}
          value={value.selector}
          placeholder="env=prod"
          onChange={(event) => set({ selector: event.target.value })}
        />
      </Field>
    </div>
  )
}

function SimulationResult({ simulation }: { simulation: Simulation }) {
  const { t } = useTranslation()
  const { test, changes } = simulation
  const flipped = changes.filter((c) => c.before.effect !== c.after.effect)
  const toAllow = flipped.filter(
    (c) => c.after.effect === 'POLICY_EFFECT_ALLOW',
  ).length
  return (
    <div className="flex flex-col border-t border-border-subtle">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 bg-background px-4 py-2.5">
        <h3 className="text-sm font-semibold">{t('policy.result')}</h3>
        <span className="font-medium">
          {flipped.length
            ? t('policy.summaryChanged', {
                count: flipped.length,
                allow: toAllow,
                deny: flipped.length - toAllow,
              })
            : t('policy.summaryNone')}
        </span>
        <span className="text-xs text-muted-foreground">
          {t('policy.evaluated', { count: Number(test.evaluatedCount) })}
        </span>
        <span className="flex-1" />
        <span
          className={cn(
            'text-xs',
            test.retainsPolicyAdministrator
              ? 'text-muted-foreground'
              : 'text-destructive',
          )}
        >
          {t('policy.administrator', {
            value: t(
              test.retainsPolicyAdministrator ? 'policy.yes' : 'policy.no',
            ),
          })}
        </span>
      </div>
      <p className="flex flex-wrap gap-x-3 px-4 pt-2 text-xs text-muted-foreground">
        {simulation.rollback && (
          <span>
            {t('policy.rollbackResult', { version: simulation.rollback })}
          </span>
        )}
        <span>
          {t('policy.testExpiry')}: <Time value={test.expiresAt} />
        </span>
      </p>
      <div className="overflow-x-auto px-2 pb-1">
        <DataTable<PolicyChange>
          data={changes}
          pageSize={20}
          empty={t('policy.noChanges')}
          rowClassName={(row) =>
            row.before.effect === row.after.effect
              ? undefined
              : row.after.effect === 'POLICY_EFFECT_ALLOW'
                ? 'bg-success-soft'
                : 'bg-destructive-soft'
          }
          columns={[
            {
              accessorKey: 'host',
              header: t('policy.host'),
              cell: ({ row }) => (
                <span className="font-mono text-xs">
                  {row.original.host || t('common.none')}
                </span>
              ),
            },
            {
              id: 'before',
              header: t('policy.before'),
              cell: ({ row }) => <Status value={row.original.before.effect} />,
            },
            {
              id: 'after',
              header: t('policy.after'),
              cell: ({ row }) => <Status value={row.original.after.effect} />,
            },
            {
              id: 'matched',
              header: t('policy.matched'),
              cell: ({ row }) => (
                <span className="font-mono text-[11px] text-foreground-2">
                  <DecisionReason change={row.original} />
                </span>
              ),
            },
          ]}
        />
      </div>
    </div>
  )
}

// Describes the new decision with the fields the gateway returned.
function DecisionReason({ change }: { change: PolicyChange }) {
  const { t } = useTranslation()
  const { after } = change
  if (after.matchedRules.length) return <>{after.matchedRules.join(', ')}</>
  if (after.errorReason)
    return (
      <>
        {t(`policy.errorReason.${after.errorReason}`, {
          defaultValue: after.errorReason,
        })}
      </>
    )
  if (after.effect === 'POLICY_EFFECT_DENY') return <>{t('policy.noMatch')}</>
  return <>{t('common.none')}</>
}

function RuleForm({
  rule,
  index,
  onSave,
  onDelete,
  onChange,
}: {
  rule?: PolicyRule
  index: number
  onSave: (rule: PolicyRule) => void
  onDelete?: () => void
  onChange: () => void
}) {
  const { t } = useTranslation()
  // Host labels written through the API or CLI may not fit one key=value per
  // line; saving the text would then store different labels.
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
  const effect = useWatch({ control: form.control, name: 'effect' })
  useEffect(() => {
    if (risksEdited) return
    form.setValue(
      'risks',
      commaList(operations).includes('execute_action') ? 'read' : '',
    )
  }, [form, operations, risksEdited])

  const input = 'font-mono text-xs'
  return (
    <section
      aria-labelledby="policy-rule-form"
      className="flex flex-col gap-3 rounded-xl border bg-card px-4 py-3.5"
    >
      <div className="flex flex-wrap items-center gap-2.5">
        <h2 id="policy-rule-form" className="flex-1 text-sm font-semibold">
          {t(rule ? 'policy.editRule' : 'policy.newRule')}{' '}
          <span className="font-mono font-medium text-muted-foreground">
            #{index + 1}
          </span>
        </h2>
        <SegmentedControl
          label={t('policy.effect')}
          value={effect}
          onChange={(value) => {
            form.setValue('effect', value, { shouldDirty: true })
            onChange()
          }}
          options={[
            {
              value: 'POLICY_EFFECT_ALLOW',
              label: t('policy.allow'),
              tone: 'success',
            },
            {
              value: 'POLICY_EFFECT_DENY',
              label: t('policy.deny'),
              tone: 'destructive',
            },
          ]}
        />
        {onDelete && (
          <Button
            variant="ghost"
            size="sm"
            className="text-destructive hover:text-destructive"
            onClick={onDelete}
          >
            {t('policy.deleteRule')}
          </Button>
        )}
      </div>
      <form
        noValidate
        className="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-2.5"
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
              className={input}
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
            className={input}
            placeholder={t('host.labelsPlaceholder')}
            {...form.register('labels')}
          />
        </Field>
        <Field label={t('policy.hoursFrom')}>
          <Input
            type="number"
            min={0}
            max={23}
            className={input}
            {...form.register('hoursFrom')}
          />
        </Field>
        <Field
          label={t('policy.hoursTo')}
          error={form.formState.errors.hoursTo?.message}
        >
          <Input
            type="number"
            min={1}
            max={24}
            className={input}
            {...form.register('hoursTo')}
          />
        </Field>
        <Field
          label={t('policy.timezone')}
          error={form.formState.errors.timezone?.message}
        >
          <Input className={input} {...form.register('timezone')} />
        </Field>
        <div className="col-span-full flex flex-wrap items-center gap-2.5">
          <Button size="sm" variant="outline" disabled={!representable}>
            {t('common.save')}
          </Button>
          <span className="text-[11px] text-muted-foreground">
            {t('policy.ruleDraftHint')}
          </span>
        </div>
      </form>
    </section>
  )
}
