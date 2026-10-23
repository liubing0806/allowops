import type {
  ActionDefinition,
  ActionSummary,
  AuditEvent,
  CatalogVersion,
  ConsoleApi,
  Host,
  HostImportPreview,
  HostImportRow,
  Job,
  Labels,
  PolicyChange,
  PolicyDecision,
  PolicyRule,
  PolicyRules,
  PolicyTest,
  PolicyTestCase,
  PolicyVersion,
  RoleMapping,
  ServiceAccount,
  ServiceAccountToken,
  Task,
  User,
} from '@/api/types'
import { defaultRoles } from '@/api/types'
import { ApiError } from '@/api/error'
import {
  base64ToBytes,
  bytesToBase64,
  parseLabels,
  toBase64,
  validateLabel,
} from '@/api/values'

const copy = <T>(value: T): T => structuredClone(value)
const date = (days = 0) =>
  new Date(Date.now() + days * 86_400_000).toISOString()
const page = { nextPageToken: '' }
const required = <T>(value: T | undefined): T => {
  if (value === undefined) throw new ApiError('error.notFound')
  return value
}
const random = (prefix: string) =>
  prefix +
  Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) =>
    b.toString(16).padStart(2, '0'),
  ).join('')
const bump = (revision: string) => String(BigInt(revision) + 1n)
const sha256 = async (bytes: Uint8Array) =>
  bytesToBase64(
    new Uint8Array(
      await crypto.subtle.digest('SHA-256', new Uint8Array(bytes)),
    ),
  )
const zeros = bytesToBase64(new Uint8Array(32))

function selected(host: Host, selector: string) {
  return Object.entries(parseLabels(selector)).every(([key, value]) =>
    key.startsWith('reported.')
      ? host.reportedLabels[key.slice(9)] === value
      : host.authorizationLabels[key] === value,
  )
}
function csvRows(csv: string) {
  const rows: string[][] = []
  let row: string[] = [],
    field = '',
    quoted = false,
    closed = false
  const text = csv.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n')
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"'
        i++
      } else if (c === '"') {
        quoted = false
        closed = true
      } else field += c
    } else if (c === ',' || c === '\n') {
      row.push(field)
      field = ''
      closed = false
      if (c === '\n') {
        if (row.some(Boolean)) rows.push(row)
        row = []
      }
    } else if (c === '"' && field === '' && !closed) quoted = true
    else if (c === '"' || closed) throw new ApiError('error.csv')
    else field += c
  }
  if (quoted) throw new ApiError('error.csv')
  row.push(field)
  if (row.some(Boolean)) rows.push(row)
  return rows
}

const definition = {
  params: {
    service: {
      type: 'enum',
      values: ['api', 'web'],
      description: 'action.param.service',
    },
    lines: {
      type: 'int',
      min: 1,
      max: 500,
      default: 100,
      description: 'action.param.lines',
    },
  },
  exec: [
    '/usr/bin/journalctl',
    '-u',
    '{service}',
    '-n',
    '{lines}',
    '--no-pager',
  ],
  run_as: 'root',
  timeout: '10s',
  max_output: '64KB',
  redact: { builtin: ['secrets'] },
} satisfies ActionDefinition
function seed() {
  const hosts: Host[] = ['web-01', 'web-02', 'web-03', 'worker-01'].map<Host>(
    (hostname, i) => ({
      hostId: `host-0${i + 1}`,
      hostname,
      authorizationLabels:
        i === 3
          ? ({} as Labels)
          : { env: i === 2 ? 'stage' : 'prod', tier: 'web' },
      reportedLabels: { os: 'linux', arch: i === 1 ? 'arm64' : 'amd64' },
      online: i !== 1,
      agentVersion: i === 1 ? '0.0.9' : '0.1.0',
      loadedCatalogs: [
        {
          catalogId: 'default',
          version: i === 1 ? '20261001090000' : '20261013090000',
        },
      ],
      capabilities: {
        catalogSchemaVersions: [1],
        parameterTypes: ['enum', 'int', 'string'],
        executionModes: ['exec'],
        builtins: [],
        outputFilters: ['tail'],
        features: [],
      },
      lastSeen: date(i === 1 ? -1 : 0),
      registeredAt: date(-30),
      revision: '1',
    }),
  )
  const users: User[] = [
    {
      userId: 'user-01',
      providerId: 'oidc',
      username: 'console-user',
      displayName: 'console-user',
      email: '',
      groups: ['ops-admins'],
      mappedRoles: ['admin'],
      manualRoles: [],
      effectiveRoles: ['admin'],
      teams: ['ops'],
      revision: '1',
    },
    {
      userId: 'user-02',
      providerId: 'ldap',
      username: 'audit-user',
      displayName: 'audit-user',
      email: '',
      groups: ['audit-readers'],
      mappedRoles: ['auditor'],
      manualRoles: [],
      effectiveRoles: ['auditor'],
      teams: ['ops'],
      revision: '1',
    },
    {
      userId: 'user-03',
      providerId: 'oidc',
      username: 'view-user',
      displayName: 'view-user',
      email: '',
      groups: ['ops-viewers'],
      mappedRoles: ['viewer'],
      manualRoles: [],
      effectiveRoles: ['viewer'],
      teams: ['ops'],
      revision: '1',
    },
  ]
  const actions: ActionSummary[] = [
    {
      name: 'journal_view_log',
      description: 'action.journal.description',
      risk: 'read',
      idempotent: true,
      executionMode: 'exec',
      builtin: '',
      actionSha256: zeros,
    },
    {
      name: 'systemd_restart_service',
      description: 'action.restart.description',
      risk: 'write',
      idempotent: false,
      executionMode: 'exec',
      builtin: '',
      actionSha256: zeros,
    },
  ]
  const catalogs: CatalogVersion[] = [
    {
      catalog: { catalogId: 'default', version: '20261013090000' },
      schemaVersion: 1,
      createdAt: date(-77),
      expiresAt: date(13),
      gitCommit: 'example-commit-02',
      envelopeSha256: zeros,
      envelopeSizeBytes: '4096',
      actionCount: 2,
      current: true,
      publishedAt: date(-1),
    },
    {
      catalog: { catalogId: 'default', version: '20261001090000' },
      schemaVersion: 1,
      createdAt: date(-88),
      expiresAt: date(2),
      gitCommit: 'example-commit-01',
      envelopeSha256: zeros,
      envelopeSizeBytes: '2048',
      actionCount: 1,
      current: false,
      publishedAt: date(-13),
    },
  ]
  const rules: PolicyRule[] = [
    {
      name: 'readonly-all',
      roles: ['operator', 'auditor'],
      teams: [],
      owners: [],
      operations: ['execute_action', 'view_output'],
      actions: [],
      risks: ['read'],
      hostLabels: {},
      sourceCidrs: [],
      effect: 'POLICY_EFFECT_ALLOW',
    },
    {
      name: 'prod-restart',
      roles: ['operator'],
      teams: [],
      owners: [],
      operations: ['execute_action'],
      actions: ['systemd_restart_service'],
      risks: [],
      hostLabels: { env: 'prod' },
      hours: { from: 9, to: 21, timezone: 'Asia/Shanghai' },
      sourceCidrs: [],
      effect: 'POLICY_EFFECT_ALLOW',
    },
    {
      name: 'deny-core',
      roles: ['*'],
      teams: [],
      owners: [],
      operations: ['execute_action'],
      actions: [],
      risks: ['write', 'dangerous'],
      hostLabels: { tier: 'core' },
      sourceCidrs: [],
      effect: 'POLICY_EFFECT_DENY',
    },
  ]
  const policies: PolicyVersion[] = [
    {
      version: '2',
      rules: { rules },
      createdAt: date(-1),
      createdBy: 'user-01',
      reason: 'policy.reason.initial',
    },
    {
      version: '1',
      rules: { rules: rules.slice(0, 2) },
      createdAt: date(-8),
      createdBy: 'user-01',
      reason: 'policy.reason.initial',
    },
  ]
  const accounts: ServiceAccount[] = [
    {
      accountId: 'sa-01',
      name: 'agent-readonly',
      ownerUserId: 'user-01',
      description: 'account.readonly.description',
      roles: ['auditor'],
      teams: ['ops'],
      revision: '1',
      createdAt: date(-30),
    },
    {
      accountId: 'sa-02',
      name: 'catalog-publisher',
      ownerUserId: 'user-01',
      description: 'account.publisher.description',
      roles: ['publisher'],
      teams: ['ops'],
      revision: '1',
      createdAt: date(-30),
    },
  ]
  const tokens: ServiceAccountToken[] = [
    {
      tokenId: 'token-01',
      accountId: 'sa-01',
      description: 'token.description.demo',
      createdAt: date(-25),
      expiresAt: date(5),
      lastUsedAt: date(),
    },
  ]
  const tasks: Task[] = [
    {
      jobId: 'job-20261013-0042',
      taskId: 'task-01',
      hostId: 'host-01',
      hostname: 'web-01',
      result: {
        status: 'TASK_STATUS_SUCCEEDED',
        exitCode: 0,
        duration: '0.042s',
        truncated: false,
        scanLimitReached: false,
        reason: '',
      },
      startedAt: date(),
      finishedAt: date(),
      outputStored: true,
      stepCount: 0,
    },
    {
      jobId: 'job-20261013-0042',
      taskId: 'task-02',
      hostId: 'host-02',
      hostname: 'web-02',
      result: {
        status: 'TASK_STATUS_OFFLINE',
        duration: '0s',
        truncated: false,
        scanLimitReached: false,
        reason: 'HOST_OFFLINE',
      },
      outputStored: false,
      stepCount: 0,
    },
    {
      jobId: 'job-20261013-0043',
      taskId: 'task-03',
      hostId: 'host-01',
      hostname: 'web-01',
      result: {
        status: 'TASK_STATUS_RUNNING',
        duration: '0s',
        truncated: false,
        scanLimitReached: false,
        reason: '',
      },
      startedAt: date(),
      outputStored: false,
      stepCount: 0,
    },
    {
      jobId: 'job-20261013-0043',
      taskId: 'task-04',
      hostId: 'host-03',
      hostname: 'web-03',
      result: {
        status: 'TASK_STATUS_PENDING',
        duration: '0s',
        truncated: false,
        scanLimitReached: false,
        reason: '',
      },
      outputStored: false,
      stepCount: 0,
    },
  ]
  const jobs: Job[] = [
    {
      jobId: 'job-20261013-0042',
      action: actions[0].name,
      catalog: catalogs[0].catalog,
      actionSha256: zeros,
      subjectId: 'sa-01',
      reason: 'job.reason.inspect',
      status: 'JOB_STATUS_PARTIALLY_FAILED',
      createdAt: date(),
      finishedAt: date(),
      totalTasks: '2',
      counts: [
        { status: 'TASK_STATUS_SUCCEEDED', count: '1' },
        { status: 'TASK_STATUS_OFFLINE', count: '1' },
      ],
      policyVersion: '2',
    },
    {
      jobId: 'job-20261013-0043',
      action: actions[0].name,
      catalog: catalogs[0].catalog,
      actionSha256: zeros,
      subjectId: 'sa-01',
      reason: 'job.reason.inspect',
      status: 'JOB_STATUS_RUNNING',
      createdAt: date(),
      totalTasks: '2',
      counts: [
        { status: 'TASK_STATUS_RUNNING', count: '1' },
        { status: 'TASK_STATUS_PENDING', count: '1' },
      ],
      policyVersion: '2',
    },
  ]
  const output: Record<string, string> = {
    'job-20261013-0042/web-01/OUTPUT_STREAM_STDOUT':
      'service=api status=active',
    'job-20261013-0042/web-01/OUTPUT_STREAM_STDERR': '',
  }
  return {
    hosts,
    users,
    sessionId: 'user-01',
    catalogs,
    actions,
    policies,
    accounts,
    tokens,
    tasks,
    jobs,
    output,
    joinTokens: [
      {
        tokenId: 'join-01',
        maxUses: 10,
        usedCount: 3,
        createdAt: date(),
        expiresAt: date(1),
      },
    ] as import('@/api/types').JoinToken[],
    mappings: [
      { providerId: 'oidc', group: 'ops-admins', roles: ['admin'] },
      { providerId: 'ldap', group: 'audit-readers', roles: ['auditor'] },
      { providerId: 'oidc', group: 'ops-viewers', roles: ['viewer'] },
    ] as RoleMapping[],
    mappingRevision: '1',
  }
}
let state = seed()
let auditPromise: Promise<AuditEvent[]> | undefined
const imports = new Map<
  string,
  {
    preview: HostImportPreview
    rows: HostImportRow[]
    revisions: { hostId: string; revision: string }[]
    userId: string
    updatedCount?: string
  }
>()
const tests = new Map<
  string,
  {
    test: PolicyTest
    candidate: PolicyRules
    changes: PolicyChange[]
    snapshot: string
    userId: string
  }
>()
export function resetMock() {
  state = seed()
  auditPromise = undefined
  imports.clear()
  tests.clear()
}
const snapshot = () =>
  JSON.stringify([state.hosts, state.users, state.accounts, state.catalogs])

function evaluate(
  rules: PolicyRule[],
  host: Host,
  test: PolicyTestCase,
): PolicyDecision {
  const user = state.users.find((u) => u.userId === test.subjectId)
  const account = state.accounts.find((a) => a.accountId === test.subjectId)
  if (!user && !account) throw new ApiError('error.notFound')
  const roles = user?.effectiveRoles ?? account?.roles ?? []
  const teams = user?.teams ?? account?.teams ?? []
  const owner = account?.ownerUserId ?? user?.userId ?? ''
  const action = required(state.actions.find((a) => a.name === test.action))
  if (!Object.keys(host.authorizationLabels).length)
    return { effect: 'POLICY_EFFECT_DENY', matchedRules: [], errorReason: '' }
  const matched = rules.filter((rule) => {
    // CIDR evaluation is deliberately unsupported in the local mock; never claim an allow.
    if (rule.sourceCidrs.length) throw new ApiError('error.mockCidr')
    const hour = rule.hours
      ? Number(
          new Intl.DateTimeFormat('en', {
            timeZone: rule.hours.timezone,
            hour: 'numeric',
            hourCycle: 'h23',
          }).format(new Date(test.at)),
        )
      : 0
    return (
      (rule.roles.includes('*') || rule.roles.some((r) => roles.includes(r))) &&
      (!rule.teams.length || rule.teams.some((t) => teams.includes(t))) &&
      (!rule.owners.length || rule.owners.includes(owner)) &&
      rule.operations.includes(test.operation) &&
      ((!rule.actions.length && !rule.risks.length) ||
        rule.actions.includes(action.name) ||
        rule.risks.includes(action.risk)) &&
      Object.entries(rule.hostLabels).every(
        ([k, v]) => host.authorizationLabels[k] === v,
      ) &&
      (!rule.hours || (hour >= rule.hours.from && hour < rule.hours.to))
    )
  })
  return {
    effect: matched.some((r) => r.effect === 'POLICY_EFFECT_DENY')
      ? 'POLICY_EFFECT_DENY'
      : matched.length
        ? 'POLICY_EFFECT_ALLOW'
        : 'POLICY_EFFECT_DENY',
    matchedRules: matched.map((r) => r.name),
    errorReason: '',
  }
}
async function auditEvents() {
  auditPromise ??= (async () => {
    const events: AuditEvent[] = []
    for (let i = 1; i <= 3; i++) {
      const payload = {
        seq: String(i),
        at: date(i === 1 ? -1 : 0),
        subjectId: 'sa-01',
        operation: 'execute_action',
        hostname: `web-0${i}`,
        action: 'journal_view_log',
        jobId: 'job-20261013-0042',
        taskId: `task-0${i}`,
        decision: 'allow',
        matchedRules: ['readonly-all'],
        policyVersion: '2',
        outputs: [],
      }
      const prevHash = events.at(-1)?.hash ?? zeros
      const hashInput = toBase64(JSON.stringify(payload))
      const bytes = new Uint8Array([
        ...base64ToBytes(prevHash),
        ...base64ToBytes(hashInput),
      ])
      events.push({
        ...payload,
        prevHash,
        hashInput,
        hash: await sha256(bytes),
      })
    }
    return events
  })()
  return auditPromise
}
export async function verifyChain(events: AuditEvent[]) {
  let prev = zeros
  for (let i = 0; i < events.length; i++) {
    const event = events[i]
    const digest = await sha256(
      new Uint8Array([
        ...base64ToBytes(prev),
        ...base64ToBytes(event.hashInput),
      ]),
    )
    if (
      event.seq !== String(i + 1) ||
      event.prevHash !== prev ||
      event.hash !== digest
    )
      return {
        valid: false,
        checkedCount: String(i),
        firstInvalidSeq: event.seq,
        reason: 'audit.invalid',
        actualPrecedingHash: zeros,
        actualFinalHash: prev,
        externallyAnchored: false,
      }
    prev = event.hash
  }
  return {
    valid: true,
    checkedCount: String(events.length),
    reason: '',
    actualPrecedingHash: zeros,
    actualFinalHash: prev,
    externallyAnchored: false,
  }
}
function checkTest(testId: string, baseVersion: string, rules: PolicyRules) {
  const test = required(tests.get(testId))
  if (
    state.policies[0].version !== baseVersion ||
    test.test.baseVersion !== baseVersion ||
    test.snapshot !== snapshot() ||
    test.userId !== state.sessionId ||
    Date.parse(test.test.expiresAt) <= Date.now() ||
    JSON.stringify(rules) !== JSON.stringify(test.candidate)
  )
    throw new ApiError('error.stalePolicy')
  if (!test.test.retainsPolicyAdministrator)
    throw new ApiError('error.policyLockout')
}

export const mockApi: ConsoleApi = {
  async logout() {},
  async getCurrentSession() {
    return {
      user: copy(
        required(state.users.find((u) => u.userId === state.sessionId)),
      ),
      client: 'LOGIN_CLIENT_CONSOLE',
      expiresAt: date(1),
      csrfToken: 'local-mock-only',
    }
  },
  async getLoginMethods() {
    return {
      methods: [
        { providerId: 'oidc', displayName: 'OIDC', kind: 'oidc' },
        { providerId: 'ldap', displayName: 'LDAP', kind: 'ldap' },
      ],
    }
  },
  async beginOidcLogin() {
    state.sessionId = 'user-01'
    return { authorizationUrl: '/' }
  },
  async loginLdap({ username, password }) {
    if (!username.trim() || !password) throw new ApiError('error.required')
    // No password is retained in fixtures, browser storage, logs, or mutation data.
    const user = required(
      state.users.find((u) => u.username === username.trim()),
    )
    state.sessionId = user.userId
    return { user: copy(user) }
  },
  async listHosts({ query = {} } = {}) {
    const hosts = state.hosts.filter(
      (h) =>
        (!query.hostname || h.hostname.includes(query.hostname)) &&
        selected(h, query.selector ?? '') &&
        (query.online === undefined || h.online === query.online) &&
        (!query.agentVersion || h.agentVersion === query.agentVersion) &&
        (!query.loadedCatalog ||
          h.loadedCatalogs.some(
            (c) =>
              c.catalogId === query.loadedCatalog?.catalogId &&
              c.version === query.loadedCatalog.version,
          )),
    )
    const counts = new Map<
      string,
      { key: string; value: string; count: string }
    >()
    for (const host of hosts)
      for (const [key, value] of Object.entries(host.authorizationLabels)) {
        const id = `${key}=${value}`
        counts.set(id, {
          key,
          value,
          count: String(Number(counts.get(id)?.count ?? 0) + 1),
        })
      }
    return {
      hosts: copy(hosts),
      page,
      totalCount: String(hosts.length),
      authorizationLabelCounts: [...counts.values()],
      labelCountsTruncated: false,
    }
  },
  async getHost({ hostname }) {
    return {
      host: copy(required(state.hosts.find((h) => h.hostname === hostname))),
    }
  },
  async setHostLabels({ targets, expectedCount, changes, expectedRevisions }) {
    const hosts = targets.hosts
      ? state.hosts.filter((h) => targets.hosts.names.includes(h.hostname))
      : state.hosts.filter((h) => selected(h, targets.selector))
    if (
      String(hosts.length) !== expectedCount ||
      expectedRevisions.length !== hosts.length ||
      hosts.some(
        (h) =>
          !expectedRevisions.some(
            (r) => r.hostId === h.hostId && r.revision === h.revision,
          ),
      )
    )
      throw new ApiError('error.stalePreview')
    for (const [key, value] of Object.entries(changes.set)) {
      validateLabel(key, value)
      if (changes.remove.includes(key)) throw new ApiError('error.labels')
    }
    for (const key of changes.remove) validateLabel(key, '')
    for (const host of hosts) {
      Object.assign(host.authorizationLabels, changes.set)
      for (const key of changes.remove) delete host.authorizationLabels[key]
      host.revision = bump(host.revision)
    }
    return { updatedCount: String(hosts.length) }
  },
  async previewHostImport({ csv }) {
    const raw = base64ToBytes(csv)
    if (raw.length > 524288) throw new ApiError('error.csvLimit')
    const [header, ...values] = csvRows(
      new TextDecoder('utf-8', { fatal: true }).decode(raw),
    )
    if (
      !header ||
      header[0] !== 'hostname' ||
      header.length < 2 ||
      !values.length ||
      values.length > 5000
    )
      throw new ApiError('error.csv')
    const seenHosts = new Set<string>()
    const keys = header.slice(1).map((h) => h.split(':'))
    const invalidHeader =
      keys.some(
        (parts) =>
          parts.length !== 2 ||
          !['set', 'remove'].includes(parts[0]) ||
          !parts[1],
      ) || new Set(keys.map(([, key]) => key)).size !== keys.length
    const revisions: { hostId: string; revision: string }[] = []
    const rows: HostImportRow[] = values.map((cells, i) => {
      const host = state.hosts.find((h) => h.hostname === cells[0])
      const before = copy(host?.authorizationLabels ?? {})
      const after = copy(before)
      const violations: HostImportRow['violations'] = []
      const add = (description: string) =>
        violations.push({ field: 'csv', description, allowedValues: [] })
      if (invalidHeader || cells.length !== header.length) add('error.csv')
      if (!host) add('error.notFound')
      if (seenHosts.has(cells[0])) add('error.csvDuplicate')
      seenHosts.add(cells[0])
      if (host) revisions.push({ hostId: host.hostId, revision: host.revision })
      if (!invalidHeader && cells.length === header.length)
        keys.forEach(([op, key], index) => {
          try {
            validateLabel(key, cells[index + 1])
            if (op === 'set') after[key] = cells[index + 1]
            else if (cells[index + 1] === 'true') delete after[key]
            else if (cells[index + 1] !== '') add('error.csvRemove')
          } catch {
            add('error.labels')
          }
        })
      return { line: i + 2, hostname: cells[0], before, after, violations }
    })
    const preview: HostImportPreview = {
      previewId: crypto.randomUUID(),
      csvSha256: await sha256(raw),
      rowCount: String(rows.length),
      invalidRowCount: String(rows.filter((r) => r.violations.length).length),
      expiresAt: date(10 / 1440),
    }
    imports.set(preview.previewId, {
      preview,
      rows,
      revisions,
      userId: state.sessionId,
    })
    return { preview: copy(preview) }
  },
  async getHostImportPreview({ previewId }) {
    const p = required(imports.get(previewId))
    return { preview: copy(p.preview), rows: copy(p.rows), page }
  },
  async executeHostImport({ previewId }) {
    const p = required(imports.get(previewId))
    if (p.userId !== state.sessionId) throw new ApiError('error.stalePreview')
    if (p.updatedCount !== undefined) return { updatedCount: p.updatedCount }
    if (
      Date.parse(p.preview.expiresAt) <= Date.now() ||
      p.preview.invalidRowCount !== '0' ||
      p.revisions.some(
        (r) =>
          !state.hosts.some(
            (h) => h.hostId === r.hostId && h.revision === r.revision,
          ),
      )
    )
      throw new ApiError('error.stalePreview')
    for (const row of p.rows) {
      const host = required(
        state.hosts.find((h) => h.hostname === row.hostname),
      )
      host.authorizationLabels = copy(row.after)
      host.revision = bump(host.revision)
    }
    p.updatedCount = String(p.rows.length)
    return { updatedCount: p.updatedCount }
  },
  async deleteHost({ hostId, expectedRevision }) {
    const host = required(state.hosts.find((h) => h.hostId === hostId))
    if (host.revision !== expectedRevision)
      throw new ApiError('error.stalePreview')
    state.hosts = state.hosts.filter((h) => h.hostId !== hostId)
  },
  async listJoinTokens() {
    return { tokens: copy(state.joinTokens), page }
  },
  async createJoinToken({ maxUses, ttl }) {
    const seconds = Number(ttl.replace(/s$/, ''))
    if (
      !Number.isInteger(maxUses) ||
      maxUses < 1 ||
      !Number.isFinite(seconds) ||
      seconds <= 0
    )
      throw new ApiError('error.positiveInteger')
    const token = {
      tokenId: `join-${crypto.randomUUID()}`,
      maxUses,
      usedCount: 0,
      createdAt: date(),
      expiresAt: date(seconds / 86400),
    }
    state.joinTokens.unshift(token)
    return {
      token: copy(token),
      secret: random('aops_join_'),
      upstream: 'gateway.example:443',
      caPin: `sha256:${'0'.repeat(64)}`,
    }
  },
  async revokeJoinToken({ tokenId }) {
    required(state.joinTokens.find((t) => t.tokenId === tokenId)).revokedAt =
      date()
  },
  async listCatalogs() {
    return { catalogs: copy(state.catalogs), page }
  },
  async listActions({ catalog }) {
    required(state.catalogs.find((c) => c.catalog.version === catalog.version))
    return {
      actions: copy(
        state.actions.slice(0, catalog.version === '20261001090000' ? 1 : 2),
      ),
      page,
    }
  },
  async getAction({ catalog, action }) {
    return {
      action: copy(required(state.actions.find((a) => a.name === action))),
      catalog,
      definitionJson: toBase64(
        JSON.stringify(
          action === 'journal_view_log'
            ? definition
            : {
                ...definition,
                params: { service: definition.params.service },
                exec: ['/usr/bin/systemctl', 'restart', '{service}'],
                timeout: '30s',
              },
        ),
      ),
    }
  },
  async getCatalogDistribution() {
    const counts = new Map<string, number>()
    for (const h of state.hosts)
      for (const c of h.loadedCatalogs)
        counts.set(c.version, (counts.get(c.version) ?? 0) + 1)
    return {
      versions: [...counts].map(([version, count]) => ({
        catalog: { catalogId: 'default', version },
        hostCount: String(count),
      })),
      notLoadedHostCount: String(
        state.hosts.filter((h) => !h.loadedCatalogs.length).length,
      ),
      page,
    }
  },
  async getPolicy({ version } = {}) {
    return {
      policy: copy(
        required(
          version
            ? state.policies.find((p) => p.version === version)
            : state.policies[0],
        ),
      ),
    }
  },
  async listPolicyHistory() {
    return { policies: copy(state.policies), page }
  },
  async testPolicy({ baseVersion, rules, historicalVersion, cases }) {
    if (baseVersion !== state.policies[0].version)
      throw new ApiError('error.stalePolicy')
    const candidate = copy(
      rules ??
        required(state.policies.find((p) => p.version === historicalVersion))
          .rules,
    )
    if (
      candidate.rules.some(
        (r) =>
          !r.roles.length ||
          !r.operations.length ||
          r.effect === 'POLICY_EFFECT_UNSPECIFIED',
      )
    )
      throw new ApiError('error.required')
    const changes: PolicyChange[] = []
    const inputs: PolicyTestCase[] = cases.length
      ? cases
      : state.accounts.flatMap((a) =>
          state.actions.map((action) => ({
            subjectId: a.accountId,
            operation: 'execute_action',
            action: action.name,
            targets: { hosts: { names: state.hosts.map((h) => h.hostname) } },
            at: date(),
            sourceIp: '',
          })),
        )
    inputs.forEach((test, caseIndex) => {
      const hosts = test.targets.hosts
        ? state.hosts.filter((h) =>
            test.targets.hosts?.names.includes(h.hostname),
          )
        : state.hosts.filter((h) => selected(h, test.targets.selector ?? ''))
      for (const host of hosts)
        changes.push({
          caseIndex,
          host: host.hostname,
          before: evaluate(state.policies[0].rules.rules, host, test),
          after: evaluate(candidate.rules, host, test),
        })
    })
    const test: PolicyTest = {
      testId: crypto.randomUUID(),
      baseVersion,
      candidateSha256: await sha256(
        new TextEncoder().encode(JSON.stringify(candidate)),
      ),
      evaluatedCount: String(changes.length),
      changedCount: String(
        changes.filter((c) => c.before.effect !== c.after.effect).length,
      ),
      retainsPolicyAdministrator: true,
      expiresAt: date(10 / 1440),
    }
    // console-user is the mock bootstrap administrator. The gateway's identity module owns real lockout checking (design P5).
    tests.set(test.testId, {
      test,
      candidate,
      changes,
      snapshot: snapshot(),
      userId: state.sessionId,
    })
    return { test: copy(test) }
  },
  async getPolicyTestChanges({ testId }) {
    return { changes: copy(required(tests.get(testId)).changes), page }
  },
  async savePolicy({ baseVersion, rules, testId, reason }) {
    checkTest(testId, baseVersion, rules)
    const policy = {
      version: bump(baseVersion),
      rules: copy(rules),
      createdAt: date(),
      createdBy: state.sessionId,
      reason,
    }
    state.policies.unshift(policy)
    return { policy: copy(policy) }
  },
  async rollbackPolicy({ baseVersion, targetVersion, testId, reason }) {
    const rules = required(
      state.policies.find((p) => p.version === targetVersion),
    ).rules
    checkTest(testId, baseVersion, rules)
    const policy = {
      version: bump(baseVersion),
      rules: copy(rules),
      createdAt: date(),
      createdBy: state.sessionId,
      reason,
      rolledBackFrom: targetVersion,
    }
    state.policies.unshift(policy)
    return { policy: copy(policy) }
  },
  async listServiceAccounts() {
    return { accounts: copy(state.accounts), page }
  },
  async createServiceAccount(input) {
    if (state.accounts.some((a) => a.name === input.name))
      throw new ApiError('error.duplicateName')
    required(state.users.find((u) => u.userId === input.ownerUserId))
    const account = {
      ...copy(input),
      accountId: `sa-${crypto.randomUUID()}`,
      revision: '1',
      createdAt: date(),
    }
    state.accounts.unshift(account)
    return { account: copy(account) }
  },
  async listServiceAccountTokens({ accountId }) {
    return {
      tokens: copy(state.tokens.filter((t) => t.accountId === accountId)),
      page,
    }
  },
  async createServiceAccountToken({ accountId, validDays = 30, description }) {
    required(state.accounts.find((a) => a.accountId === accountId))
    if (!Number.isInteger(validDays) || validDays < 1 || validDays > 365)
      throw new ApiError('error.tokenTtl')
    const token = {
      tokenId: crypto.randomUUID(),
      accountId,
      description,
      createdAt: date(),
      expiresAt: date(validDays),
    }
    state.tokens.push(token)
    return { token: copy(token), secret: random('aops_') }
  },
  async revokeServiceAccountToken({ accountId, tokenId }) {
    required(
      state.tokens.find(
        (t) => t.accountId === accountId && t.tokenId === tokenId,
      ),
    ).revokedAt = date()
  },
  async listJobs({ statuses = [], action } = {}) {
    return {
      jobs: copy(
        state.jobs.filter(
          (j) =>
            (!statuses.length || statuses.includes(j.status)) &&
            (!action || j.action.includes(action)),
        ),
      ),
      page,
    }
  },
  async getJob({ jobId }) {
    return { job: copy(required(state.jobs.find((j) => j.jobId === jobId))) }
  },
  async listTasks({ jobId }) {
    required(state.jobs.find((j) => j.jobId === jobId))
    return { tasks: copy(state.tasks.filter((t) => t.jobId === jobId)), page }
  },
  async getJobOutput({ jobId, hostname, stream, offset, limitBytes }) {
    const user = required(state.users.find((u) => u.userId === state.sessionId))
    if (!user.effectiveRoles.some((r) => ['admin', 'auditor'].includes(r)))
      throw new ApiError('error.outputDenied')
    const text = required(state.output[`${jobId}/${hostname}/${stream}`])
    const bytes = new TextEncoder().encode(text)
    const start = Number(offset)
    if (!Number.isSafeInteger(start) || start < 0 || start > bytes.length)
      throw new ApiError('error.outputOffset')
    const data = bytes.slice(
      start,
      start + Math.min(limitBytes || 16384, 24576),
    )
    return {
      data: bytesToBase64(data),
      nextOffset: String(start + data.length),
      eof: start + data.length === bytes.length,
      truncated: false,
      scanLimitReached: false,
      outputStored: true,
      outputTrust: 'OUTPUT_TRUST_UNTRUSTED',
      output: {
        sizeBytes: String(bytes.length),
        sha256: await sha256(bytes),
        truncated: false,
      },
    }
  },
  async cancelJob({ jobId }) {
    const job = required(state.jobs.find((j) => j.jobId === jobId))
    if (['JOB_STATUS_QUEUED', 'JOB_STATUS_RUNNING'].includes(job.status)) {
      job.status = 'JOB_STATUS_CANCELLED'
      job.finishedAt = date()
      for (const task of state.tasks.filter((t) => t.jobId === jobId))
        if (
          ['TASK_STATUS_PENDING', 'TASK_STATUS_RUNNING'].includes(
            task.result.status,
          )
        )
          task.result.status = 'TASK_STATUS_CANCELLED'
      job.counts = state.tasks
        .filter((t) => t.jobId === jobId)
        .reduce<Job['counts']>((counts, task) => {
          const count = counts.find((c) => c.status === task.result.status)
          if (count) count.count = bump(count.count)
          else counts.push({ status: task.result.status, count: '1' })
          return counts
        }, [])
    }
    return { job: copy(job) }
  },
  async listAuditEvents({ query = {} } = {}) {
    return {
      events: copy(
        (await auditEvents()).filter(
          (e) =>
            (!query.time?.from || e.at >= query.time.from) &&
            (!query.time?.to || e.at < query.time.to) &&
            (!query.subjectId || e.subjectId.includes(query.subjectId)) &&
            (!query.hostname || e.hostname.includes(query.hostname)) &&
            (!query.action || e.action.includes(query.action)),
        ),
      ),
      page,
    }
  },
  async verifyAudit({ fromSeq, toSeq }) {
    const events = await auditEvents()
    if (fromSeq !== '1' || toSeq !== String(events.length))
      throw new ApiError('error.auditRange')
    return verifyChain(events)
  },
  async listUsers() {
    return { users: copy(state.users), page }
  },
  async listRoles() {
    return {
      roles: defaultRoles.map((name) => ({
        name,
        description: `role.${name}`,
      })),
      page,
    }
  },
  async setUserRoles({ userId, manualRoles, expectedRevision }) {
    const user = required(state.users.find((u) => u.userId === userId))
    if (user.revision !== expectedRevision)
      throw new ApiError('error.stalePreview')
    user.manualRoles = copy(manualRoles)
    user.effectiveRoles = [...new Set([...user.mappedRoles, ...manualRoles])]
    user.revision = bump(user.revision)
    return { user: copy(user) }
  },
  async getRoleMappings() {
    return { mappings: copy(state.mappings), revision: state.mappingRevision }
  },
  async saveRoleMappings({ mappings, expectedRevision }) {
    if (state.mappingRevision !== expectedRevision)
      throw new ApiError('error.stalePreview')
    state.mappings = copy(mappings)
    state.mappingRevision = bump(state.mappingRevision)
    for (const user of state.users) {
      user.mappedRoles = [
        ...new Set(
          mappings
            .filter(
              (m) =>
                m.providerId === user.providerId &&
                user.groups.includes(m.group),
            )
            .flatMap((m) => m.roles),
        ),
      ]
      user.effectiveRoles = [
        ...new Set([...user.mappedRoles, ...user.manualRoles]),
      ]
      user.revision = bump(user.revision)
    }
    return { revision: state.mappingRevision }
  },
  async getSystemStatus() {
    return {
      observedAt: date(),
      status: 'HEALTH_STATUS_HEALTHY',
      onlineHosts: String(state.hosts.filter((h) => h.online).length),
      offlineHosts: String(state.hosts.filter((h) => !h.online).length),
      runningJobs: String(
        state.jobs.filter((j) => j.status === 'JOB_STATUS_RUNNING').length,
      ),
      failedJobsLast24Hours: String(
        state.jobs.filter(
          (j) =>
            ['JOB_STATUS_PARTIALLY_FAILED', 'JOB_STATUS_FAILED'].includes(
              j.status,
            ) && Date.parse(j.createdAt) >= Date.now() - 86400000,
        ).length,
      ),
      expiringCatalogs: String(
        state.catalogs.filter(
          (c) =>
            c.current && Date.parse(c.expiresAt) <= Date.now() + 14 * 86400000,
        ).length,
      ),
      expiringServiceAccountTokens: String(
        state.tokens.filter(
          (t) =>
            !t.revokedAt &&
            Date.parse(t.expiresAt) <= Date.now() + 7 * 86400000,
        ).length,
      ),
      dependencies: [
        { name: 'PostgreSQL', status: 'HEALTH_STATUS_HEALTHY', reason: '' },
        {
          name: 'health.objectStorage',
          status: 'HEALTH_STATUS_HEALTHY',
          reason: '',
        },
      ],
      limits: {
        maxMessageBytes: 1048576,
        maxChunkBytes: 65536,
        defaultPageSize: 50,
        maxPageSize: 200,
        defaultOutputPageBytes: 16384,
        maxOutputPageBytes: 24576,
        maxCatalogBytes: '67108864',
        maxCsvBytes: 524288,
      },
    }
  },
  async listGatewayInstances() {
    return {
      instances: ['gateway-01', 'gateway-02'].map((instanceId, i) => ({
        instanceId,
        version: '0.1.0',
        draining: false,
        connectedHosts: String(
          i === 0
            ? Math.ceil(state.hosts.filter((h) => h.online).length / 2)
            : Math.floor(state.hosts.filter((h) => h.online).length / 2),
        ),
        startedAt: date(-10),
        lastSeen: date(),
        dependencies: [],
      })),
      page,
    }
  },
  async getAgentVersionDistribution() {
    const versions = [...new Set(state.hosts.map((h) => h.agentVersion))]
    return {
      versions: versions.map((agentVersion) => ({
        agentVersion,
        hostCount: String(
          state.hosts.filter((h) => h.agentVersion === agentVersion).length,
        ),
        onlineCount: String(
          state.hosts.filter((h) => h.agentVersion === agentVersion && h.online)
            .length,
        ),
      })),
      page,
    }
  },
}
