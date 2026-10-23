// Handwritten ProtoJSON DTOs for the P2 draft at main 199d5c6.
// uint64 = decimal string; bytes = Base64; Timestamp/Duration = JSON strings.
// Only messages used by this console are represented; no client is generated here.
export const jobStatuses = [
  'JOB_STATUS_QUEUED',
  'JOB_STATUS_RUNNING',
  'JOB_STATUS_SUCCEEDED',
  'JOB_STATUS_PARTIALLY_FAILED',
  'JOB_STATUS_FAILED',
  'JOB_STATUS_CANCELLED',
  'JOB_STATUS_DENIED',
] as const
export const taskStatuses = [
  'TASK_STATUS_PENDING',
  'TASK_STATUS_RUNNING',
  'TASK_STATUS_SUCCEEDED',
  'TASK_STATUS_FAILED',
  'TASK_STATUS_TIMEOUT',
  'TASK_STATUS_OFFLINE',
  'TASK_STATUS_SKIPPED',
  'TASK_STATUS_CANCELLED',
  'TASK_STATUS_UNSUPPORTED',
] as const
export const defaultRoles = [
  'admin',
  'operator',
  'auditor',
  'viewer',
  'publisher',
] as const
export type JobStatus = (typeof jobStatuses)[number] | 'JOB_STATUS_UNSPECIFIED'
export type TaskStatus =
  | (typeof taskStatuses)[number]
  | 'TASK_STATUS_UNSPECIFIED'
export type PolicyEffect =
  | 'POLICY_EFFECT_UNSPECIFIED'
  | 'POLICY_EFFECT_ALLOW'
  | 'POLICY_EFFECT_DENY'
export type HealthStatus =
  | 'HEALTH_STATUS_UNSPECIFIED'
  | 'HEALTH_STATUS_HEALTHY'
  | 'HEALTH_STATUS_DEGRADED'
  | 'HEALTH_STATUS_UNAVAILABLE'
export type Labels = Record<string, string>
export interface PageResponse {
  nextPageToken: string
}
export interface CatalogRef {
  catalogId: string
  version: string
}
export interface HostTargets {
  hosts: { names: string[] }
  selector?: never
} // OR selector, matching proto oneof
export type Targets = HostTargets | { selector: string; hosts?: never }
export interface Host {
  hostId: string
  hostname: string
  authorizationLabels: Labels
  reportedLabels: Labels
  online: boolean
  agentVersion: string
  loadedCatalogs: CatalogRef[]
  capabilities: {
    catalogSchemaVersions: number[]
    parameterTypes: string[]
    executionModes: string[]
    builtins: string[]
    outputFilters: string[]
    features: string[]
  }
  lastSeen: string
  registeredAt: string
  revision: string
}
export interface HostQuery {
  selector?: string
  hostname?: string
  online?: boolean
  agentVersion?: string
  loadedCatalog?: CatalogRef
}
export interface LabelChanges {
  set: Labels
  remove: string[]
}
export interface SetHostLabelsRequest {
  targets: Targets
  expectedCount: string
  changes: LabelChanges
  expectedRevisions: { hostId: string; revision: string }[]
}
export interface FieldViolation {
  field: string
  description: string
  allowedValues: string[]
}
export interface HostImportRow {
  line: number
  hostname: string
  before: Labels
  after: Labels
  violations: FieldViolation[]
}
export interface HostImportPreview {
  previewId: string
  csvSha256: string
  rowCount: string
  invalidRowCount: string
  expiresAt: string
}
export interface JoinToken {
  tokenId: string
  maxUses: number
  usedCount: number
  expiresAt: string
  createdAt: string
  revokedAt?: string
}
export interface CreateJoinTokenResponse {
  token: JoinToken
  secret: string
  upstream: string
  caPin: string
}
export interface CatalogVersion {
  catalog: CatalogRef
  schemaVersion: number
  createdAt: string
  expiresAt: string
  gitCommit: string
  envelopeSha256: string
  envelopeSizeBytes: string
  actionCount: number
  current: boolean
  publishedAt: string
}
export interface ActionSummary {
  name: string
  description: string
  risk: string
  idempotent: boolean
  executionMode: string
  builtin: string
  actionSha256: string
}
// This is the catalog schema inside GetAction.definitionJson, not a protobuf message.
export interface ActionDefinition {
  params?: Record<
    string,
    {
      type: string
      description: string
      [constraint: string]: unknown
    }
  >
  exec?: (string | string[])[]
  steps?: unknown[]
  script?: unknown
  args?: unknown[]
  builtin?: string
  builtin_config?: Record<string, unknown>
  on_error?: string
  exec_fallbacks?: string[]
  allow_interpreter?: boolean
  run_as?: string
  timeout: string
  max_output: string | number
  redact?: { builtin?: string[] | null; custom?: unknown[] }
}
export interface PolicyRule {
  name: string
  roles: string[]
  teams: string[]
  owners: string[]
  operations: string[]
  actions: string[]
  risks: string[]
  hostLabels: Labels
  hours?: { from: number; to: number; timezone: string }
  sourceCidrs: string[]
  effect: PolicyEffect
}
export interface PolicyRules {
  rules: PolicyRule[]
}
export interface PolicyVersion {
  version: string
  rules: PolicyRules
  createdAt: string
  createdBy: string
  reason: string
  rolledBackFrom?: string
}
export interface PolicyDecision {
  effect: PolicyEffect
  matchedRules: string[]
  errorReason: string
}
export interface PolicyTestCase {
  subjectId: string
  operation: string
  action: string
  targets: Targets
  at: string
  sourceIp: string
}
export interface PolicyChange {
  caseIndex: number
  host: string
  before: PolicyDecision
  after: PolicyDecision
}
export interface PolicyTest {
  testId: string
  baseVersion: string
  candidateSha256: string
  evaluatedCount: string
  changedCount: string
  retainsPolicyAdministrator: boolean
  expiresAt: string
}
export interface ServiceAccount {
  accountId: string
  name: string
  ownerUserId: string
  description: string
  roles: string[]
  teams: string[]
  revision: string
  createdAt: string
}
export interface ServiceAccountToken {
  tokenId: string
  accountId: string
  description: string
  createdAt: string
  expiresAt: string
  lastUsedAt?: string
  revokedAt?: string
}
export interface User {
  userId: string
  providerId: string
  username: string
  displayName: string
  email: string
  groups: string[]
  mappedRoles: string[]
  manualRoles: string[]
  effectiveRoles: string[]
  teams: string[]
  revision: string
}
export interface RoleMapping {
  providerId: string
  group: string
  roles: string[]
}
export interface Role {
  name: string
  description: string
}
export interface OutputMetadata {
  sizeBytes: string
  sha256: string
  truncated: boolean
}
export interface ExecutionResult {
  status: TaskStatus
  exitCode?: number
  duration: string
  truncated: boolean
  scanLimitReached: boolean
  stdout?: OutputMetadata
  stderr?: OutputMetadata
  reason: string
}
export interface Task {
  jobId: string
  taskId: string
  hostId: string
  hostname: string
  result: ExecutionResult
  startedAt?: string
  finishedAt?: string
  outputStored: boolean
  stepCount: number
}
export interface Job {
  jobId: string
  action: string
  catalog: CatalogRef
  actionSha256: string
  subjectId: string
  reason: string
  status: JobStatus
  createdAt: string
  finishedAt?: string
  totalTasks: string
  counts: { status: TaskStatus; count: string }[]
  policyVersion: string
}
export interface GetJobOutputResponse {
  data: string
  nextOffset: string
  eof: boolean
  truncated: boolean
  scanLimitReached: boolean
  outputStored: boolean
  outputTrust: 'OUTPUT_TRUST_UNTRUSTED' | 'OUTPUT_TRUST_UNSPECIFIED'
  output: OutputMetadata
}
export interface AuditEvent {
  seq: string
  prevHash: string
  hash: string
  at: string
  subjectId: string
  operation: string
  hostname: string
  action: string
  jobId: string
  taskId: string
  decision: string
  matchedRules: string[]
  policyVersion: string
  outputs: {
    objectPath: string
    sha256: string
    stream: 'OUTPUT_STREAM_STDOUT' | 'OUTPUT_STREAM_STDERR'
    stepIndex?: number
  }[]
  hashInput: string
  checkpointSeq?: string
  checkpointHash?: string
}
export interface AuditQuery {
  time?: { from?: string; to?: string }
  subjectId?: string
  hostname?: string
  action?: string
  jobId?: string
  operation?: string
}
export interface VerifyAuditResponse {
  valid: boolean
  checkedCount: string
  firstInvalidSeq?: string
  reason: string
  actualPrecedingHash: string
  actualFinalHash: string
  externallyAnchored: boolean
}
export interface DependencyHealth {
  name: string
  status: HealthStatus
  reason: string
}
export interface GatewayInstance {
  instanceId: string
  version: string
  draining: boolean
  connectedHosts: string
  startedAt: string
  lastSeen: string
  dependencies: DependencyHealth[]
}
export interface GatewayUpdate {
  latestVersion: string
  publishedAt?: string
  checkedAt?: string
}
export interface SystemStatus {
  observedAt: string
  status: HealthStatus
  onlineHosts: string
  offlineHosts: string
  runningJobs: string
  failedJobsLast24Hours: string
  expiringCatalogs: string
  expiringServiceAccountTokens: string
  dependencies: DependencyHealth[]
  limits: {
    maxMessageBytes: number
    maxChunkBytes: number
    defaultPageSize: number
    maxPageSize: number
    defaultOutputPageBytes: number
    maxOutputPageBytes: number
    maxCatalogBytes: string
    maxCsvBytes: number
  }
  updateCheckEnabled: boolean
  gatewayVersion: string
  gatewayUpdate?: GatewayUpdate
  updateCheckedAt?: string
  updateCheckError: string
  hostsBelowGatewayVersion: string
}
// Direct RPC-shaped methods. This is the single replacement point for Connect.
export interface ConsoleApi {
  getCurrentSession(): Promise<{
    user: User
    client: 'LOGIN_CLIENT_CONSOLE'
    expiresAt: string
    csrfToken: string
    gatewayVersion: string
    gatewayUpdate?: GatewayUpdate
  }>
  getLoginMethods(): Promise<{
    methods: { providerId: string; displayName: string; kind: string }[]
  }>
  beginOidcLogin(input: {
    providerId: string
    client: 'LOGIN_CLIENT_CONSOLE'
  }): Promise<{ authorizationUrl: string }>
  loginLdap(input: {
    providerId: string
    username: string
    password: string
    client: 'LOGIN_CLIENT_CONSOLE'
  }): Promise<{ user: User }>
  logout(): Promise<void>
  listHosts(input?: {
    query?: HostQuery
  }): Promise<{
    hosts: Host[]
    page: PageResponse
    totalCount: string
    authorizationLabelCounts: { key: string; value: string; count: string }[]
    labelCountsTruncated: boolean
  }>
  getHost(input: { hostname: string }): Promise<{ host: Host }>
  setHostLabels(input: SetHostLabelsRequest): Promise<{ updatedCount: string }>
  previewHostImport(input: {
    csv: string
  }): Promise<{ preview: HostImportPreview }>
  getHostImportPreview(input: {
    previewId: string
  }): Promise<{
    preview: HostImportPreview
    rows: HostImportRow[]
    page: PageResponse
  }>
  executeHostImport(input: {
    previewId: string
  }): Promise<{ updatedCount: string }>
  deleteHost(input: { hostId: string; expectedRevision: string }): Promise<void>
  listJoinTokens(): Promise<{ tokens: JoinToken[]; page: PageResponse }>
  createJoinToken(input: {
    maxUses: number
    ttl: string
  }): Promise<CreateJoinTokenResponse>
  revokeJoinToken(input: { tokenId: string }): Promise<void>
  listCatalogs(): Promise<{ catalogs: CatalogVersion[]; page: PageResponse }>
  listActions(input: {
    catalog: CatalogRef
  }): Promise<{ actions: ActionSummary[]; page: PageResponse }>
  getAction(input: {
    catalog: CatalogRef
    action: string
  }): Promise<{
    action: ActionSummary
    definitionJson: string
    catalog: CatalogRef
  }>
  getCatalogDistribution(input: { catalogId: string }): Promise<{
    versions: { catalog: CatalogRef; hostCount: string }[]
    notLoadedHostCount: string
    page: PageResponse
  }>
  getPolicy(input?: { version?: string }): Promise<{ policy: PolicyVersion }>
  listPolicyHistory(): Promise<{
    policies: PolicyVersion[]
    page: PageResponse
  }>
  testPolicy(input: {
    baseVersion: string
    rules?: PolicyRules
    historicalVersion?: string
    cases: PolicyTestCase[]
  }): Promise<{ test: PolicyTest }>
  getPolicyTestChanges(input: {
    testId: string
  }): Promise<{ changes: PolicyChange[]; page: PageResponse }>
  savePolicy(input: {
    baseVersion: string
    rules: PolicyRules
    testId: string
    reason: string
  }): Promise<{ policy: PolicyVersion }>
  rollbackPolicy(input: {
    baseVersion: string
    targetVersion: string
    testId: string
    reason: string
  }): Promise<{ policy: PolicyVersion }>
  listServiceAccounts(): Promise<{
    accounts: ServiceAccount[]
    page: PageResponse
  }>
  createServiceAccount(input: {
    name: string
    ownerUserId: string
    description: string
    roles: string[]
    teams: string[]
  }): Promise<{ account: ServiceAccount }>
  listServiceAccountTokens(input: {
    accountId: string
  }): Promise<{ tokens: ServiceAccountToken[]; page: PageResponse }>
  createServiceAccountToken(input: {
    accountId: string
    description: string
    validDays?: number
  }): Promise<{ token: ServiceAccountToken; secret: string }>
  revokeServiceAccountToken(input: {
    accountId: string
    tokenId: string
  }): Promise<void>
  listJobs(input?: {
    statuses?: JobStatus[]
    action?: string
    page?: { pageSize?: number; pageToken?: string }
  }): Promise<{ jobs: Job[]; page: PageResponse }>
  getJob(input: { jobId: string }): Promise<{ job: Job }>
  listTasks(input: {
    jobId: string
  }): Promise<{ tasks: Task[]; page: PageResponse }>
  getJobOutput(input: {
    jobId: string
    hostname: string
    stream: 'OUTPUT_STREAM_STDOUT' | 'OUTPUT_STREAM_STDERR'
    offset: string
    limitBytes?: number
  }): Promise<GetJobOutputResponse>
  cancelJob(input: { jobId: string }): Promise<{ job: Job }>
  listAuditEvents(input?: {
    query?: AuditQuery
  }): Promise<{ events: AuditEvent[]; page: PageResponse }>
  verifyAudit(input: {
    fromSeq: string
    toSeq: string
  }): Promise<VerifyAuditResponse>
  listUsers(): Promise<{ users: User[]; page: PageResponse }>
  listRoles(): Promise<{ roles: Role[]; page: PageResponse }>
  setUserRoles(input: {
    userId: string
    manualRoles: string[]
    expectedRevision: string
  }): Promise<{ user: User }>
  getRoleMappings(): Promise<{ mappings: RoleMapping[]; revision: string }>
  saveRoleMappings(input: {
    mappings: RoleMapping[]
    expectedRevision: string
  }): Promise<{ revision: string }>
  getSystemStatus(): Promise<SystemStatus>
  listGatewayInstances(): Promise<{
    instances: GatewayInstance[]
    page: PageResponse
  }>
  getAgentVersionDistribution(): Promise<{
    versions: { agentVersion: string; hostCount: string; onlineCount: string }[]
    page: PageResponse
  }>
}
