import {
  fromJson,
  toJson,
  type DescMethodUnary,
  type JsonObject,
  type JsonValue,
  type Message,
} from '@bufbuild/protobuf'
import {
  Code,
  ConnectError,
  createClient,
  type CallOptions,
} from '@connectrpc/connect'
import { createConnectTransport } from '@connectrpc/connect-web'
import { AuditService } from '@/gen/allowops/v1/audit_pb'
import { CatalogService } from '@/gen/allowops/v1/catalog_pb'
import { ErrorDetailSchema } from '@/gen/allowops/v1/common_pb'
import { HostService, JoinTokenService } from '@/gen/allowops/v1/host_pb'
import {
  AuthService,
  ServiceAccountService,
  UserService,
} from '@/gen/allowops/v1/identity_pb'
import { JobService } from '@/gen/allowops/v1/job_pb'
import { PolicyService } from '@/gen/allowops/v1/policy_pb'
import { SystemService } from '@/gen/allowops/v1/system_pb'
import { ApiError } from './error'
import type { ConsoleApi } from './types'

const transport = createConnectTransport({
  baseUrl: window.location.origin,
  useBinaryFormat: false,
  fetch: (input, init) =>
    globalThis.fetch(input, { ...init, credentials: 'same-origin' }),
})
const auth = createClient(AuthService, transport)
const writes = new Set<keyof ConsoleApi>([
  'logout',
  'setHostLabels',
  'previewHostImport',
  'executeHostImport',
  'deleteHost',
  'createJoinToken',
  'revokeJoinToken',
  'testPolicy',
  'savePolicy',
  'rollbackPolicy',
  'createServiceAccount',
  'createServiceAccountToken',
  'revokeServiceAccountToken',
  'cancelJob',
  'setUserRoles',
  'saveRoleMappings',
])

function apiError(error: unknown, method: keyof ConsoleApi) {
  const rpc = ConnectError.from(error)
  const detail = rpc.findDetails(ErrorDetailSchema)[0]
  const reason = detail?.reason
  const retryAfter = detail?.retryAfter
  const retryAfterMs = retryAfter
    ? Number(retryAfter.seconds) * 1000 + Math.round(retryAfter.nanos / 1e6)
    : undefined
  const key =
    reason === 'AUDIT_RESULT_UNAVAILABLE'
      ? 'error.auditResultUnavailable'
      : rpc.code === Code.Unauthenticated
        ? 'error.unauthenticated'
        : rpc.code === Code.PermissionDenied
          ? 'error.permissionDenied'
          : rpc.code === Code.NotFound
            ? 'error.notFound'
            : rpc.code === Code.Aborted
              ? ['testPolicy', 'savePolicy', 'rollbackPolicy'].includes(method)
                ? 'error.stalePolicy'
                : 'error.conflict'
              : rpc.code === Code.Unavailable
                ? 'error.unavailable'
                : rpc.code === Code.ResourceExhausted
                  ? 'error.resourceExhausted'
                  : rpc.code === Code.InvalidArgument
                    ? 'error.invalidArgument'
                    : 'common.error'
  return new ApiError(key, rpc.code, reason || undefined, retryAfterMs)
}

// P8A pages use ProtoJSON (uint64 strings, Base64 bytes, symbolic enums).
// Generated descriptors validate requests and preserve those encodings.
function bind<K extends keyof ConsoleApi>(
  name: K,
  method: DescMethodUnary,
  items?: string,
): ConsoleApi[K] {
  const client = createClient(method.parent, transport)
  const invoke = client[method.localName] as (
    input: Message,
    options?: CallOptions,
  ) => Promise<Message>
  const call = async (input: JsonObject = {}) => {
    try {
      const headers = new Headers()
      if (writes.has(name)) {
        const session = await auth.getCurrentSession({})
        headers.set('X-CSRF-Token', session.csrfToken)
      }
      // Forms include undefined optional fields; protobuf JSON requires their absence.
      const request = JSON.parse(JSON.stringify(input)) as JsonObject
      const fetchPage = async (value: JsonObject) =>
        toJson(
          method.output,
          await invoke(fromJson(method.input, value), { headers }),
          { alwaysEmitImplicit: true },
        ) as JsonObject
      const result = await fetchPage(request)
      if (items) {
        let cursor = (result.page as JsonObject | undefined)?.nextPageToken
        while (typeof cursor === 'string' && cursor !== '') {
          const next = await fetchPage({
            ...request,
            page: { pageToken: cursor },
          })
          ;(result[items] as JsonValue[]).push(...(next[items] as JsonValue[]))
          cursor = (next.page as JsonObject | undefined)?.nextPageToken
          result.page = next.page
        }
      }
      return result
    } catch (error) {
      throw apiError(error, name)
    }
  }
  // This boundary adapts the generated wire schema to the existing page models.
  return call as unknown as ConsoleApi[K]
}

export const api: ConsoleApi = {
  getCurrentSession: bind(
    'getCurrentSession',
    AuthService.method.getCurrentSession,
  ),
  getLoginMethods: bind('getLoginMethods', AuthService.method.getLoginMethods),
  beginOidcLogin: bind('beginOidcLogin', AuthService.method.beginOidcLogin),
  loginLdap: bind('loginLdap', AuthService.method.loginLdap),
  logout: bind('logout', AuthService.method.logout),
  listHosts: bind('listHosts', HostService.method.listHosts, 'hosts'),
  getHost: bind('getHost', HostService.method.getHost),
  setHostLabels: bind('setHostLabels', HostService.method.setHostLabels),
  previewHostImport: bind(
    'previewHostImport',
    HostService.method.previewHostImport,
  ),
  getHostImportPreview: bind(
    'getHostImportPreview',
    HostService.method.getHostImportPreview,
    'rows',
  ),
  executeHostImport: bind(
    'executeHostImport',
    HostService.method.executeHostImport,
  ),
  deleteHost: bind('deleteHost', HostService.method.deleteHost),
  listJoinTokens: bind(
    'listJoinTokens',
    JoinTokenService.method.listJoinTokens,
    'tokens',
  ),
  createJoinToken: bind(
    'createJoinToken',
    JoinTokenService.method.createJoinToken,
  ),
  revokeJoinToken: bind(
    'revokeJoinToken',
    JoinTokenService.method.revokeJoinToken,
  ),
  listCatalogs: bind(
    'listCatalogs',
    CatalogService.method.listCatalogs,
    'catalogs',
  ),
  listActions: bind(
    'listActions',
    CatalogService.method.listActions,
    'actions',
  ),
  getAction: bind('getAction', CatalogService.method.getAction),
  getCatalogDistribution: bind(
    'getCatalogDistribution',
    CatalogService.method.getCatalogDistribution,
    'versions',
  ),
  getPolicy: bind('getPolicy', PolicyService.method.getPolicy),
  listPolicyHistory: bind(
    'listPolicyHistory',
    PolicyService.method.listPolicyHistory,
    'policies',
  ),
  testPolicy: bind('testPolicy', PolicyService.method.testPolicy),
  getPolicyTestChanges: bind(
    'getPolicyTestChanges',
    PolicyService.method.getPolicyTestChanges,
    'changes',
  ),
  savePolicy: bind('savePolicy', PolicyService.method.savePolicy),
  rollbackPolicy: bind('rollbackPolicy', PolicyService.method.rollbackPolicy),
  listServiceAccounts: bind(
    'listServiceAccounts',
    ServiceAccountService.method.listServiceAccounts,
    'accounts',
  ),
  createServiceAccount: bind(
    'createServiceAccount',
    ServiceAccountService.method.createServiceAccount,
  ),
  listServiceAccountTokens: bind(
    'listServiceAccountTokens',
    ServiceAccountService.method.listServiceAccountTokens,
    'tokens',
  ),
  createServiceAccountToken: bind(
    'createServiceAccountToken',
    ServiceAccountService.method.createServiceAccountToken,
  ),
  revokeServiceAccountToken: bind(
    'revokeServiceAccountToken',
    ServiceAccountService.method.revokeServiceAccountToken,
  ),
  listJobs: bind('listJobs', JobService.method.listJobs),
  getJob: bind('getJob', JobService.method.getJob),
  listTasks: bind('listTasks', JobService.method.listTasks, 'tasks'),
  getJobOutput: bind('getJobOutput', JobService.method.getJobOutput),
  cancelJob: bind('cancelJob', JobService.method.cancelJob),
  listAuditEvents: bind(
    'listAuditEvents',
    AuditService.method.listAuditEvents,
    'events',
  ),
  verifyAudit: bind('verifyAudit', AuditService.method.verifyAudit),
  listUsers: bind('listUsers', UserService.method.listUsers, 'users'),
  listRoles: bind('listRoles', UserService.method.listRoles, 'roles'),
  setUserRoles: bind('setUserRoles', UserService.method.setUserRoles),
  getRoleMappings: bind('getRoleMappings', UserService.method.getRoleMappings),
  saveRoleMappings: bind(
    'saveRoleMappings',
    UserService.method.saveRoleMappings,
  ),
  getSystemStatus: bind(
    'getSystemStatus',
    SystemService.method.getSystemStatus,
  ),
  listGatewayInstances: bind(
    'listGatewayInstances',
    SystemService.method.listGatewayInstances,
    'instances',
  ),
  getAgentVersionDistribution: bind(
    'getAgentVersionDistribution',
    SystemService.method.getAgentVersionDistribution,
    'versions',
  ),
}
