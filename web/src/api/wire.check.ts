// Compile-time checks that the console models in ./types.ts still match the
// generated ProtoJSON types in @/gen/allowops/v1 (protoc-gen-es json_types=true).
// This file has no runtime code. `pnpm typecheck` fails when a proto field that
// a console model uses is renamed, removed, or changes type.
import type {
  ListAuditEventsRequestJson,
  ListAuditEventsResponseJson,
  VerifyAuditRequestJson,
  VerifyAuditResponseJson,
} from '@/gen/allowops/v1/audit_pb'
import type {
  GetActionRequestJson,
  GetActionResponseJson,
  GetCatalogDistributionRequestJson,
  GetCatalogDistributionResponseJson,
  ListActionsRequestJson,
  ListActionsResponseJson,
  ListCatalogsRequestJson,
  ListCatalogsResponseJson,
} from '@/gen/allowops/v1/catalog_pb'
import type {
  CreateJoinTokenRequestJson,
  CreateJoinTokenResponseJson,
  DeleteHostRequestJson,
  DeleteHostResponseJson,
  ExecuteHostImportRequestJson,
  ExecuteHostImportResponseJson,
  GetHostImportPreviewRequestJson,
  GetHostImportPreviewResponseJson,
  GetHostRequestJson,
  GetHostResponseJson,
  ListHostsRequestJson,
  ListHostsResponseJson,
  ListJoinTokensRequestJson,
  ListJoinTokensResponseJson,
  PreviewHostImportRequestJson,
  PreviewHostImportResponseJson,
  RevokeJoinTokenRequestJson,
  RevokeJoinTokenResponseJson,
  SetHostLabelsRequestJson,
  SetHostLabelsResponseJson,
} from '@/gen/allowops/v1/host_pb'
import type {
  BeginOidcLoginRequestJson,
  BeginOidcLoginResponseJson,
  CreateServiceAccountRequestJson,
  CreateServiceAccountResponseJson,
  CreateServiceAccountTokenRequestJson,
  CreateServiceAccountTokenResponseJson,
  GetCurrentSessionRequestJson,
  GetCurrentSessionResponseJson,
  GetLoginMethodsRequestJson,
  GetLoginMethodsResponseJson,
  GetRoleMappingsRequestJson,
  GetRoleMappingsResponseJson,
  ListRolesRequestJson,
  ListRolesResponseJson,
  ListServiceAccountsRequestJson,
  ListServiceAccountsResponseJson,
  ListServiceAccountTokensRequestJson,
  ListServiceAccountTokensResponseJson,
  ListUsersRequestJson,
  ListUsersResponseJson,
  LoginLdapRequestJson,
  LoginLdapResponseJson,
  LogoutRequestJson,
  LogoutResponseJson,
  RevokeServiceAccountTokenRequestJson,
  RevokeServiceAccountTokenResponseJson,
  SaveRoleMappingsRequestJson,
  SaveRoleMappingsResponseJson,
  SetUserRolesRequestJson,
  SetUserRolesResponseJson,
} from '@/gen/allowops/v1/identity_pb'
import type {
  CancelJobRequestJson,
  CancelJobResponseJson,
  GetJobOutputRequestJson,
  GetJobOutputResponseJson,
  GetJobRequestJson,
  GetJobResponseJson,
  ListJobsRequestJson,
  ListJobsResponseJson,
  ListTasksRequestJson,
  ListTasksResponseJson,
} from '@/gen/allowops/v1/job_pb'
import type {
  GetPolicyRequestJson,
  GetPolicyResponseJson,
  GetPolicyTestChangesRequestJson,
  GetPolicyTestChangesResponseJson,
  ListPolicyHistoryRequestJson,
  ListPolicyHistoryResponseJson,
  RollbackPolicyRequestJson,
  RollbackPolicyResponseJson,
  SavePolicyRequestJson,
  SavePolicyResponseJson,
  TestPolicyRequestJson,
  TestPolicyResponseJson,
} from '@/gen/allowops/v1/policy_pb'
import type {
  GetAgentVersionDistributionRequestJson,
  GetAgentVersionDistributionResponseJson,
  GetSystemStatusRequestJson,
  GetSystemStatusResponseJson,
  ListGatewayInstancesRequestJson,
  ListGatewayInstancesResponseJson,
} from '@/gen/allowops/v1/system_pb'
import type {
  JobStatusJson,
  TaskStatusJson,
} from '@/gen/allowops/v1/common_pb'
import type { ConsoleApi, jobStatuses, taskStatuses } from './types'

// Lists the paths in D (a console model) that do not exist in J (the generated
// ProtoJSON type) or whose type is not assignable to it. Fields that the console
// does not model are allowed; every field it does model must exist in J.
type Diff<D, J, P extends string> = D extends unknown
  ? [NonNullable<D>] extends [never]
    ? never
    : [NonNullable<D>] extends [readonly (infer DE)[]]
      ? [NonNullable<J>] extends [readonly (infer JE)[]]
        ? Diff<DE, JE, `${P}[]`>
        : P
      : [NonNullable<D>] extends [object]
        ? [NonNullable<J>] extends [object]
          ? {
              [K in keyof NonNullable<D> &
                string]-?: K extends keyof NonNullable<J>
                ? Diff<NonNullable<D>[K], NonNullable<J>[K], `${P}.${K}`>
                : `${P}.${K}`
            }[keyof NonNullable<D> & string]
          : P
        : [NonNullable<D>] extends [NonNullable<J>]
          ? never
          : P
  : never

// Request and response ProtoJSON types for each ConsoleApi method.
interface Wire {
  getCurrentSession: [
    GetCurrentSessionRequestJson,
    GetCurrentSessionResponseJson,
  ]
  getLoginMethods: [GetLoginMethodsRequestJson, GetLoginMethodsResponseJson]
  beginOidcLogin: [BeginOidcLoginRequestJson, BeginOidcLoginResponseJson]
  loginLdap: [LoginLdapRequestJson, LoginLdapResponseJson]
  logout: [LogoutRequestJson, LogoutResponseJson]
  listHosts: [ListHostsRequestJson, ListHostsResponseJson]
  getHost: [GetHostRequestJson, GetHostResponseJson]
  setHostLabels: [SetHostLabelsRequestJson, SetHostLabelsResponseJson]
  previewHostImport: [
    PreviewHostImportRequestJson,
    PreviewHostImportResponseJson,
  ]
  getHostImportPreview: [
    GetHostImportPreviewRequestJson,
    GetHostImportPreviewResponseJson,
  ]
  executeHostImport: [
    ExecuteHostImportRequestJson,
    ExecuteHostImportResponseJson,
  ]
  deleteHost: [DeleteHostRequestJson, DeleteHostResponseJson]
  listJoinTokens: [ListJoinTokensRequestJson, ListJoinTokensResponseJson]
  createJoinToken: [CreateJoinTokenRequestJson, CreateJoinTokenResponseJson]
  revokeJoinToken: [RevokeJoinTokenRequestJson, RevokeJoinTokenResponseJson]
  listCatalogs: [ListCatalogsRequestJson, ListCatalogsResponseJson]
  listActions: [ListActionsRequestJson, ListActionsResponseJson]
  getAction: [GetActionRequestJson, GetActionResponseJson]
  getCatalogDistribution: [
    GetCatalogDistributionRequestJson,
    GetCatalogDistributionResponseJson,
  ]
  getPolicy: [GetPolicyRequestJson, GetPolicyResponseJson]
  listPolicyHistory: [
    ListPolicyHistoryRequestJson,
    ListPolicyHistoryResponseJson,
  ]
  testPolicy: [TestPolicyRequestJson, TestPolicyResponseJson]
  getPolicyTestChanges: [
    GetPolicyTestChangesRequestJson,
    GetPolicyTestChangesResponseJson,
  ]
  savePolicy: [SavePolicyRequestJson, SavePolicyResponseJson]
  rollbackPolicy: [RollbackPolicyRequestJson, RollbackPolicyResponseJson]
  listServiceAccounts: [
    ListServiceAccountsRequestJson,
    ListServiceAccountsResponseJson,
  ]
  createServiceAccount: [
    CreateServiceAccountRequestJson,
    CreateServiceAccountResponseJson,
  ]
  listServiceAccountTokens: [
    ListServiceAccountTokensRequestJson,
    ListServiceAccountTokensResponseJson,
  ]
  createServiceAccountToken: [
    CreateServiceAccountTokenRequestJson,
    CreateServiceAccountTokenResponseJson,
  ]
  revokeServiceAccountToken: [
    RevokeServiceAccountTokenRequestJson,
    RevokeServiceAccountTokenResponseJson,
  ]
  listJobs: [ListJobsRequestJson, ListJobsResponseJson]
  getJob: [GetJobRequestJson, GetJobResponseJson]
  listTasks: [ListTasksRequestJson, ListTasksResponseJson]
  getJobOutput: [GetJobOutputRequestJson, GetJobOutputResponseJson]
  cancelJob: [CancelJobRequestJson, CancelJobResponseJson]
  listAuditEvents: [ListAuditEventsRequestJson, ListAuditEventsResponseJson]
  verifyAudit: [VerifyAuditRequestJson, VerifyAuditResponseJson]
  listUsers: [ListUsersRequestJson, ListUsersResponseJson]
  listRoles: [ListRolesRequestJson, ListRolesResponseJson]
  setUserRoles: [SetUserRolesRequestJson, SetUserRolesResponseJson]
  getRoleMappings: [GetRoleMappingsRequestJson, GetRoleMappingsResponseJson]
  saveRoleMappings: [SaveRoleMappingsRequestJson, SaveRoleMappingsResponseJson]
  getSystemStatus: [GetSystemStatusRequestJson, GetSystemStatusResponseJson]
  listGatewayInstances: [
    ListGatewayInstancesRequestJson,
    ListGatewayInstancesResponseJson,
  ]
  getAgentVersionDistribution: [
    GetAgentVersionDistributionRequestJson,
    GetAgentVersionDistributionResponseJson,
  ]
}

type Input<K extends keyof ConsoleApi> = Parameters<ConsoleApi[K]>[0]
type Output<K extends keyof ConsoleApi> = Awaited<ReturnType<ConsoleApi[K]>>
type Failures = {
  [K in keyof ConsoleApi]:
    | Diff<Input<K>, Wire[K][0], `${K}.request`>
    | (Output<K> extends void
        ? never
        : Diff<Output<K>, Wire[K][1], `${K}.response`>)
}[keyof ConsoleApi]

// A non-empty Failures is the union of the mismatching field paths. It appears
// in the compiler error as the missing key of the request object.
export const apiMatchesProtoJson: Record<Failures, never> = {}

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2
    ? true
    : false
// The status lists used by the filters must list every non-zero enum value.
export const statusListsMatchProtoJson: Equal<
  (typeof jobStatuses)[number] | (typeof taskStatuses)[number],
  Exclude<JobStatusJson | TaskStatusJson, `${string}_UNSPECIFIED`>
> = true
