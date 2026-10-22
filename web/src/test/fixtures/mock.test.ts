import { describe, expect, it, vi } from 'vitest'
import { api, fromBase64, toBase64 } from '@/api'
import { verifyChain } from './mock'
import { jobStatuses, taskStatuses } from '@/api/types'

async function hostRequest(hostname = 'web-01') {
  const { host } = await api.getHost({ hostname })
  return {
    targets: { hosts: { names: [hostname] } },
    expectedCount: '1',
    changes: { set: {}, remove: [] },
    expectedRevisions: [{ hostId: host.hostId, revision: host.revision }],
  }
}
async function policyTest(
  rules?: Awaited<ReturnType<typeof api.getPolicy>>['policy']['rules'],
) {
  const { policy } = await api.getPolicy()
  return api.testPolicy({
    baseVersion: policy.version,
    rules: rules ?? policy.rules,
    cases: [],
  })
}

describe('P2 ProtoJSON mock contract', () => {
  it('uses symbolic enums, string uint64 and Base64 bytes', async () => {
    const { jobs } = await api.listJobs()
    expect(
      jobs.every(
        (j) =>
          jobStatuses.includes(j.status as (typeof jobStatuses)[number]) &&
          typeof j.totalTasks === 'string' &&
          typeof j.policyVersion === 'string',
      ),
    ).toBe(true)
    const { tasks } = await api.listTasks({ jobId: jobs[0].jobId })
    expect(
      tasks.every((t) =>
        taskStatuses.includes(t.result.status as (typeof taskStatuses)[number]),
      ),
    ).toBe(true)
    expect(tasks[1].result.exitCode).toBeUndefined()
    const { catalogs } = await api.listCatalogs()
    expect(typeof catalogs[0].catalog.version).toBe('string')
    expect(atob(catalogs[0].envelopeSha256)).toHaveLength(32)
    const action = await api.getAction({
      catalog: catalogs[0].catalog,
      action: 'journal_view_log',
    })
    expect(JSON.parse(fromBase64(action.definitionJson))).toHaveProperty('exec')
  })
  it('separates authorization selectors from reported selectors', async () => {
    expect(
      (await api.listHosts({ query: { selector: 'os=linux' } })).totalCount,
    ).toBe('0')
    expect(
      (await api.listHosts({ query: { selector: 'reported.os=linux' } }))
        .totalCount,
    ).toBe('4')
    expect(
      (
        await api.listHosts({
          query: { selector: 'env=prod,reported.arch=amd64' },
        })
      ).hosts.map((h) => h.hostname),
    ).toEqual(['web-01'])
    await expect(
      api.listHosts({ query: { selector: 'env in (prod)' } }),
    ).rejects.toThrow('error.labels')
  })
  it('preserves unspecified labels and explicitly removes named keys', async () => {
    const request = await hostRequest()
    await api.setHostLabels({
      ...request,
      changes: { set: { team: 'ops' }, remove: ['tier'] },
    })
    expect(
      (await api.getHost({ hostname: 'web-01' })).host.authorizationLabels,
    ).toEqual({ env: 'prod', team: 'ops' })
  })
  it('rejects a stale bulk revision without modifying any target', async () => {
    const { hosts } = await api.listHosts({ query: { selector: 'env=prod' } })
    const request = {
      targets: { selector: 'env=prod' },
      expectedCount: '2',
      changes: { set: { env: 'stage' }, remove: [] },
      expectedRevisions: hosts.map((h) => ({
        hostId: h.hostId,
        revision: h.revision,
      })),
    }
    await api.setHostLabels({
      ...(await hostRequest('web-02')),
      changes: { set: { tier: 'edge' }, remove: [] },
    })
    await expect(api.setHostLabels(request)).rejects.toThrow(
      'error.stalePreview',
    )
    expect(
      (await api.listHosts({ query: { selector: 'env=prod' } })).totalCount,
    ).toBe('2')
  })
  it('previews RFC 4180 CSV without mutation and imports empty values and explicit removals', async () => {
    const { preview } = await api.previewHostImport({
      csv: toBase64('hostname,set:env,remove:tier\r\n"web-01","",true\r\n'),
    })
    const detail = await api.getHostImportPreview({
      previewId: preview.previewId,
    })
    expect(preview.rowCount).toBe('1')
    expect(preview.invalidRowCount).toBe('0')
    expect(atob(preview.csvSha256)).toHaveLength(32)
    expect(detail.rows[0].after).toEqual({ env: '' })
    expect(
      (await api.getHost({ hostname: 'web-01' })).host.authorizationLabels.env,
    ).toBe('prod')
    await api.executeHostImport({ previewId: preview.previewId })
    expect(
      (await api.getHost({ hostname: 'web-01' })).host.authorizationLabels,
    ).toEqual({ env: '' })
  })
  it('shows CSV row errors and refuses a partial commit', async () => {
    const { preview } = await api.previewHostImport({
      csv: toBase64(
        'hostname,set:env\nweb-01,stage\nweb-01,prod\nunknown-01,stage',
      ),
    })
    expect(preview.invalidRowCount).toBe('2')
    await expect(
      api.executeHostImport({ previewId: preview.previewId }),
    ).rejects.toThrow('error.stalePreview')
    expect(
      (await api.getHost({ hostname: 'web-01' })).host.authorizationLabels.env,
    ).toBe('prod')
  })
  it('rejects CSV preview after revision changes', async () => {
    const { preview } = await api.previewHostImport({
      csv: toBase64('hostname,set:env\nweb-01,stage'),
    })
    await api.setHostLabels({
      ...(await hostRequest()),
      changes: { set: { tier: 'edge' }, remove: [] },
    })
    await expect(
      api.executeHostImport({ previewId: preview.previewId }),
    ).rejects.toThrow('error.stalePreview')
    expect(
      (await api.getHost({ hostname: 'web-01' })).host.authorizationLabels.env,
    ).toBe('prod')
  })
  it('expires CSV previews after ten minutes', async () => {
    const { preview } = await api.previewHostImport({
      csv: toBase64('hostname,set:env\nweb-01,stage'),
    })
    vi.useFakeTimers()
    try {
      vi.setSystemTime(Date.parse(preview.expiresAt) + 1)
      await expect(
        api.executeHostImport({ previewId: preview.previewId }),
      ).rejects.toThrow('error.stalePreview')
    } finally {
      vi.useRealTimers()
    }
  })
  it('replays successful import receipts without overwriting later edits', async () => {
    const { preview } = await api.previewHostImport({
      csv: toBase64('hostname,set:env\nweb-01,stage'),
    })
    await api.executeHostImport({ previewId: preview.previewId })
    await api.setHostLabels({
      ...(await hostRequest()),
      changes: { set: { env: 'prod' }, remove: [] },
    })
    expect(
      await api.executeHostImport({ previewId: preview.previewId }),
    ).toEqual({ updatedCount: '1' })
    expect(
      (await api.getHost({ hostname: 'web-01' })).host.authorizationLabels.env,
    ).toBe('prod')
  })
  it('returns plaintext tokens only from creation responses', async () => {
    const join = await api.createJoinToken({ maxUses: 2, ttl: '86400s' })
    expect(join.secret).toMatch(/^aops_join_[a-f0-9]{64}$/)
    expect(JSON.stringify(await api.listJoinTokens())).not.toContain(
      join.secret,
    )
    const token = await api.createServiceAccountToken({
      accountId: 'sa-01',
      description: '',
      validDays: 30,
    })
    expect(token.secret).toMatch(/^aops_[a-f0-9]{64}$/)
    expect(
      JSON.stringify(
        await api.listServiceAccountTokens({ accountId: 'sa-01' }),
      ),
    ).not.toContain(token.secret)
    await api.revokeServiceAccountToken({
      accountId: 'sa-01',
      tokenId: token.token.tokenId,
    })
    expect(
      (await api.listServiceAccountTokens({ accountId: 'sa-01' })).tokens.find(
        (t) => t.tokenId === token.token.tokenId,
      )?.revokedAt,
    ).toBeDefined()
  })
  it.each([0, 366, 1.5])(
    'rejects invalid service token validity %s',
    async (validDays) => {
      await expect(
        api.createServiceAccountToken({
          accountId: 'sa-01',
          description: '',
          validDays,
        }),
      ).rejects.toThrow('error.tokenTtl')
    },
  )
  it('keeps task history after deleting a host', async () => {
    const { host } = await api.getHost({ hostname: 'web-01' })
    await api.deleteHost({
      hostId: host.hostId,
      expectedRevision: host.revision,
    })
    await expect(api.getHost({ hostname: 'web-01' })).rejects.toThrow(
      'error.notFound',
    )
    expect(
      (await api.listTasks({ jobId: 'job-20261013-0042' })).tasks[0].hostId,
    ).toBe(host.hostId)
  })
  it('cancels pending and running tasks while retaining terminal jobs', async () => {
    const { job } = await api.cancelJob({ jobId: 'job-20261013-0043' })
    expect(job.status).toBe('JOB_STATUS_CANCELLED')
    expect(job.counts).toEqual([
      { status: 'TASK_STATUS_CANCELLED', count: '2' },
    ])
    expect(
      (await api.listTasks({ jobId: job.jobId })).tasks.every(
        (t) => t.result.status === 'TASK_STATUS_CANCELLED',
      ),
    ).toBe(true)
    expect(
      (await api.cancelJob({ jobId: 'job-20261013-0042' })).job.status,
    ).toBe('JOB_STATUS_PARTIALLY_FAILED')
  })
  it('uses deny precedence and denies new hosts without authorization labels', async () => {
    const { policy } = await api.getPolicy()
    const rules = {
      rules: [
        ...policy.rules.rules,
        {
          ...policy.rules.rules[0],
          name: 'deny-prod',
          hostLabels: { env: 'prod' },
          effect: 'POLICY_EFFECT_DENY' as const,
        },
      ],
    }
    const { test } = await policyTest(rules)
    const { changes } = await api.getPolicyTestChanges({ testId: test.testId })
    expect(changes.find((c) => c.host === 'web-01')?.after.effect).toBe(
      'POLICY_EFFECT_DENY',
    )
    expect(
      changes
        .filter((c) => c.host === 'worker-01')
        .every((c) => c.after.effect === 'POLICY_EFFECT_DENY'),
    ).toBe(true)
  })
  it('rejects a policy save after candidate or resource snapshot changes', async () => {
    const { policy } = await api.getPolicy()
    const { test } = await policyTest()
    await expect(
      api.savePolicy({
        baseVersion: policy.version,
        rules: { rules: [] },
        testId: test.testId,
        reason: 'example',
      }),
    ).rejects.toThrow('error.stalePolicy')
    await api.setHostLabels({
      ...(await hostRequest()),
      changes: { set: { env: 'stage' }, remove: [] },
    })
    await expect(
      api.savePolicy({
        baseVersion: policy.version,
        rules: policy.rules,
        testId: test.testId,
        reason: 'example',
      }),
    ).rejects.toThrow('error.stalePolicy')
  })
  it('requires a matching historical simulation and increments version on rollback', async () => {
    const { test } = await api.testPolicy({
      baseVersion: '2',
      historicalVersion: '1',
      cases: [],
    })
    const { policy } = await api.rollbackPolicy({
      baseVersion: '2',
      targetVersion: '1',
      testId: test.testId,
      reason: 'example',
    })
    expect(policy.version).toBe('3')
    expect(policy.rolledBackFrom).toBe('1')
    expect(policy.rules.rules).toHaveLength(2)
  })
  it('unions manual and mapped roles and recalculates group mapping changes', async () => {
    await api.setUserRoles({
      userId: 'user-02',
      manualRoles: ['operator'],
      expectedRevision: '1',
    })
    expect((await api.listUsers()).users[1].effectiveRoles).toEqual([
      'auditor',
      'operator',
    ])
    const mappings = await api.getRoleMappings()
    await api.saveRoleMappings({
      expectedRevision: mappings.revision,
      mappings: mappings.mappings.filter((m) => m.providerId !== 'ldap'),
    })
    expect((await api.listUsers()).users[1].effectiveRoles).toEqual([
      'operator',
    ])
  })
  it('keeps output separate from summaries and denies viewer access', async () => {
    const { job } = await api.getJob({ jobId: 'job-20261013-0042' })
    expect(JSON.stringify(job)).not.toContain('service=api')
    const output = await api.getJobOutput({
      jobId: job.jobId,
      hostname: 'web-01',
      stream: 'OUTPUT_STREAM_STDOUT',
      offset: '0',
      limitBytes: 7,
    })
    expect(fromBase64(output.data)).toBe('service')
    expect(output.nextOffset).toBe('7')
    expect(output.eof).toBe(false)
    await api.loginLdap({
      providerId: 'ldap',
      username: 'view-user',
      password: 'demo',
      client: 'LOGIN_CLIENT_CONSOLE',
    })
    await expect(
      api.getJobOutput({
        jobId: job.jobId,
        hostname: 'web-01',
        stream: 'OUTPUT_STREAM_STDOUT',
        offset: '0',
        limitBytes: 7,
      }),
    ).rejects.toThrow('error.outputDenied')
  })
  it('checks authoritative hash input bytes and detects tampering and missing events', async () => {
    const { events } = await api.listAuditEvents()
    expect(await verifyChain(events)).toMatchObject({
      valid: true,
      checkedCount: '3',
      externallyAnchored: false,
    })
    events[1].hashInput = toBase64('tampered')
    expect(await verifyChain(events)).toMatchObject({
      valid: false,
      firstInvalidSeq: '2',
    })
    const fresh = await api.listAuditEvents()
    expect(await verifyChain([fresh.events[0], fresh.events[2]])).toMatchObject(
      { valid: false, firstInvalidSeq: '3' },
    )
  })
  it('uses an exclusive audit end time', async () => {
    const { events } = await api.listAuditEvents()
    const filtered = await api.listAuditEvents({
      query: { time: { to: events[0].at } },
    })
    expect(filtered.events).toEqual([])
  })
  it('rejects CSV headers with an extra operation separator', async () => {
    const { preview } = await api.previewHostImport({
      csv: toBase64('hostname,set:env:extra\nweb-01,stage'),
    })
    expect(preview.invalidRowCount).toBe('1')
  })
  it('reconciles gateway connections with overview host counts', async () => {
    const status = await api.getSystemStatus()
    const { instances } = await api.listGatewayInstances()
    expect(
      instances.reduce(
        (sum, instance) => sum + BigInt(instance.connectedHosts),
        0n,
      ),
    ).toBe(BigInt(status.onlineHosts))
  })
})
