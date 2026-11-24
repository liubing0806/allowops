import { create, toBinary } from '@bufbuild/protobuf'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ErrorDetailSchema } from '@/gen/allowops/v1/common_pb'

afterEach(() => vi.unstubAllGlobals())

describe('production Connect adapter', () => {
  it('reads hosts from the gateway with the browser session cookie', async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          hosts: [],
          page: {},
          totalCount: '0',
        }),
        { headers: { 'Content-Type': 'application/json' } },
      ),
    )
    vi.stubGlobal('fetch', fetch)
    const { api } = await vi.importActual<typeof import('./index')>('./index')
    await api.listHosts()
    expect(fetch).toHaveBeenCalled()
    const [url, options] = fetch.mock.calls[0]
    expect(String(url)).toContain('/allowops.v1.HostService/ListHosts')
    expect(options.credentials).toBe('same-origin')
  })

  it('obtains a session-bound CSRF token before a write', async () => {
    const fetch = vi.fn(
      async (url: string) =>
        new Response(
          JSON.stringify(
            url.endsWith('/GetCurrentSession')
              ? {
                  user: { userId: 'admin' },
                  client: 'LOGIN_CLIENT_CONSOLE',
                  csrfToken: 'fixture-csrf',
                }
              : { token: { tokenId: 'join' }, secret: 'fixture-secret' },
          ),
          { headers: { 'Content-Type': 'application/json' } },
        ),
    )
    vi.stubGlobal('fetch', fetch)
    const { api } = await vi.importActual<typeof import('./index')>('./index')
    await api.createJoinToken({ maxUses: 1, ttl: '86400s' })
    expect(fetch).toHaveBeenCalledTimes(2)
    const [url, options] = fetch.mock.calls[1] as unknown as [
      string,
      RequestInit,
    ]
    expect(url).toContain('/allowops.v1.JoinTokenService/CreateJoinToken')
    expect(new Headers(options.headers).get('X-CSRF-Token')).toBe(
      'fixture-csrf',
    )
  })

  it('preserves large uint64 values, output bytes, enums, and implicit defaults', async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: '5Lit5paH',
          nextOffset: '9007199254740993',
          eof: true,
          outputTrust: 'OUTPUT_TRUST_UNTRUSTED',
          output: { sizeBytes: '6' },
        }),
        { headers: { 'Content-Type': 'application/json' } },
      ),
    )
    vi.stubGlobal('fetch', fetch)
    const { api } = await vi.importActual<typeof import('./index')>('./index')
    const result = await api.getJobOutput({
      jobId: 'job',
      hostname: 'host',
      stream: 'OUTPUT_STREAM_STDERR',
      offset: '9007199254740993',
      limitBytes: 32768,
    })
    expect(result.nextOffset).toBe('9007199254740993')
    expect(result.data).toBe('5Lit5paH')
    expect(result.outputTrust).toBe('OUTPUT_TRUST_UNTRUSTED')
    expect(result.scanLimitReached).toBe(false)
    const request = JSON.parse(
      new TextDecoder().decode(fetch.mock.calls[0][1].body),
    )
    expect(request.offset).toBe('9007199254740993')
    expect(request.stream).toBe('OUTPUT_STREAM_STDERR')
  })

  it('passes approval filters and returns the opaque cursor without fetching the next page', async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({
        approvals: [{ approvalId: 'apr-1', status: 'APPROVAL_STATUS_PENDING' }],
        page: { nextPageToken: 'next' },
      }), { headers: { 'Content-Type': 'application/json' } }),
    )
    vi.stubGlobal('fetch', fetch)
    const { api } = await vi.importActual<typeof import('./index')>('./index')
    const request = {
      page: { pageToken: 'current' },
      statuses: ['APPROVAL_STATUS_PENDING' as const],
      action: 'restart',
      onlyActionable: true,
    }
    const result = await api.listApprovals(request)
    expect(fetch).toHaveBeenCalledTimes(1)
    const [url, options] = fetch.mock.calls[0]
    expect(url).toContain('/allowops.v1.ApprovalService/ListApprovals')
    expect(new Headers(options.headers).has('X-CSRF-Token')).toBe(false)
    expect(JSON.parse(new TextDecoder().decode(options.body))).toEqual(request)
    expect(result.page.nextPageToken).toBe('next')
    expect(result.approvals[0]).toMatchObject({ approvalId: 'apr-1', canApprove: false })
  })

  it('uses CSRF for all approval writes and preserves the supplied request digest', async () => {
    const fetch = vi.fn<(url: string, options: RequestInit) => Promise<Response>>(async (url) =>
      new Response(JSON.stringify(url.endsWith('/GetCurrentSession')
        ? { csrfToken: 'fixture-csrf' }
        : { approval: { approvalId: 'apr-1' } }
      ), { headers: { 'Content-Type': 'application/json' } }),
    )
    vi.stubGlobal('fetch', fetch)
    const { api } = await vi.importActual<typeof import('./index')>('./index')
    const approvalId = 'apr-1'
    const expectedRequestDigest = btoa('0123456789abcdef0123456789abcdef')
    const approveRequest = { approvalId, expectedRequestDigest, reason: 'Reviewed' }
    const rejectRequest = { approvalId, reason: 'Wrong window' }
    await api.approveRequest(approveRequest)
    await api.rejectRequest(rejectRequest)
    await api.cancelApproval({ approvalId })
    expect(fetch).toHaveBeenCalledTimes(6)
    const writes = fetch.mock.calls.filter(([url]) => url.includes('ApprovalService'))
    expect(writes.map(([url]) => url.split('/').at(-1))).toEqual([
      'ApproveRequest', 'RejectRequest', 'CancelApproval',
    ])
    for (const [, options] of writes) {
      expect(new Headers(options.headers).get('X-CSRF-Token')).toBe('fixture-csrf')
      expect(options.credentials).toBe('same-origin')
    }
    expect(writes.map(([, options]) =>
      JSON.parse(new TextDecoder().decode(options.body as Uint8Array<ArrayBuffer>))
    )).toEqual([approveRequest, rejectRequest, { approvalId }])
  })

  it('reads the remaining server pages with the original host filters', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            hosts: [{ hostname: 'first' }],
            totalCount: '2',
            page: { nextPageToken: 'cursor' },
          }),
          { headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            hosts: [{ hostname: 'second' }],
            totalCount: '2',
            page: {},
          }),
          { headers: { 'Content-Type': 'application/json' } },
        ),
      )
    vi.stubGlobal('fetch', fetch)
    const { api } = await vi.importActual<typeof import('./index')>('./index')
    const result = await api.listHosts({
      query: { online: false, selector: 'env=test' },
    })
    expect(result.hosts.map((host) => host.hostname)).toEqual([
      'first',
      'second',
    ])
    expect(result.totalCount).toBe('2')
    expect(
      JSON.parse(new TextDecoder().decode(fetch.mock.calls[1][1].body)),
    ).toEqual({
      query: { online: false, selector: 'env=test' },
      page: { pageToken: 'cursor' },
    })
  })

  it('reads a single page of jobs and returns the next page token', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            jobs: [{ jobId: 'first' }],
            page: { nextPageToken: 'cursor' },
          }),
          { headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValue(
        new Response(
          JSON.stringify({ jobs: [{ jobId: 'second' }], page: {} }),
          { headers: { 'Content-Type': 'application/json' } },
        ),
      )
    vi.stubGlobal('fetch', fetch)
    const { api } = await vi.importActual<typeof import('./index')>('./index')
    const result = await api.listJobs({
      action: 'restart',
      page: { pageSize: 10, pageToken: 'previous' },
    })
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(
      JSON.parse(new TextDecoder().decode(fetch.mock.calls[0][1].body)),
    ).toEqual({
      action: 'restart',
      page: { pageSize: 10, pageToken: 'previous' },
    })
    expect(result.jobs.map((job) => job.jobId)).toEqual(['first'])
    expect(result.page.nextPageToken).toBe('cursor')
  })

  it('sends LDAP credentials only to LoginLdap without a prior session request', async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ user: { userId: 'ldap-user' } }), {
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetch)
    const { api } = await vi.importActual<typeof import('./index')>('./index')
    await api.loginLdap({
      providerId: 'ldap',
      username: 'user',
      password: 'fixture-password',
      client: 'LOGIN_CLIENT_CONSOLE',
    })
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(fetch.mock.calls[0][0]).toContain(
      '/allowops.v1.AuthService/LoginLdap',
    )
    expect(
      JSON.parse(new TextDecoder().decode(fetch.mock.calls[0][1].body)),
    ).toEqual({
      providerId: 'ldap',
      username: 'user',
      password: 'fixture-password',
      client: 'LOGIN_CLIENT_CONSOLE',
    })
    expect(
      new Headers(fetch.mock.calls[0][1].headers).has('X-CSRF-Token'),
    ).toBe(false)
  })

  it('shows safe permission errors without gateway exception text', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            code: 'permission_denied',
            message: 'fixture-sensitive-provider-exception',
          }),
          { status: 403, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    )
    const { api } = await vi.importActual<typeof import('./index')>('./index')
    await expect(
      api.getJobOutput({
        jobId: 'job',
        hostname: 'host',
        stream: 'OUTPUT_STREAM_STDOUT',
        offset: '0',
        limitBytes: 32,
      }),
    ).rejects.toMatchObject({
      key: 'error.permissionDenied',
      code: 7,
      message: 'error.permissionDenied',
    })
  })

  it('exposes the ErrorDetail reason and retry_after of a failed call', async () => {
    const detail = toBinary(
      ErrorDetailSchema,
      create(ErrorDetailSchema, {
        reason: 'OUTPUT_PENDING',
        retryAfter: { seconds: 2n, nanos: 500_000_000 },
      }),
    )
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            code: 'unavailable',
            message: 'fixture',
            details: [
              {
                type: 'allowops.v1.ErrorDetail',
                value: btoa(String.fromCharCode(...detail)).replace(/=+$/, ''),
              },
            ],
          }),
          { status: 503, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    )
    const { api } = await vi.importActual<typeof import('./index')>('./index')
    await expect(
      api.getJobOutput({
        jobId: 'job',
        hostname: 'host',
        stream: 'OUTPUT_STREAM_STDOUT',
        offset: '0',
      }),
    ).rejects.toMatchObject({
      key: 'error.unavailable',
      code: 14,
      reason: 'OUTPUT_PENDING',
      retryAfterMs: 2500,
    })
  })
})
