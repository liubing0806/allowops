import { redirectToLogin } from '@/api/navigation'
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api, ApiError, toBase64 } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})
async function open(path: string) {
  window.history.replaceState({}, '', path)
  const view = render(<App />)
  await screen.findByRole('heading', { level: 1 }, { timeout: 5000 })
  return view
}

describe('console mutation workflows', () => {
  it('navigates to the gateway OIDC endpoint', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch')
    await open('/login')
    const button = await screen.findByRole('button', { name: '使用 OIDC 登录' })
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)
    await waitFor(() => expect(redirectToLogin).toHaveBeenCalledWith('/'))
    expect(fetch).not.toHaveBeenCalled()
    fetch.mockRestore()
  })
  it('validates empty LDAP inputs', async () => {
    await open('/login')
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '登录' })).toBeEnabled(),
    )
    fireEvent.click(screen.getByRole('button', { name: '登录' }))
    expect(await screen.findAllByRole('alert')).toHaveLength(2)
    expect(
      screen.getByRole('heading', { name: '登录控制台' }),
    ).toBeInTheDocument()
  })
  it('previews exact bulk targets before applying authorization labels', async () => {
    await open('/hosts')
    fireEvent.click(screen.getByRole('button', { name: '批量设置标签' }))
    const panel = screen
      .getByRole('heading', { name: '批量设置标签' })
      .closest('section')!
    fireEvent.change(within(panel).getByLabelText('标签选择器'), {
      target: { value: 'env=prod' },
    })
    fireEvent.change(within(panel).getByLabelText('授权标签'), {
      target: { value: 'team=ops' },
    })
    fireEvent.click(within(panel).getByRole('button', { name: '预览目标' }))
    fireEvent.click(
      await within(panel).findByRole('button', { name: '应用到 2 台主机' }),
    )
    expect(await screen.findByRole('status')).toHaveTextContent(
      '已更新 2 台主机的标签',
    )
    expect(
      (await api.getHost({ hostname: 'web-01' })).host.authorizationLabels,
    ).toMatchObject({ env: 'prod', tier: 'web', team: 'ops' })
    expect(
      (await api.getHost({ hostname: 'web-02' })).host.authorizationLabels.team,
    ).toBe('ops')
    expect(
      (await api.getHost({ hostname: 'web-03' })).host.authorizationLabels.team,
    ).toBeUndefined()
  })
  it('reads a CSV file, previews it, and submits the bound preview', async () => {
    await open('/hosts')
    fireEvent.click(screen.getByRole('button', { name: 'CSV 导入标签' }))
    const file = new File(
      ['hostname,set:env,remove:tier\r\nweb-01,stage,true'],
      'labels.csv',
      { type: 'text/csv' },
    )
    fireEvent.change(screen.getByLabelText('选择 CSV 文件'), {
      target: { files: [file] },
    })
    await waitFor(() =>
      expect(screen.getByLabelText('CSV 内容')).toHaveValue(
        'hostname,set:env,remove:tier\nweb-01,stage,true',
      ),
    )
    fireEvent.click(screen.getByRole('button', { name: '预览变更' }))
    fireEvent.click(await screen.findByRole('button', { name: '确认导入' }))
    expect(await screen.findByRole('status')).toHaveTextContent(
      '已导入 1 台主机的标签',
    )
    expect(
      (await api.getHost({ hostname: 'web-01' })).host.authorizationLabels,
    ).toEqual({ env: 'stage' })
  })
  it('prevents importing a preview with row errors', async () => {
    await open('/hosts')
    fireEvent.click(screen.getByRole('button', { name: 'CSV 导入标签' }))
    fireEvent.change(screen.getByLabelText('CSV 内容'), {
      target: { value: 'hostname,set:env\nunknown-01,prod' },
    })
    fireEvent.click(screen.getByRole('button', { name: '预览变更' }))
    expect(
      await screen.findByRole('button', { name: '确认导入' }),
    ).toBeDisabled()
    expect(screen.getByText('未找到资源')).toBeInTheDocument()
  })
  it('requires deletion confirmation and preserves the host on cancel', async () => {
    await open('/hosts')
    fireEvent.click(
      await screen.findByRole('button', { name: '删除主机 web-01' }),
    )
    fireEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: '取消',
      }),
    )
    expect(screen.getByRole('link', { name: 'web-01' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '删除主机 web-01' }))
    fireEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: '确认',
      }),
    )
    expect(await screen.findByRole('status')).toHaveTextContent('主机已删除')
    expect(
      screen.queryByRole('link', { name: 'web-01' }),
    ).not.toBeInTheDocument()
  })
  it('revokes a join token after confirmation', async () => {
    await open('/join-tokens')
    fireEvent.click(await screen.findByRole('button', { name: '吊销' }))
    const dialog = await screen.findByRole('dialog', {
      name: '吊销 join token',
    })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Token 已吊销')
    expect((await api.listJoinTokens()).tokens[0].revokedAt).toBeDefined()
  })
  it('edits a rule, simulates, and saves a new policy version', async () => {
    await open('/policies')
    fireEvent.click(
      await screen.findByRole('button', { name: '编辑 readonly-all' }),
    )
    fireEvent.change(screen.getByLabelText('风险（逗号分隔）'), {
      target: { value: 'write' },
    })
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '试算' })).toBeEnabled(),
    )
    fireEvent.click(screen.getByRole('button', { name: '试算' }))
    await screen.findByRole('heading', { name: '试算结果' })
    fireEvent.change(screen.getByLabelText('变更原因'), {
      target: { value: 'example change' },
    })
    fireEvent.click(screen.getByRole('button', { name: '保存策略' }))
    expect(await screen.findByRole('status')).toHaveTextContent('策略已保存')
    const { policy } = await api.getPolicy()
    expect(policy.version).toBe('3')
    expect(policy.rules.rules[0].risks).toEqual(['write'])
  })
  // RR-b-01c: a new rule starts with empty risks. Selecting execute_action
  // fills risks with read until the user edits the field.
  async function saveNewRule(
    operations: string,
    risks?: string,
  ): Promise<string[]> {
    await open('/policies')
    fireEvent.click(await screen.findByRole('button', { name: '添加规则' }))
    fireEvent.change(screen.getByLabelText('规则名称'), {
      target: { value: 'new-rule' },
    })
    fireEvent.change(screen.getByLabelText('角色（逗号分隔）'), {
      target: { value: 'viewer' },
    })
    fireEvent.change(screen.getByLabelText('操作（逗号分隔）'), {
      target: { value: operations },
    })
    if (risks !== undefined)
      fireEvent.change(screen.getByLabelText('风险（逗号分隔）'), {
        target: { value: risks },
      })
    const shown = (screen.getByLabelText('风险（逗号分隔）') as HTMLInputElement)
      .value
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '试算' })).toBeEnabled(),
    )
    fireEvent.click(screen.getByRole('button', { name: '试算' }))
    await screen.findByRole('heading', { name: '试算结果' })
    fireEvent.change(screen.getByLabelText('变更原因'), {
      target: { value: 'new rule' },
    })
    fireEvent.click(screen.getByRole('button', { name: '保存策略' }))
    expect(await screen.findByRole('status')).toHaveTextContent('策略已保存')
    const { rules } = (await api.getPolicy()).policy.rules
    const saved = rules.find((rule) => rule.name === 'new-rule')!
    expect(saved.risks.join(',')).toBe(shown)
    return saved.risks
  }
  it('creates a view_jobs rule with empty risks', async () => {
    expect(await saveNewRule('view_jobs')).toEqual([])
  })
  it('defaults risks to read for a new execute_action rule', async () => {
    expect(await saveNewRule('execute_action')).toEqual(['read'])
  })
  it('keeps risks the user edited on a new execute_action rule', async () => {
    expect(await saveNewRule('execute_action', 'write')).toEqual(['write'])
  })
  // RR-b-01c: an existing rule keeps its stored risks when only other fields
  // change, whether or not its operations include execute_action.
  it.each(['view_jobs', 'execute_action', 'view_jobs,execute_action'])(
    'keeps stored risks when editing another field of a %s rule',
    async (operations) => {
      const risks = ['write', 'dangerous']
      const { policy } = await api.getPolicy()
      const seeded = {
        rules: [
          ...policy.rules.rules,
          {
            ...policy.rules.rules[0],
            name: 'seeded-rule',
            roles: ['viewer'],
            operations: operations.split(','),
            actions: [],
            risks,
            effect: 'POLICY_EFFECT_ALLOW' as const,
          },
        ],
      }
      const seedTest = await api.testPolicy({
        baseVersion: policy.version,
        rules: seeded,
        cases: [],
      })
      await api.savePolicy({
        baseVersion: policy.version,
        rules: seeded,
        testId: seedTest.test.testId,
        reason: 'seed',
      })
      await open('/policies')
      fireEvent.click(
        await screen.findByRole('button', { name: '编辑 seeded-rule' }),
      )
      expect(
        (screen.getByLabelText('风险（逗号分隔）') as HTMLInputElement).value,
      ).toBe('write,dangerous')
      fireEvent.change(screen.getByLabelText('角色（逗号分隔）'), {
        target: { value: 'viewer,auditor' },
      })
      fireEvent.click(screen.getByRole('button', { name: '保存' }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: '试算' })).toBeEnabled(),
      )
      fireEvent.click(screen.getByRole('button', { name: '试算' }))
      await screen.findByRole('heading', { name: '试算结果' })
      fireEvent.change(screen.getByLabelText('变更原因'), {
        target: { value: 'edit other field' },
      })
      fireEvent.click(screen.getByRole('button', { name: '保存策略' }))
      expect(await screen.findByRole('status')).toHaveTextContent('策略已保存')
      const saved = (await api.getPolicy()).policy.rules.rules.find(
        (rule) => rule.name === 'seeded-rule',
      )!
      expect(saved.roles).toEqual(['viewer', 'auditor'])
      expect(saved.risks).toEqual(risks)
    },
  )
  it('simulates and confirms policy rollback as a higher version', async () => {
    await open('/policies')
    fireEvent.click(await screen.findByRole('button', { name: '试算回滚到 1' }))
    await screen.findByRole('heading', { name: '试算结果' })
    fireEvent.change(screen.getByLabelText('变更原因'), {
      target: { value: 'example rollback' },
    })
    fireEvent.click(screen.getByRole('button', { name: '确认回滚' }))
    fireEvent.click(
      within(await screen.findByRole('dialog', { name: '回滚策略' })).getByRole(
        'button',
        { name: '确认' },
      ),
    )
    expect(await screen.findByRole('status')).toHaveTextContent('策略已回滚')
    expect((await api.getPolicy()).policy).toMatchObject({
      version: '3',
      rolledBackFrom: '1',
    })
  })
  it('creates a service account with an existing owner and role', async () => {
    await open('/service-accounts')
    fireEvent.click(screen.getByRole('button', { name: '创建服务账号' }))
    const panel = screen
      .getByRole('heading', { name: '创建服务账号' })
      .closest('section')!
    fireEvent.change(within(panel).getByLabelText('名称'), {
      target: { value: 'agent-example' },
    })
    fireEvent.change(within(panel).getByLabelText('负责人'), {
      target: { value: 'user-01' },
    })
    // Wait for owner options fetched through the API.
    await within(panel).findByRole('option', { name: 'console-user' })
    fireEvent.change(within(panel).getByLabelText('负责人'), {
      target: { value: 'user-01' },
    })
    fireEvent.click(within(panel).getByRole('button', { name: '创建服务账号' }))
    expect(await screen.findByRole('status')).toHaveTextContent(
      '服务账号已创建',
    )
    expect((await api.listServiceAccounts()).accounts[0]).toMatchObject({
      name: 'agent-example',
      ownerUserId: 'user-01',
      roles: ['auditor'],
    })
  })
  it('validates service token expiry and revokes an existing token', async () => {
    await open('/service-accounts')
    fireEvent.click(
      await screen.findByRole('button', { name: '管理 agent-readonly' }),
    )
    fireEvent.change(screen.getByLabelText('有效期（天，1–365）'), {
      target: { value: '366' },
    })
    fireEvent.submit(
      screen.getByRole('button', { name: '创建 token' }).closest('form')!,
    )
    expect(
      await screen.findByText('Token 有效期必须为 1–365 天'),
    ).toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: '吊销' }))
    fireEvent.click(
      within(
        await screen.findByRole('dialog', { name: '吊销 token' }),
      ).getByRole('button', { name: '确认' }),
    )
    expect(await screen.findByRole('status')).toHaveTextContent('Token 已吊销')
    expect(
      (await api.listServiceAccountTokens({ accountId: 'sa-01' })).tokens[0]
        .revokedAt,
    ).toBeDefined()
  })
  it('cancels a running job after confirmation', async () => {
    await open('/jobs/job-20261013-0043')
    fireEvent.click(await screen.findByRole('button', { name: '取消 job' }))
    fireEvent.click(
      within(await screen.findByRole('dialog', { name: '取消 job' })).getByRole(
        'button',
        { name: '确认' },
      ),
    )
    expect(await screen.findByRole('status')).toHaveTextContent(
      '已发送取消请求',
    )
    expect((await api.getJob({ jobId: 'job-20261013-0043' })).job.status).toBe(
      'JOB_STATUS_CANCELLED',
    )
  })
  it('renders script-like output as text', async () => {
    const original = api.getJobOutput
    const spy = vi
      .spyOn(api, 'getJobOutput')
      .mockImplementation(async (input) => ({
        ...(await original(input)),
        data: toBase64('<script>window.injected=true</script>'),
      }))
    try {
      await open('/jobs/job-20261013-0042')
      const button = await screen.findByRole('button', {
        name: '查看输出 web-01',
      })
      await waitFor(() => expect(button).toBeEnabled())
      fireEvent.click(button)
      await waitFor(() =>
        expect(
          screen.getAllByText('<script>window.injected=true</script>'),
        ).toHaveLength(2),
      )
      expect(document.querySelector('script')).toBeNull()
    } finally {
      spy.mockRestore()
    }
  })
  it('queries audit by hostname', async () => {
    await open('/audit')
    fireEvent.change(screen.getByLabelText('主机'), {
      target: { value: 'web-02' },
    })
    fireEvent.click(screen.getByRole('button', { name: '查询' }))
    expect(await screen.findByText('web-02')).toBeInTheDocument()
    expect(screen.queryByText('web-01')).not.toBeInTheDocument()
  })
  it('saves group mappings with optimistic revision checks', async () => {
    await open('/users')
    const inputs = await screen.findAllByLabelText('映射角色（逗号分隔）')
    fireEvent.change(inputs[1], { target: { value: 'viewer' } })
    fireEvent.click(screen.getByRole('button', { name: '保存映射' }))
    expect(await screen.findByRole('status')).toHaveTextContent(
      '角色映射已保存',
    )
    expect((await api.listUsers()).users[1].effectiveRoles).toEqual(['viewer'])
  })
  it('handles unknown routes', async () => {
    await open('/unknown')
    expect(
      await screen.findByRole('heading', { name: '页面不存在' }),
    ).toBeInTheDocument()
    fireEvent.click(screen.getByRole('link', { name: '返回概览' }))
    expect(await screen.findByText('在线主机')).toBeInTheDocument()
  })
  it('uses the identity provider returned by the interface layer', async () => {
    const methods = vi.spyOn(api, 'getLoginMethods').mockResolvedValue({
      methods: [
        { providerId: 'example-oidc', displayName: 'OIDC', kind: 'oidc' },
      ],
    })
    const begin = vi.spyOn(api, 'beginOidcLogin')
    try {
      await open('/login')
      await waitFor(() =>
        expect(
          screen.getByRole('button', { name: '使用 OIDC 登录' }),
        ).toBeEnabled(),
      )
      fireEvent.click(
        await screen.findByRole('button', { name: '使用 OIDC 登录' }),
      )
      await waitFor(() => expect(redirectToLogin).toHaveBeenCalled())
      expect(begin).toHaveBeenCalledWith({
        providerId: 'example-oidc',
        client: 'LOGIN_CLIENT_CONSOLE',
      })
    } finally {
      methods.mockRestore()
      begin.mockRestore()
    }
  })
  it('offers each OIDC provider and navigates to the selected provider', async () => {
    const methods = vi.spyOn(api, 'getLoginMethods').mockResolvedValue({
      methods: [
        { providerId: 'first', displayName: 'First', kind: 'oidc' },
        { providerId: 'second', displayName: 'Second', kind: 'oidc' },
      ],
    })
    const begin = vi
      .spyOn(api, 'beginOidcLogin')
      .mockResolvedValue({ authorizationUrl: '/auth/oidc/start?state=fixture' })
    try {
      await open('/login')
      expect(
        await screen.findByRole('button', { name: '使用 First 登录' }),
      ).toBeEnabled()
      fireEvent.click(
        await screen.findByRole('button', { name: '使用 Second 登录' }),
      )
      await waitFor(() =>
        expect(begin).toHaveBeenCalledWith({
          providerId: 'second',
          client: 'LOGIN_CLIENT_CONSOLE',
        }),
      )
      await waitFor(() =>
        expect(redirectToLogin).toHaveBeenCalledWith(
          '/auth/oidc/start?state=fixture',
        ),
      )
    } finally {
      methods.mockRestore()
      begin.mockRestore()
    }
  })
  it('uses the single LDAP provider without an identity source selector', async () => {
    const methods = vi.spyOn(api, 'getLoginMethods').mockResolvedValue({
      methods: [
        {
          providerId: 'company-ldap',
          displayName: 'Company LDAP',
          kind: 'ldap',
        },
      ],
    })
    const login = vi.spyOn(api, 'loginLdap')
    try {
      await open('/login')
      await waitFor(() =>
        expect(screen.getByRole('button', { name: '登录' })).toBeEnabled(),
      )
      expect(screen.queryByLabelText('身份源')).not.toBeInTheDocument()
      fireEvent.change(screen.getByLabelText('用户名'), {
        target: { value: 'console-user' },
      })
      fireEvent.change(screen.getByLabelText('密码'), {
        target: { value: 'fixture-password' },
      })
      fireEvent.click(screen.getByRole('button', { name: '登录' }))
      await screen.findByRole('heading', { name: '概览' })
      expect(login).toHaveBeenCalledWith({
        providerId: 'company-ldap',
        username: 'console-user',
        password: 'fixture-password',
        client: 'LOGIN_CLIENT_CONSOLE',
      })
    } finally {
      methods.mockRestore()
      login.mockRestore()
    }
  })
  it.each(['zh-CN', 'en'])(
    'never displays a multiple LDAP selector in %s',
    async (language) => {
      const methods = vi.spyOn(api, 'getLoginMethods').mockResolvedValue({
        methods: [
          { providerId: 'first', displayName: 'First', kind: 'ldap' },
          { providerId: 'second', displayName: 'Second', kind: 'ldap' },
        ],
      })
      try {
        await i18n.changeLanguage(language)
        await open('/login')
        await waitFor(() =>
          expect(
            screen.getByRole('button', {
              name: language === 'en' ? 'Sign in' : '登录',
            }),
          ).toBeEnabled(),
        )
        expect(screen.getAllByRole('combobox')).toHaveLength(1) // Language only.
        expect(
          screen.getAllByLabelText(language === 'en' ? 'Username' : '用户名'),
        ).toHaveLength(1)
      } finally {
        methods.mockRestore()
      }
    },
  )
  it('lets a viewer request output and displays the API permission denial', async () => {
    await api.loginLdap({
      providerId: 'ldap',
      username: 'view-user',
      password: 'fixture',
      client: 'LOGIN_CLIENT_CONSOLE',
    })
    const output = vi
      .spyOn(api, 'getJobOutput')
      .mockRejectedValue(new ApiError('error.permissionDenied'))
    try {
      await open('/jobs/job-20261013-0042')
      const button = await screen.findByRole('button', {
        name: '查看输出 web-01',
      })
      await waitFor(() => expect(button).toBeEnabled())
      fireEvent.click(button)
      await waitFor(() => expect(screen.getAllByText('无权限')).toHaveLength(2))
    } finally {
      output.mockRestore()
    }
  })
})

describe('English pages', () => {
  it.each([
    ['/login', 'Sign in to console'],
    ['/', 'Overview'],
    ['/hosts', 'Hosts'],
    ['/hosts/web-01', 'web-01'],
    ['/join-tokens', 'Join tokens'],
    ['/catalog', 'Catalog'],
    ['/policies', 'Policies'],
    ['/service-accounts', 'Service accounts'],
    ['/jobs', 'Jobs'],
    ['/jobs/job-20261013-0042', 'job-20261013-0042'],
    ['/audit', 'Audit'],
    ['/users', 'Users & roles'],
    ['/system', 'System'],
  ])('renders %s in English', async (path, heading) => {
    await i18n.changeLanguage('en')
    await open(path)
    expect(
      await screen.findByRole('heading', { name: heading, level: 1 }),
    ).toBeInTheDocument()
  })
})
