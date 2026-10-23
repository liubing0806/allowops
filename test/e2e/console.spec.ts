import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { test, expect, type APIRequestContext, type BrowserContext, type Page, type Response } from '@playwright/test'

const origin = process.env.ALLOWOPS_E2E_URL!
const authDir = process.env.ALLOWOPS_E2E_AUTH_DIR!
const artifacts = process.env.ALLOWOPS_E2E_ARTIFACTS!
let adminState: Awaited<ReturnType<BrowserContext['storageState']>>
let jobId: string
let stdout: string
const runtimeErrors = new WeakMap<Page, string[]>()

function watchErrors(page: Page) {
  if (runtimeErrors.has(page)) return
  const errors: string[] = []
  runtimeErrors.set(page, errors)
  page.on('pageerror', error => errors.push(error.message))
}

async function rpc<T>(request: APIRequestContext, service: string, method: string, data = {}, csrf?: string) {
  const response = await request.post(`/allowops.v1.${service}/${method}`, {
    data,
    headers: {
      'Connect-Protocol-Version': '1',
      Origin: origin,
      ...(csrf ? { 'X-CSRF-Token': csrf } : {}),
    },
  })
  // Do not put credential-bearing response bodies in assertion messages.
  expect(response.status(), `${service}/${method}`).toBe(200)
  return await response.json() as T
}

async function login(page: Page, username = 'demo-admin') {
  watchErrors(page)
  await page.goto('/login')
  await expect(page.getByRole('heading', { name: 'LDAP 登录', exact: true })).toBeVisible()
  await page.getByLabel('用户名', { exact: true }).fill(username)
  const filename = username === 'demo-admin' ? 'login-password' : 'viewer-password'
  await page.getByLabel('密码', { exact: true }).fill(readFileSync(join(authDir, filename), 'utf8').trim())
  await page.getByRole('button', { name: '登录', exact: true }).click()
  await expect(page).toHaveURL(`${origin}/`)
  await expect(page.getByRole('heading', { name: '概览', exact: true })).toBeVisible()
}

async function screenshot(page: Page, name: string) {
  await page.screenshot({
    path: join(artifacts, `${name}.png`),
    fullPage: true,
    // Both the plaintext token and installation command contain the join secret.
    mask: [page.locator('input[type=password]'), page.locator('dialog:has(pre.secret) pre, [role="dialog"]:has(pre.secret) pre')],
  })
}

async function navigate(page: Page, name: string) {
  await page.getByRole('navigation', { name: '控制台导航' }).getByRole('link', { name, exact: true }).click()
  await expect(page.getByRole('heading', { name, exact: true })).toBeVisible()
}

async function expectOutputResponse(response: Response, status: number) {
  const result = await response.json()
  await test.info().attach('output-response', {
    contentType: 'application/json',
    body: JSON.stringify({
      status: response.status(),
      requestedLimitBytes: response.request().postDataJSON().limitBytes,
      code: result.code,
      reason: result.message === 'OUTPUT_PAGE_LIMIT' ? result.message : undefined,
    }),
  })
  expect(response.status(), 'GetJobOutput HTTP status').toBe(status)
}

test.beforeAll(async ({ browser }) => {
  test.setTimeout(120_000)
  const context = await browser.newContext({ baseURL: origin, ignoreHTTPSErrors: true })
  try {
    const page = await context.newPage()
    await login(page)
    adminState = await context.storageState()
    expect(adminState.cookies.some(cookie => cookie.httpOnly && cookie.secure && cookie.sameSite === 'Strict')).toBe(true)
    const session = await rpc<{ csrfToken: string; user: { effectiveRoles: string[] } }>(page.request, 'AuthService', 'GetCurrentSession')
    expect(session.user.effectiveRoles).toContain('admin')
    expect(session.csrfToken).not.toBe('')
    // Wait for the host's signed catalog acknowledgement, not just agent connection.
    await expect.poll(async () => {
      const { host } = await rpc<{ host: { online: boolean; loadedCatalogs: unknown[] } }>(page.request, 'HostService', 'GetHost', { hostname: 'demo-1' })
      return host.online && host.loadedCatalogs.length > 0
    }, { timeout: 60_000 }).toBe(true)
    const { host } = await rpc<{ host: { hostId: string; revision: string } }>(page.request, 'HostService', 'GetHost', { hostname: 'demo-1' })
    await rpc(page.request, 'HostService', 'SetHostLabels', {
      targets: { hosts: { names: ['demo-1'] } }, expectedCount: '1',
      changes: { set: { environment: 'demo' } },
      expectedRevisions: [{ hostId: host.hostId, revision: host.revision }],
    }, session.csrfToken)
    const started = await rpc<{ job: { jobId: string } }>(page.request, 'JobService', 'RunJob', {
      action: 'disk_usage', targets: { hosts: { names: ['demo-1'] } },
      expectedCount: '1', reason: 'P10B local read-only E2E', waitSeconds: 30,
    }, session.csrfToken)
    jobId = started.job.jobId
    await expect.poll(async () => {
      const result = await rpc<{ job: { status: string } }>(page.request, 'JobService', 'GetJob', { jobId })
      return result.job.status
    }, { timeout: 60_000 }).toBe('JOB_STATUS_SUCCEEDED')
    await expect.poll(async () => {
      const result = await rpc<{ tasks: { outputStored: boolean }[] }>(page.request, 'JobService', 'ListTasks', { jobId })
      return result.tasks.length === 1 && result.tasks[0].outputStored
    }, { timeout: 60_000 }).toBe(true)
    const output = await rpc<{ data: string; eof: boolean; outputStored: boolean; outputTrust: string }>(page.request, 'JobService', 'GetJobOutput', {
      jobId, hostname: 'demo-1', stream: 'OUTPUT_STREAM_STDOUT', limitBytes: 16384,
    })
    expect(output.outputStored).toBe(true)
    expect(output.eof).toBe(true)
    expect(output.outputTrust).toBe('OUTPUT_TRUST_UNTRUSTED')
    stdout = Buffer.from(output.data, 'base64').toString('utf8')
    expect(stdout).toContain('Filesystem')
    expect(runtimeErrors.get(page), 'Browser runtime exceptions').toEqual([])
  } finally {
    await context.close()
  }
})

test.beforeEach(async ({ context, page }) => {
  await context.addCookies(adminState.cookies)
  watchErrors(page)
})

test.afterEach(async ({ page }, info) => {
  if (info.status !== info.expectedStatus) {
    await screenshot(page, `failure-${info.testId}`)
  }
  expect(runtimeErrors.get(page), 'Browser runtime exceptions').toEqual([])
})

test('LDAP sign in, secure session, sign out and protected route', async ({ context, page }) => {
  await context.clearCookies()
  await page.goto('/hosts')
  await expect(page).toHaveURL(`${origin}/login`)
  await screenshot(page, '01-login')
  await login(page)
  await page.getByRole('button', { name: '登出', exact: true }).click()
  await expect(page).toHaveURL(`${origin}/login`)
  await expect(page.getByLabel('密码', { exact: true })).toHaveValue('')
  const response = await page.request.post('/allowops.v1.AuthService/GetCurrentSession', { data: {} })
  expect(response.status()).toBe(401)
  expect((await response.json()).code).toBe('unauthenticated')
  await page.goto('/hosts')
  await expect(page).toHaveURL(`${origin}/login`)
  await screenshot(page, '02-logout')
})

test('overview shows real host and recent job', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: '概览', exact: true })).toBeVisible()
  await expect(page.locator('.metric').filter({ hasText: '在线主机' }).locator('strong')).toHaveText('1')
  await expect(page.locator('.metric').filter({ hasText: '离线主机' }).locator('strong')).toHaveText('0')
  await expect(page.getByRole('row').filter({ hasText: jobId })).toContainText('disk_usage')
  await expect(page.getByRole('row').filter({ hasText: jobId })).toContainText('成功')
  await screenshot(page, '03-overview')
})

test('host list, label editing and selector use persisted authorization labels', async ({ page }) => {
  await page.goto('/')
  await navigate(page, '主机')
  const row = page.getByRole('row').filter({ has: page.getByRole('link', { name: 'demo-1', exact: true }) })
  await expect(row).toContainText('在线')
  await expect(row).toContainText('environment=demo')
  await screenshot(page, '04-hosts')
  await row.getByRole('link', { name: 'demo-1', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'demo-1', exact: true })).toBeVisible()
  await page.getByLabel('授权标签', { exact: true }).fill('environment=demo\nteam=e2e\nnote=a, b')
  await page.getByRole('button', { name: '保存标签', exact: true }).click()
  await expect(page.getByText('标签已保存', { exact: true })).toBeVisible()
  const saved = await rpc<{ host: { authorizationLabels: Record<string, string> } }>(page.request, 'HostService', 'GetHost', { hostname: 'demo-1' })
  expect(saved.host.authorizationLabels).toEqual({ environment: 'demo', note: 'a, b', team: 'e2e' })
  await page.reload()
  await expect(page.getByLabel('授权标签', { exact: true })).toHaveValue('environment=demo\nnote=a, b\nteam=e2e')
  await screenshot(page, '05-host-detail')
  await navigate(page, '主机')
  await page.getByLabel('标签选择器', { exact: true }).fill('team=e2e')
  await expect(page.getByRole('link', { name: 'demo-1', exact: true })).toBeVisible()
  await page.getByLabel('标签选择器', { exact: true }).fill('team=absent')
  await expect(page.getByRole('link', { name: 'demo-1', exact: true })).toHaveCount(0)
  await expect(page.getByText('暂无数据', { exact: true })).toBeVisible()
})

test('create join token with CSRF and one-time secret', async ({ page }) => {
  await page.goto('/')
  await navigate(page, 'Join token')
  await page.getByLabel('最大使用次数', { exact: true }).fill('1')
  await page.getByLabel('有效期（小时）', { exact: true }).fill('2')
  const createdResponse = page.waitForResponse(response => response.url().endsWith('/allowops.v1.JoinTokenService/CreateJoinToken'))
  await page.getByRole('button', { name: '创建 join token', exact: true }).click()
  const response = await createdResponse
  expect(response.status()).toBe(200)
  const created = await response.json()
  const dialog = page.getByRole('dialog', { name: '请保存 token', exact: true })
  await expect(dialog).toBeVisible()
  // Avoid assertions that could print plaintext secrets on failure.
  expect((await dialog.locator('pre.secret').textContent()) === created.secret).toBe(true)
  expect(created.secret.length > 20).toBe(true)
  // The install command reads the secret from a file and never contains it (21c266a).
  const install = (await dialog.locator('pre:not(.secret)').textContent()) ?? ''
  expect(install.includes('--token-file ')).toBe(true)
  expect(install.includes(created.secret)).toBe(false)
  // The file hint precedes the install command (RR-d-06).
  expect(await dialog.locator('p + h3 + pre:not(.secret)').count()).toBe(1)
  await screenshot(page, '06-join-token-secret-masked')
  await dialog.getByRole('button', { name: '我已保存', exact: true }).click()
  await expect(dialog).toHaveCount(0)
  const row = page.getByRole('row').filter({ hasText: created.token.tokenId })
  await expect(row).toBeVisible()
  const persisted = await rpc<{ tokens: { tokenId: string; maxUses: number }[] }>(page.request, 'JoinTokenService', 'ListJoinTokens')
  expect(persisted.tokens.find(token => token.tokenId === created.token.tokenId)?.maxUses).toBe(1)
  expect(JSON.stringify(persisted).includes(created.secret)).toBe(false)
  await screenshot(page, '07-join-tokens')
})

test('catalog and exec, steps, script, builtin action definitions', async ({ page }) => {
  await page.goto('/')
  await navigate(page, '目录')
  await expect(page.getByText('generic-ops /', { exact: false })).toBeVisible()
  await expect(page.getByRole('button', { name: 'disk_usage', exact: true })).toBeVisible()
  await screenshot(page, '08-catalog')
  for (const [action, expected] of [
    ['disk_usage', '/usr/bin/df -h -x tmpfs -x devtmpfs'],
    ['host_snapshot', '"steps"'],
    ['nginx_access_stats', '"interpreter": "/usr/bin/python3"'],
    ['mysql_query_readonly', '"builtin": "mysql_query"'],
  ]) {
    // The catalog is longer than one client-side table page.
    const actions = page.locator('section.panel').filter({ has: page.getByRole('heading', { name: 'Action 列表', exact: true }) })
    while (!(await actions.getByRole('button', { name: action, exact: true }).count())) {
      const next = actions.getByRole('button', { name: '下一页', exact: true })
      await expect(next, `Catalog contains ${action}`).toBeEnabled()
      await next.click()
    }
    await page.getByRole('button', { name: action, exact: true }).click()
    const dialog = page.getByRole('dialog', { name: action, exact: true })
    await expect(dialog.locator('pre').filter({ hasText: expected })).toHaveCount(1)
    await expect(dialog.getByRole('heading', { name: '参数', exact: true })).toBeVisible()
    await expect(dialog.getByText('执行超时', { exact: true })).toBeVisible()
    await screenshot(page, `09-action-${action}`)
    await dialog.getByRole('button', { name: '关闭', exact: true }).click()
    // Reset action-table pagination before finding the next definition.
    await page.reload()
    await expect(page.getByRole('button', { name: 'disk_usage', exact: true })).toBeVisible()
  }
})

test('policy viewing includes default roles, output permission and history', async ({ page }) => {
  await page.goto('/')
  await navigate(page, '策略')
  const admin = page.getByRole('row').filter({ hasText: 'default:admin' })
  await expect(admin).toContainText('view_output')
  await expect(admin).toContainText('execute_action')
  const viewer = page.getByRole('row').filter({ hasText: 'default:viewer' })
  await expect(viewer).toContainText('view_jobs')
  await expect(viewer).not.toContainText('view_output')
  await expect(page.getByRole('heading', { name: '版本历史', exact: true })).toBeVisible()
  await screenshot(page, '10-policies')
})

test('Jobs displays completed read-only job and persisted stdout/stderr', async ({ page }) => {
  await page.goto('/')
  await navigate(page, 'Job')
  await page.getByLabel('Action', { exact: true }).fill('disk_usage')
  const row = page.getByRole('row').filter({ hasText: jobId })
  await expect(row).toContainText('成功')
  await screenshot(page, '11-jobs')
  await row.getByRole('link', { name: jobId, exact: true }).click()
  await expect(page.getByRole('heading', { name: jobId, exact: true })).toBeVisible()
  const task = page.getByRole('row').filter({ hasText: 'demo-1' })
  await expect(task).toContainText('成功')
  await expect(task).toContainText('是')
  await screenshot(page, '12-job-detail')
  const outputResponse = page.waitForResponse(response => response.url().endsWith('/allowops.v1.JobService/GetJobOutput'))
  await task.getByRole('button', { name: '查看输出 demo-1', exact: true }).click()
  await expectOutputResponse(await outputResponse, 200)
  const dialog = page.getByRole('dialog', { name: '主机输出：demo-1', exact: true })
  await expect(dialog.locator('section.output').filter({ has: page.getByRole('heading', { name: '标准输出', exact: true }) }).locator('pre')).toHaveText(stdout.trim())
  await expect(dialog.locator('section.output').filter({ has: page.getByRole('heading', { name: '标准错误', exact: true }) }).locator('pre')).toHaveText('—')
  await expect(dialog.getByText('主机输出是不可信数据', { exact: true })).toBeVisible()
  await expect(dialog.getByText('输出已读取完毕', { exact: true })).toHaveCount(2)
  await screenshot(page, '13-job-output')
})

test('viewer sees output button, API permission denial and translated notice (A34)', async ({ context, page }) => {
  await context.clearCookies()
  await login(page, 'demo-viewer')
  const session = await rpc<{ user: { effectiveRoles: string[] } }>(page.request, 'AuthService', 'GetCurrentSession')
  expect(session.user.effectiveRoles).toEqual(['viewer'])
  await page.goto(`/jobs/${jobId}`)
  await expect(page.getByRole('heading', { name: jobId, exact: true })).toBeVisible()
  const button = page.getByRole('button', { name: '查看输出 demo-1', exact: true })
  await expect(button).toBeEnabled()
  const deniedResponse = page.waitForResponse(response => response.url().endsWith('/allowops.v1.JobService/GetJobOutput'))
  await button.click()
  const denied = await deniedResponse
  await expectOutputResponse(denied, 403)
  expect((await denied.json()).code).toBe('permission_denied')
  const dialog = page.getByRole('dialog', { name: '主机输出：demo-1', exact: true })
  await expect(dialog.getByRole('alert')).toHaveCount(2)
  await expect(dialog.getByRole('alert')).toHaveText(['无权限', '无权限'])
  await expect(dialog.locator('pre')).toHaveText(['—', '—'])
  await screenshot(page, '14-output-denied')
  await dialog.getByRole('button', { name: '关闭', exact: true }).click()
  await page.getByRole('combobox', { name: '语言', exact: true }).selectOption('en')
  await page.getByRole('button', { name: 'View output demo-1', exact: true }).click()
  await expect(page.getByRole('dialog').getByRole('alert')).toHaveText(['Permission denied', 'Permission denied'])
  await screenshot(page, '15-output-denied-en')
})

test('audit query finds actual read-only execution and verifies hash chain', async ({ page }) => {
  await page.goto('/')
  await navigate(page, '审计')
  await page.getByLabel('主机', { exact: true }).fill('demo-1')
  await page.getByLabel('Action', { exact: true }).fill('disk_usage')
  await page.getByRole('button', { name: '查询', exact: true }).click()
  const rows = page.locator('tbody tr')
  await expect(rows).not.toHaveCount(0)
  await expect(rows.filter({ hasText: 'disk_usage' })).not.toHaveCount(0)
  const queried = await rpc<{ events: { seq: string; hostname: string; action: string; decision: string }[] }>(page.request, 'AuditService', 'ListAuditEvents', { query: { hostname: 'demo-1', action: 'disk_usage' } })
  expect(queried.events.some(event => event.hostname === 'demo-1' && event.action === 'disk_usage' && event.decision === 'allow')).toBe(true)
  await screenshot(page, '16-audit-query')
  await page.getByLabel('起始序列号', { exact: true }).fill('1')
  await page.getByLabel('结束序列号', { exact: true }).fill('3')
  await page.getByRole('button', { name: '校验哈希链', exact: true }).click()
  await expect(page.locator('main').getByText('哈希链校验通过，已校验 3 条', { exact: true })).toBeVisible()
})

test('Chinese and English navigation and page labels', async ({ page }) => {
  await page.goto('/')
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh-CN')
  await page.getByRole('combobox', { name: '语言', exact: true }).selectOption('en')
  await expect(page.locator('html')).toHaveAttribute('lang', 'en')
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible()
  await expect(page.getByRole('navigation', { name: 'Console navigation' }).getByRole('link', { name: 'Hosts', exact: true })).toBeVisible()
  await screenshot(page, '17-overview-en')
  await page.getByRole('combobox', { name: 'Language', exact: true }).selectOption('zh-CN')
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh-CN')
  await expect(page.getByRole('heading', { name: '概览', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: '登出', exact: true })).toBeVisible()
})
