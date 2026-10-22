import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'
import App from '@/App'
import i18n from '@/i18n'
import en from '@/locales/en.json'
import zhCN from '@/locales/zh-CN.json'

beforeEach(async () => {
  window.history.replaceState({}, '', '/')
  await i18n.changeLanguage('zh-CN')
})

async function open(path: string) {
  window.history.replaceState({}, '', path)
  const view = render(<App />)
  await screen.findByRole('heading', { level: 1 }, { timeout: 5000 })
  return view
}

describe('console pages', () => {
  it('logs in with the local LDAP form', async () => {
    await open('/login')
    expect(
      await screen.findByRole('button', { name: '使用 OIDC 登录' }),
    ).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('用户名'), {
      target: { value: 'console-user' },
    })
    fireEvent.change(screen.getByLabelText('密码'), {
      target: { value: 'demo-password' },
    })
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '登录' })).toBeEnabled(),
    )
    fireEvent.click(screen.getByRole('button', { name: '登录' }))
    expect(
      await screen.findByRole('heading', { name: '概览', level: 1 }),
    ).toBeInTheDocument()
  })
  it('opens recent jobs from overview', async () => {
    await open('/')
    expect(await screen.findByText('在线主机')).toBeInTheDocument()
    fireEvent.click(
      await screen.findByRole('link', { name: 'job-20261013-0042' }),
    )
    expect(
      await screen.findByRole('heading', { name: 'job-20261013-0042' }),
    ).toBeInTheDocument()
  })
  it('filters hosts by selector', async () => {
    await open('/hosts')
    expect(
      await screen.findByRole('link', { name: 'web-01' }),
    ).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('标签选择器'), {
      target: { value: 'env=stage' },
    })
    await waitFor(() =>
      expect(
        screen.queryByRole('link', { name: 'web-01' }),
      ).not.toBeInTheDocument(),
    )
    expect(
      await screen.findByRole('link', { name: 'web-03' }),
    ).toBeInTheDocument()
  })
  it('edits authorization labels in host detail', async () => {
    await open('/hosts/web-01')
    expect(
      await screen.findByRole('heading', { name: 'web-01', level: 1 }),
    ).toBeInTheDocument()
    fireEvent.change(await screen.findByLabelText('授权标签'), {
      target: { value: 'env=prod\ntier=edge' },
    })
    fireEvent.click(screen.getByRole('button', { name: '保存标签' }))
    expect(await screen.findByRole('status')).toHaveTextContent('标签已保存')
  })
  it('creates a join token and hides it after dismissal', async () => {
    await open('/join-tokens')
    expect(
      await screen.findByRole('heading', { name: 'Join token', level: 1 }),
    ).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '创建 join token' }))
    const dialog = await screen.findByRole('dialog', { name: '请保存 token' })
    expect(within(dialog).getByText(/allowops-agent join/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '我已保存' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByText(/aops_join_/)).not.toBeInTheDocument()
  })
  it('opens action details in catalog', async () => {
    await open('/catalog')
    expect(await screen.findByText('目录过期倒计时')).toBeInTheDocument()
    fireEvent.click(
      await screen.findByRole('button', { name: 'journal_view_log' }),
    )
    const dialog = await screen.findByRole('dialog', {
      name: 'journal_view_log',
    })
    expect(await within(dialog).findByText(/journalctl/)).toBeInTheDocument()
    expect(within(dialog).getByText('secrets')).toBeInTheDocument()
  })
  it('requires simulation before saving a policy', async () => {
    await open('/policies')
    expect(
      await screen.findByRole('heading', { name: '策略', level: 1 }),
    ).toBeInTheDocument()
    fireEvent.click(
      await screen.findByRole('button', { name: '编辑 readonly-all' }),
    )
    expect(screen.getByRole('button', { name: '保存策略' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '试算' })).toBeEnabled(),
    )
    fireEvent.click(screen.getByRole('button', { name: '试算' }))
    expect(
      await screen.findByRole('heading', { name: '试算结果' }),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '保存策略' })).toBeEnabled()
  })
  it('creates a service account token and hides it after dismissal', async () => {
    await open('/service-accounts')
    expect(await screen.findByText('即将到期')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '管理 agent-readonly' }))
    fireEvent.click(screen.getByRole('button', { name: '创建 token' }))
    const dialog = await screen.findByRole('dialog', { name: '请保存 token' })
    expect(within(dialog).getByText(/^aops_[a-f0-9]{64}$/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '我已保存' }))
    expect(screen.queryByText(/^aops_[a-f0-9]{64}$/)).not.toBeInTheDocument()
  })
  it('filters jobs using the documented status', async () => {
    await open('/jobs')
    expect(
      await screen.findByRole('link', { name: 'job-20261013-0042' }),
    ).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Job 状态'), {
      target: { value: 'JOB_STATUS_RUNNING' },
    })
    await waitFor(() =>
      expect(
        screen.queryByRole('link', { name: 'job-20261013-0042' }),
      ).not.toBeInTheDocument(),
    )
    expect(
      await screen.findByRole('link', { name: 'job-20261013-0043' }),
    ).toBeInTheDocument()
  })
  it('shows host output as plain text in job detail', async () => {
    await open('/jobs/job-20261013-0042')
    fireEvent.click(
      await screen.findByRole('button', { name: '查看输出 web-01' }),
    )
    expect(
      await screen.findByText('service=api status=active'),
    ).toBeInTheDocument()
    expect(screen.getByText('主机输出是不可信数据')).toBeInTheDocument()
  })
  it('verifies an audit hash chain', async () => {
    await open('/audit')
    expect(
      await screen.findByRole('heading', { name: '审计', level: 1 }),
    ).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '校验哈希链' }))
    expect(await screen.findByRole('status')).toHaveTextContent(
      '哈希链校验通过',
    )
  })
  it('updates user role assignments', async () => {
    await open('/users')
    fireEvent.click(
      await screen.findByRole('button', { name: '分配角色 audit-user' }),
    )
    fireEvent.click(screen.getByLabelText('operator'))
    fireEvent.click(screen.getByRole('button', { name: '保存角色' }))
    expect(await screen.findByRole('status')).toHaveTextContent('角色已保存')
  })
  it('refreshes dependency health in system', async () => {
    await open('/system')
    expect(await screen.findByText('PostgreSQL')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '刷新健康状态' }))
    expect(await screen.findByRole('status')).toHaveTextContent(
      '健康状态已刷新',
    )
  })
  it('changes the entire console language', async () => {
    await open('/')
    fireEvent.change(await screen.findByLabelText('语言'), {
      target: { value: 'en' },
    })
    expect(
      await screen.findByRole('heading', { name: 'Overview', level: 1 }),
    ).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Hosts' })).toBeInTheDocument()
  })
  it('logs out and returns to the login page', async () => {
    await open('/')
    fireEvent.click(await screen.findByRole('button', { name: '登出' }))
    expect(
      await screen.findByRole('heading', { name: '登录控制台' }),
    ).toBeInTheDocument()
  })
  it('keeps every translation key consistent', () => {
    expect(Object.keys(zhCN).sort()).toEqual(Object.keys(en).sort())
  })
})
