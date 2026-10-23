import { render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

const releaseNotes =
  'https://github.com/liubing0806/allowops/releases/tag/v0.2.0'
const update = {
  latestVersion: '0.2.0',
  publishedAt: '2026-10-20T00:00:00Z',
  checkedAt: '2026-10-22T08:00:00Z',
}

beforeEach(async () => {
  window.history.replaceState({}, '', '/')
  await i18n.changeLanguage('zh-CN')
})
afterEach(() => vi.restoreAllMocks())

async function open(path: string) {
  window.history.replaceState({}, '', path)
  render(<App />)
  await screen.findByRole('heading', { level: 1 }, { timeout: 5000 })
}

async function withSession(gatewayUpdate?: typeof update) {
  const current = await api.getCurrentSession()
  vi.spyOn(api, 'getCurrentSession').mockResolvedValue({
    ...current,
    gatewayVersion: '0.1.0',
    gatewayUpdate,
  })
}

async function withStatus(
  overrides: Partial<Awaited<ReturnType<typeof api.getSystemStatus>>>,
) {
  const status = await api.getSystemStatus()
  vi.spyOn(api, 'getSystemStatus').mockResolvedValue({
    ...status,
    gatewayVersion: '0.1.0',
    ...overrides,
  })
}

describe('sidebar update notice', () => {
  it('links the newer release notes next to the gateway version', async () => {
    await withSession(update)
    await open('/')
    const nav = screen.getByRole('complementary')
    const link = within(nav).getByRole('link', { name: /有新版本.*0\.2\.0/ })
    expect(link).toHaveTextContent('有新版本')
    expect(link).toHaveAttribute('href', releaseNotes)
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  })
  it('shows no notice without a newer release', async () => {
    await withSession()
    await open('/')
    const nav = screen.getByRole('complementary')
    expect(within(nav).getByText('v0.1.0')).toBeInTheDocument()
    expect(within(nav).queryByText('有新版本')).not.toBeInTheDocument()
  })
})

describe('overview update notice', () => {
  it('lists the newer gateway release under needs attention', async () => {
    await withStatus({ updateCheckEnabled: true, gatewayUpdate: update })
    await open('/')
    const item = await screen.findByRole('link', {
      name: '网关有新版本 v0.2.0',
    })
    expect(item).toHaveAttribute('href', '/system')
  })
  it('omits the item without a newer release', async () => {
    await withStatus({ updateCheckEnabled: true })
    await open('/')
    await screen.findByText(/个目录将在 14 天内到期/)
    expect(screen.queryByText(/网关有新版本/)).not.toBeInTheDocument()
  })
})

describe('system gateway version', () => {
  it('shows the newer release, the check time and hosts below the gateway', async () => {
    await withStatus({
      updateCheckEnabled: true,
      gatewayUpdate: update,
      updateCheckedAt: update.checkedAt,
      hostsBelowGatewayVersion: '3',
    })
    await open('/system')
    const panel = (
      await screen.findByRole('heading', { name: '网关版本' })
    ).closest('section') as HTMLElement
    expect(within(panel).getByText('v0.1.0')).toBeInTheDocument()
    expect(within(panel).getByText('已开启')).toBeInTheDocument()
    expect(
      within(panel).getByRole('link', { name: 'v0.2.0 发布说明' }),
    ).toHaveAttribute('href', releaseNotes)
    expect(
      within(panel).getByText('3 台主机的主机端版本低于网关'),
    ).toBeInTheDocument()
    expect(within(panel).queryByText(/尚未检查/)).not.toBeInTheDocument()
  })
  it('reports a disabled check', async () => {
    await withStatus({ updateCheckEnabled: false })
    await open('/system')
    const panel = (
      await screen.findByRole('heading', { name: '网关版本' })
    ).closest('section') as HTMLElement
    expect(within(panel).getByText('未开启')).toBeInTheDocument()
    expect(within(panel).queryByText(/发布说明/)).not.toBeInTheDocument()
  })
  it('reports the last check error and an up-to-date gateway', async () => {
    await withStatus({
      updateCheckEnabled: true,
      updateCheckedAt: update.checkedAt,
      updateCheckError: 'request failed',
    })
    await open('/system')
    const panel = (
      await screen.findByRole('heading', { name: '网关版本' })
    ).closest('section') as HTMLElement
    expect(within(panel).getByText('已是最新版本')).toBeInTheDocument()
    expect(
      within(panel).getByText('最近一次检查失败：request failed'),
    ).toBeInTheDocument()
  })
  it('warns when gateway instances run different versions', async () => {
    const listed = await api.listGatewayInstances()
    vi.spyOn(api, 'listGatewayInstances').mockResolvedValue({
      ...listed,
      instances: listed.instances.map((instance, i) => ({
        ...instance,
        version: i === 0 ? '0.1.0' : '0.2.0',
      })),
    })
    await open('/system')
    expect(
      await screen.findByText('网关实例版本不一致：0.1.0、0.2.0'),
    ).toBeInTheDocument()
  })
  it('shows no mismatch warning when instances agree', async () => {
    await open('/system')
    await screen.findByText('gateway-02')
    expect(screen.queryByText(/网关实例版本不一致/)).not.toBeInTheDocument()
  })
})
