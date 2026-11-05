import { fireEvent, render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

async function openOverview() {
  window.history.replaceState({}, '', '/')
  render(<App />)
  await screen.findByRole('heading', { name: '概览', level: 1 }, { timeout: 5000 })
  return screen.findByRole('region', { name: '需要处理' })
}

describe('overview redesign', () => {
  it('lists unlabeled hosts and agents below the gateway', async () => {
    const attention = await openOverview()
    expect(await within(attention).findByText('1 台主机没有授权标签')).toBeInTheDocument()
    expect(within(attention).getByText('worker-01 · 对所有 agent 默认拒绝执行')).toBeInTheDocument()
    expect(
      await within(attention).findByText('1 台主机的主机端版本低于网关 0.1.0'),
    ).toBeInTheDocument()
    expect(within(attention).getByText('0.0.9 × 1')).toBeInTheDocument()
    fireEvent.click(within(attention).getByRole('link', { name: '设置标签' }))
    expect(await screen.findByRole('link', { name: 'worker-01' })).toBeInTheDocument()
    expect(window.location.search).toBe('?status=unlabeled')
  })
  it('shows expiry items only when the API reports them', async () => {
    const original = api.getSystemStatus
    const spy = vi.spyOn(api, 'getSystemStatus').mockImplementation(async () => ({
      ...(await original()),
      expiringCatalogs: '0',
      expiringServiceAccountTokens: '2',
    }))
    try {
      const attention = await openOverview()
      expect(
        await within(attention).findByText('2 个服务账号 token 将在 7 天内到期'),
      ).toBeInTheDocument()
      expect(within(attention).queryByText(/个目录将在 14 天内到期/)).not.toBeInTheDocument()
    } finally {
      spy.mockRestore()
    }
  })
  it('builds the summary sentence from API counts', async () => {
    await openOverview()
    const summary = screen.getByRole('region', { name: '当前状态' })
    expect(summary).toHaveTextContent('3 / 4 台主机在线。')
    expect(
      await within(summary).findByText(/1 台主机没有授权标签，agent 调用会被直接拒绝。/),
    ).toBeInTheDocument()
  })
})
