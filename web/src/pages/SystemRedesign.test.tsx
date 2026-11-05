import { fireEvent, render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

async function openSystem() {
  window.history.replaceState({}, '', '/system')
  render(<App />)
  await screen.findByRole('heading', { name: '系统', level: 1 }, { timeout: 5000 })
  await screen.findByText('PostgreSQL')
}

describe('system redesign', () => {
  it('shows service limits from GetSystemStatus', async () => {
    await openSystem()
    const limits = screen.getByRole('region', { name: '服务限制' })
    expect(within(limits).getByText('单条消息上限').nextSibling).toHaveTextContent('1 MiB')
    expect(within(limits).getByText('默认 / 最大分页').nextSibling).toHaveTextContent('50 / 200')
    expect(within(limits).getByText('目录大小上限').nextSibling).toHaveTextContent('64 MiB')
  })
  it('counts agents below the gateway and links to the outdated host filter', async () => {
    await openSystem()
    const distribution = screen.getByRole('region', { name: '主机端版本分布' })
    expect(
      await within(distribution).findByText('1 台主机的主机端版本低于网关 0.1.0。'),
    ).toBeInTheDocument()
    fireEvent.click(within(distribution).getByRole('link', { name: '在主机列表中筛选「需升级」→' }))
    expect(await screen.findByRole('heading', { name: '主机', level: 1 })).toBeInTheDocument()
    expect(window.location.search).toBe('?status=outdated')
  })
  it('shows instance cards and flags differing instance versions', async () => {
    const original = api.listGatewayInstances
    const spy = vi.spyOn(api, 'listGatewayInstances').mockImplementation(async () => {
      const result = await original()
      result.instances[1] = { ...result.instances[1], version: '0.0.9', draining: true }
      return result
    })
    try {
      await openSystem()
      const instances = screen.getByRole('region', { name: '网关实例' })
      expect(await within(instances).findByText('gateway-02')).toBeInTheDocument()
      expect(within(instances).getByText('正在停止接收任务')).toBeInTheDocument()
      expect(screen.getByText('网关实例版本不一致：0.0.9、0.1.0')).toBeInTheDocument()
    } finally {
      spy.mockRestore()
    }
  })
})
