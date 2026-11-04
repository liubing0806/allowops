import { fireEvent, render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api, type JoinToken } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

async function openJoinTokens() {
  window.history.replaceState({}, '', '/join-tokens')
  render(<App />)
  await screen.findByRole('heading', { name: 'Join token', level: 1 }, { timeout: 5000 })
  return screen.findByRole('region', { name: 'Join token 列表' })
}

const hour = 3600000
const at = (offset: number) => new Date(Date.now() + offset).toISOString()

describe('join token list', () => {
  it('shows the created-at column and uses as used/max', async () => {
    const list = await openJoinTokens()
    expect(
      within(list).getByRole('columnheader', { name: '创建时间' }),
    ).toBeInTheDocument()
    const row = (await within(list).findByText('join-01')).closest('tr')!
    expect(within(row).getByText('3/10')).toBeInTheDocument()
    expect(within(row).getByText('有效')).toBeInTheDocument()
  })
  it('derives used-up, expiring and expired states and offers revoke only on live tokens', async () => {
    const tokens: JoinToken[] = [
      { tokenId: 'jt-used', maxUses: 2, usedCount: 2, createdAt: at(-hour), expiresAt: at(20 * hour) },
      { tokenId: 'jt-soon', maxUses: 5, usedCount: 1, createdAt: at(-hour), expiresAt: at(hour) },
      { tokenId: 'jt-old', maxUses: 1, usedCount: 0, createdAt: at(-30 * hour), expiresAt: at(-hour) },
      { tokenId: 'jt-off', maxUses: 1, usedCount: 0, createdAt: at(-hour), expiresAt: at(20 * hour), revokedAt: at(-60000) },
    ]
    const list = vi
      .spyOn(api, 'listJoinTokens')
      .mockResolvedValue({ tokens, page: { nextPageToken: '' } })
    try {
      const region = await openJoinTokens()
      const row = async (id: string) =>
        (await within(region).findByText(id)).closest('tr')!
      expect(within(await row('jt-used')).getByText('已用尽')).toBeInTheDocument()
      expect(within(await row('jt-soon')).getByText('即将到期')).toBeInTheDocument()
      expect(within(await row('jt-old')).getByText('已过期')).toBeInTheDocument()
      expect(within(await row('jt-off')).getByText('已吊销')).toBeInTheDocument()
      const revoke = within(region).getAllByRole('button', { name: '吊销' })
      expect(revoke).toHaveLength(1)
      expect(within(await row('jt-soon')).getByRole('button', { name: '吊销' })).toBe(
        revoke[0],
      )
    } finally {
      list.mockRestore()
    }
  })
  it('walks through the join steps and keeps the default-deny reminder', async () => {
    await openJoinTokens()
    fireEvent.click(screen.getByRole('button', { name: '创建 join token' }))
    const dialog = await screen.findByRole('dialog', { name: '请保存 token' })
    const steps = within(dialog).getAllByRole('listitem')
    expect(steps).toHaveLength(3)
    expect(within(steps[1]).getByText(/allowops-agent join/)).toBeInTheDocument()
    expect(
      within(steps[2]).getByText(/对所有 agent 默认拒绝执行/),
    ).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '我已保存' }))
    expect(screen.queryByText(/^aops_join_/)).not.toBeInTheDocument()
  })
})
