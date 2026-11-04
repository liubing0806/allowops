import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

async function openCatalog() {
  window.history.replaceState({}, '', '/catalog')
  render(<App />)
  await screen.findByRole('heading', { name: '目录', level: 1 }, { timeout: 5000 })
  return screen.findByRole('region', { name: '当前目录' })
}

describe('catalog page', () => {
  it('shows the envelope size of the current catalog', async () => {
    const card = await openCatalog()
    expect(within(card).getByText('信封大小')).toBeInTheDocument()
    expect(within(card).getByText('4.0 KiB')).toBeInTheDocument()
    expect(within(card).getByText(/2 个 action/)).toBeInTheDocument()
  })
  it('filters actions by risk and by search text', async () => {
    await openCatalog()
    const list = screen.getByRole('region', { name: 'Action 列表' })
    await within(list).findByRole('button', { name: 'journal_view_log' })
    fireEvent.click(
      within(screen.getByRole('group', { name: '按风险筛选' })).getByRole(
        'button',
        { name: /^写入/ },
      ),
    )
    expect(
      within(list).queryByRole('button', { name: 'journal_view_log' }),
    ).not.toBeInTheDocument()
    expect(
      within(list).getByRole('button', { name: 'systemd_restart_service' }),
    ).toBeInTheDocument()
    expect(within(list).getByText('显示 1 / 2 个 action')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('搜索 action'), {
      target: { value: 'journal' },
    })
    expect(within(list).getByText('显示 0 / 2 个 action')).toBeInTheDocument()
  })
  it('switches to an older version from the history and back', async () => {
    await openCatalog()
    fireEvent.click(screen.getByRole('button', { name: '版本历史' }))
    const history = screen.getByRole('region', { name: '版本历史' })
    fireEvent.click(within(history).getByRole('button', { name: /20261001090000/ }))
    const card = await screen.findByRole('region', { name: '历史版本' })
    expect(within(card).getByText('20261001090000')).toBeInTheDocument()
    expect(within(card).getByText('2.0 KiB')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '回到当前目录' }))
    expect(await screen.findByRole('region', { name: '当前目录' })).toBeInTheDocument()
  })
  it('copies the publish command for this gateway', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } })
    try {
      await openCatalog()
      fireEvent.click(screen.getByRole('button', { name: '复制发布命令' }))
      await waitFor(() =>
        expect(writeText).toHaveBeenCalledWith(
          `allowops catalog publish -f catalog.dsse.json --gateway ${window.location.origin} --token-env ALLOWOPS_PUBLISHER_TOKEN`,
        ),
      )
    } finally {
      vi.unstubAllGlobals()
    }
  })
  it('closes the action panel on Escape and keeps the list usable', async () => {
    await openCatalog()
    const name = await screen.findByRole('button', { name: 'journal_view_log' })
    name.focus()
    fireEvent.click(name)
    const panel = await screen.findByRole('complementary', {
      name: 'journal_view_log',
    })
    expect(await within(panel).findByText('输出过滤')).toBeInTheDocument()
    expect(within(panel).getByText('幂等')).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() =>
      expect(
        screen.queryByRole('complementary', { name: 'journal_view_log' }),
      ).not.toBeInTheDocument(),
    )
    expect(document.activeElement).toBe(name)
  })
})
