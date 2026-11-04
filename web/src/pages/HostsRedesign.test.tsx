import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

async function openHosts(path = '/hosts', host = 'web-01') {
  window.history.replaceState({}, '', path)
  const view = render(<App />)
  await screen.findByRole('heading', { name: '主机', level: 1 }, { timeout: 5000 })
  await screen.findByRole('link', { name: host })
  return view
}

async function openOverview() {
  window.history.replaceState({}, '', '/')
  render(<App />)
  await screen.findByRole('heading', { name: '概览', level: 1 }, { timeout: 5000 })
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((res) => {
    resolve = res
  })
  return { promise, resolve }
}

describe('hosts status segments', () => {
  it('filters unlabeled hosts and keeps the default-deny hint', async () => {
    await openHosts()
    const group = screen.getByRole('group', { name: '按状态筛选' })
    fireEvent.click(within(group).getByRole('button', { name: /^无授权标签/ }))
    await waitFor(() =>
      expect(screen.queryByRole('link', { name: 'web-01' })).not.toBeInTheDocument(),
    )
    expect(screen.getByRole('link', { name: 'worker-01' })).toBeInTheDocument()
    expect(screen.getByText('无授权标签，默认拒绝')).toBeInTheDocument()
    expect(window.location.search).toBe('?status=unlabeled')
  })
  it('lists hosts below the gateway version or on an old catalog', async () => {
    await openHosts('/hosts?status=outdated', 'web-02')
    expect(screen.queryByRole('link', { name: 'web-01' })).not.toBeInTheDocument()
    expect(screen.getByText('可升级到 0.1.0')).toBeInTheDocument()
  })
})

describe('hosts selection bar', () => {
  it('previews a label diff for the selection and applies it with revisions', async () => {
    const setLabels = vi.spyOn(api, 'setHostLabels')
    try {
      await openHosts()
      fireEvent.click(screen.getByLabelText('选择 web-01'))
      fireEvent.click(screen.getByLabelText('选择 web-02'))
      const bar = screen.getByRole('toolbar', { name: '批量操作' })
      expect(bar).toHaveTextContent('已选 2 台')
      fireEvent.click(within(bar).getByRole('button', { name: '设置标签…' }))
      const panel = screen
        .getByRole('heading', { name: '设置所选 2 台主机的授权标签' })
        .closest('section')!
      fireEvent.change(within(panel).getByLabelText('授权标签'), {
        target: { value: 'team=ops' },
      })
      fireEvent.click(within(panel).getByRole('button', { name: '预览目标' }))
      const apply = await within(panel).findByRole('button', {
        name: '应用到 2 台主机',
      })
      expect(within(panel).getAllByText('team=ops')).toHaveLength(2)
      expect(setLabels).not.toHaveBeenCalled()
      fireEvent.click(apply)
      expect(await screen.findByRole('status')).toHaveTextContent(
        '已更新 2 台主机的标签',
      )
      expect(setLabels).toHaveBeenCalledWith({
        targets: { hosts: { names: ['web-01', 'web-02'] } },
        expectedCount: '2',
        changes: { set: { team: 'ops' }, remove: [] },
        expectedRevisions: [
          { hostId: 'host-01', revision: '1' },
          { hostId: 'host-02', revision: '1' },
        ],
      })
      await waitFor(() =>
        expect(screen.queryByRole('toolbar', { name: '批量操作' })).not.toBeInTheDocument(),
      )
    } finally {
      setLabels.mockRestore()
    }
  })
  it('drops a pending preview when the selection changes', async () => {
    const original = api.listHosts
    const gate = deferred<Awaited<ReturnType<typeof api.listHosts>>>()
    let gated = false
    let setLabelsOpen = false
    const listHosts = vi.spyOn(api, 'listHosts').mockImplementation((input) => {
      if (input === undefined && !gated && setLabelsOpen) {
        gated = true
        return gate.promise
      }
      return original(input)
    })
    const setLabels = vi.spyOn(api, 'setHostLabels')
    try {
      await openHosts()
      fireEvent.click(screen.getByLabelText('选择 web-01'))
      fireEvent.click(screen.getByLabelText('选择 web-02'))
      fireEvent.click(screen.getByRole('button', { name: '设置标签…' }))
      const panel = screen
        .getByRole('heading', { name: '设置所选 2 台主机的授权标签' })
        .closest('section')!
      fireEvent.change(within(panel).getByLabelText('授权标签'), {
        target: { value: 'team=ops' },
      })
      setLabelsOpen = true
      fireEvent.click(within(panel).getByRole('button', { name: '预览目标' }))
      await waitFor(() => expect(gated).toBe(true))
      // The selection shrinks while the preview read is still pending.
      fireEvent.click(screen.getByLabelText('选择 web-02'))
      const fresh = await original()
      await act(async () => {
        gate.resolve(fresh)
        await gate.promise
      })
      const shrunk = screen
        .getByRole('heading', { name: '设置所选 1 台主机的授权标签' })
        .closest('section')!
      await waitFor(() =>
        expect(within(shrunk).getByRole('button', { name: '预览目标' })).toBeEnabled(),
      )
      expect(
        within(shrunk).queryByRole('button', { name: /应用到/ }),
      ).not.toBeInTheDocument()
      expect(setLabels).not.toHaveBeenCalled()
    } finally {
      listHosts.mockRestore()
      setLabels.mockRestore()
    }
  })
  it('copies the selection as MCP targets with expected_count', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } })
    try {
      await openHosts()
      fireEvent.click(screen.getByLabelText('选择 web-01'))
      fireEvent.click(screen.getByRole('button', { name: '复制为 MCP 目标' }))
      await waitFor(() =>
        expect(writeText).toHaveBeenCalledWith(
          '{"targets":{"hosts":["web-01"]},"expected_count":1}',
        ),
      )
      expect(await screen.findByRole('status')).toHaveTextContent(
        '已复制 1 台主机作为 MCP 调用目标',
      )
    } finally {
      vi.unstubAllGlobals()
    }
  })
})

describe('host detail side panel', () => {
  it('closes on Escape and returns focus to the opener', async () => {
    await openHosts()
    const link = screen.getByRole('link', { name: 'web-01' })
    link.focus()
    fireEvent.click(link)
    expect(
      await screen.findByRole('heading', { name: 'web-01', level: 2 }),
    ).toBeInTheDocument()
    // The list stays usable behind the panel.
    expect(screen.getByRole('link', { name: 'web-03' })).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() =>
      expect(
        screen.queryByRole('heading', { name: 'web-01', level: 2 }),
      ).not.toBeInTheDocument(),
    )
    expect(document.activeElement).toBe(link)
  })
  it('shows the default-deny warning for an unlabeled host', async () => {
    await openHosts('/hosts/worker-01', 'worker-01')
    expect(
      await screen.findByRole('heading', { name: 'worker-01', level: 2 }),
    ).toBeInTheDocument()
    expect(await screen.findByText('未设置授权标签，默认拒绝执行')).toBeInTheDocument()
  })
})

describe('command palette', () => {
  it('jumps to a host by name with the keyboard', async () => {
    await openOverview()
    fireEvent.keyDown(document, { key: 'k', ctrlKey: true })
    const dialog = await screen.findByRole('dialog', { name: '命令面板' })
    const input = within(dialog).getByRole('combobox')
    fireEvent.change(input, { target: { value: 'worker' } })
    expect(
      await within(dialog).findByRole('option', { name: /worker-01/ }),
    ).toHaveAttribute('aria-selected', 'true')
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(
      await screen.findByRole('heading', { name: 'worker-01', level: 2 }),
    ).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '命令面板' })).not.toBeInTheDocument()
  })
  it('opens the unlabeled host filter from a command', async () => {
    await openOverview()
    fireEvent.click(screen.getByRole('button', { name: /搜索或执行命令/ }))
    const dialog = await screen.findByRole('dialog', { name: '命令面板' })
    fireEvent.click(
      within(dialog).getByRole('option', { name: '查看无授权标签的主机' }),
    )
    expect(await screen.findByRole('link', { name: 'worker-01' })).toBeInTheDocument()
    expect(window.location.search).toBe('?status=unlabeled')
  })
})
