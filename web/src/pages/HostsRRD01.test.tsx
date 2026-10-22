import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => { await i18n.changeLanguage('zh-CN') })

async function openHosts(tool: '批量设置标签' | 'CSV 导入标签') {
  window.history.replaceState({}, '', '/hosts')
  const view = render(<App />)
  await screen.findByRole('heading', { level: 1 }, { timeout: 5000 })
  fireEvent.click(screen.getByRole('button', { name: tool }))
  await screen.findByRole('heading', { name: tool })
  return view
}

describe('RR-d-01 trimmed drafts', () => {
  it.each([
    ['no trailing newline', 'hostname,set:env\nweb-01,x'],
    ['trailing newline', 'hostname,set:env\nweb-01,x\n'],
  ])('CSV preview appears with %s', async (_n, csv) => {
    const previewHostImport = vi.spyOn(api, 'previewHostImport')
    const getPreview = vi.spyOn(api, 'getHostImportPreview')
    const view = await openHosts('CSV 导入标签')
    try {
      const panel = screen.getByRole('heading', { name: 'CSV 导入标签' }).closest('section')!
      fireEvent.change(within(panel).getByLabelText('CSV 内容'), { target: { value: csv } })
      fireEvent.click(within(panel).getByRole('button', { name: '预览变更' }))
      await waitFor(() => expect(previewHostImport).toHaveBeenCalledTimes(1))
      await waitFor(() => expect(within(panel).getByRole('button', { name: '预览变更' })).toBeEnabled())
      await new Promise((r) => setTimeout(r, 200))
      expect(within(panel).getByRole('button', { name: '确认导入' })).toBeInTheDocument()
    } finally { view.unmount(); previewHostImport.mockRestore(); getPreview.mockRestore() }
  })
  it.each([['team=a'], ['team=a ']])('bulk preview appears with selector %j', async (selector) => {
    const listHosts = vi.spyOn(api, 'listHosts')
    const view = await openHosts('批量设置标签')
    try {
      const panel = screen.getByRole('heading', { name: '批量设置标签' }).closest('section')!
      fireEvent.change(within(panel).getByLabelText('标签选择器'), { target: { value: selector } })
      fireEvent.change(within(panel).getByLabelText('授权标签'), { target: { value: 'team=b' } })
      const before = listHosts.mock.calls.length
      fireEvent.click(within(panel).getByRole('button', { name: '预览目标' }))
      await waitFor(() => expect(listHosts.mock.calls.length).toBeGreaterThan(before))
      await new Promise((r) => setTimeout(r, 200))
      expect(within(panel).getByRole('button', { name: /应用到/ })).toBeInTheDocument()
    } finally { view.unmount(); listHosts.mockRestore() }
  })
})
