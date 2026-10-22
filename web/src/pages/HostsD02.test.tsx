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

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

async function openHosts(tool: '批量设置标签' | 'CSV 导入标签') {
  window.history.replaceState({}, '', '/hosts')
  const view = render(<App />)
  await screen.findByRole('heading', { level: 1 }, { timeout: 5000 })
  fireEvent.click(screen.getByRole('button', { name: tool }))
  await screen.findByRole('heading', { name: tool })
  return view
}

describe('D02 bulk preview race', () => {
  it('ignores a stale bulk response after the draft changes', async () => {
    const originalListHosts = api.listHosts
    const gate = deferred<Awaited<ReturnType<typeof api.listHosts>>>()
    const listHosts = vi
      .spyOn(api, 'listHosts')
      .mockImplementation((input) =>
        input?.query?.selector === 'team=old'
          ? gate.promise
          : originalListHosts(input),
      )
    const setLabels = vi.spyOn(api, 'setHostLabels')
    try {
      const view = await openHosts('批量设置标签')
      const panel = screen
        .getByRole('heading', { name: '批量设置标签' })
        .closest('section')!
      fireEvent.change(within(panel).getByLabelText('标签选择器'), {
        target: { value: 'team=old' },
      })
      fireEvent.change(within(panel).getByLabelText('授权标签'), {
        target: { value: 'team=old' },
      })
      fireEvent.click(
        within(panel).getByRole('button', { name: '预览目标' }),
      )
      await waitFor(() =>
        expect(
          listHosts.mock.calls.some(
            (call) => call[0]?.query?.selector === 'team=old',
          ),
        ).toBe(true),
      )
      expect(
        listHosts.mock.calls.find(
          (call) => call[0]?.query?.selector === 'team=old',
        )?.[0],
      ).toEqual({
        query: { selector: 'team=old' },
      })
      // Draft changes while the old request is still pending.
      fireEvent.change(within(panel).getByLabelText('标签选择器'), {
        target: { value: 'team=new' },
      })
      fireEvent.change(within(panel).getByLabelText('授权标签'), {
        target: { value: 'team=new' },
      })
      await act(async () => {
        gate.resolve({
          hosts: [
            {
              hostId: 'host-01',
              hostname: 'web-01',
              authorizationLabels: { team: 'old' },
              reportedLabels: {},
              online: true,
              agentVersion: '0.1.0',
              loadedCatalogs: [],
              capabilities: {
                catalogSchemaVersions: [],
                parameterTypes: [],
                executionModes: [],
                builtins: [],
                outputFilters: [],
                features: [],
              },
              lastSeen: new Date().toISOString(),
              registeredAt: new Date().toISOString(),
              revision: '1',
            },
          ],
          page: { nextPageToken: '' },
          totalCount: '1',
          authorizationLabelCounts: [],
          labelCountsTruncated: false,
        })
        await gate.promise
      })
      // Stale old response must not re-enable submit.
      await waitFor(() => expect(within(panel).getByRole('button', { name: '预览目标' })).toBeEnabled())
      expect(
        within(panel).queryByRole('button', { name: /应用到/ }),
      ).not.toBeInTheDocument()
      expect(setLabels).not.toHaveBeenCalled()
      view.unmount()
    } finally {
      listHosts.mockRestore()
      setLabels.mockRestore()
    }
  })
})

describe('D02 csv preview race', () => {
  it('ignores a stale two-step CSV preview after the draft changes', async () => {
    const first = deferred<Awaited<ReturnType<typeof api.previewHostImport>>>()
    const second = deferred<
      Awaited<ReturnType<typeof api.getHostImportPreview>>
    >()
    const previewHostImport = vi
      .spyOn(api, 'previewHostImport')
      .mockImplementationOnce(() => first.promise)
    const getPreview = vi
      .spyOn(api, 'getHostImportPreview')
      .mockImplementationOnce(() => second.promise)
    const execute = vi.spyOn(api, 'executeHostImport')
    try {
      const view = await openHosts('CSV 导入标签')
      const panel = screen
        .getByRole('heading', { name: 'CSV 导入标签' })
        .closest('section')!
      const textarea = within(panel).getByLabelText('CSV 内容')
      fireEvent.change(textarea, {
        target: { value: 'hostname,set:env\nweb-01,old' },
      })
      fireEvent.click(within(panel).getByRole('button', { name: '预览变更' }))
      await waitFor(() => expect(previewHostImport).toHaveBeenCalledTimes(1))
      // Draft changes before either step resolves.
      fireEvent.change(textarea, {
        target: { value: 'hostname,set:env\nweb-01,new' },
      })
      await act(async () => {
        first.resolve({
          preview: {
            previewId: 'stale-preview',
            csvSha256: 'old',
            rowCount: '1',
            invalidRowCount: '0',
            expiresAt: new Date(Date.now() + 600000).toISOString(),
          },
        })
        await first.promise
      })
      await act(async () => {
        second.resolve({
          preview: {
            previewId: 'stale-preview',
            csvSha256: 'old',
            rowCount: '1',
            invalidRowCount: '0',
            expiresAt: new Date(Date.now() + 600000).toISOString(),
          },
          rows: [],
          page: { nextPageToken: '' },
        })
        await second.promise
      })
      await waitFor(() => expect(within(panel).getByRole('button', { name: '预览变更' })).toBeEnabled())
      expect(
        within(panel).queryByRole('button', { name: '确认导入' }),
      ).not.toBeInTheDocument()
      expect(execute).not.toHaveBeenCalled()
      expect(getPreview).not.toHaveBeenCalled()
      view.unmount()
    } finally {
      previewHostImport.mockRestore()
      getPreview.mockRestore()
      execute.mockRestore()
    }
  })
})

describe('D02 csv file input race', () => {
  it('ignores a stale FileReader load after the draft changes', async () => {
    const readers: {
      onload: (() => void) | null
      onerror: (() => void) | null
      result: string | ArrayBuffer | null
      readAsText: (file: Blob, encoding?: string) => void
    }[] = []
    class ControlledReader {
      onload: (() => void) | null = null
      onerror: (() => void) | null = null
      result: string | ArrayBuffer | null = null
      readAsText() {
        readers.push(this as unknown as (typeof readers)[number])
      }
    }
    const OriginalReader = globalThis.FileReader
    vi.stubGlobal('FileReader', ControlledReader)
    try {
      const view = await openHosts('CSV 导入标签')
      const panel = screen
        .getByRole('heading', { name: 'CSV 导入标签' })
        .closest('section')!
      const fileInput = within(panel).getByLabelText('选择 CSV 文件')
      const textarea = within(panel).getByLabelText('CSV 内容')
      const file = new File(['hostname,set:env\nweb-01,from-file'], 'a.csv', {
        type: 'text/csv',
      })
      fireEvent.change(fileInput, { target: { files: [file] } })
      expect(readers).toHaveLength(1)
      // User types a newer draft before the file load completes.
      fireEvent.change(textarea, {
        target: { value: 'hostname,set:env\nweb-01,typed-new' },
      })
      readers[0].result = 'hostname,set:env\nweb-01,from-file'
      act(() => readers[0].onload?.())
      expect(textarea).toHaveValue('hostname,set:env\nweb-01,typed-new')
      expect(
        within(panel).queryByRole('button', { name: '确认导入' }),
      ).not.toBeInTheDocument()
      view.unmount()
    } finally {
      vi.stubGlobal('FileReader', OriginalReader)
    }
  })
})


it('invalidates an in-flight CSV preview when a replacement file is selected', async () => {
  const pending = deferred<Awaited<ReturnType<typeof api.previewHostImport>>>()
  const previewHostImport = vi.spyOn(api, 'previewHostImport').mockReturnValueOnce(pending.promise)
  const getPreview = vi.spyOn(api, 'getHostImportPreview')
  try {
    await openHosts('CSV 导入标签')
    const panel = screen.getByRole('heading', { name: 'CSV 导入标签' }).closest('section')!
    const textarea = within(panel).getByLabelText('CSV 内容')
    fireEvent.change(textarea, { target: { value: 'hostname,set:env\nweb-01,old' } })
    fireEvent.click(within(panel).getByRole('button', { name: '预览变更' }))
    await waitFor(() => expect(previewHostImport).toHaveBeenCalledTimes(1))
    fireEvent.change(within(panel).getByLabelText('选择 CSV 文件'), {
      target: { files: [new File(['hostname,set:env\nweb-01,new'], 'replacement.csv', { type: 'text/csv' })] },
    })
    // Exercise the real FileReader -> form.setValue path, without a form change event.
    await waitFor(() => expect(textarea).toHaveValue('hostname,set:env\nweb-01,new'))
    await act(async () => {
      pending.resolve({ preview: { previewId: 'stale-file-preview', csvSha256: 'old', rowCount: '1', invalidRowCount: '0', expiresAt: '2099-01-01T00:00:00Z' } })
      await pending.promise
    })
    await waitFor(() => expect(within(panel).getByRole('button', { name: '预览变更' })).toBeEnabled())
    expect(getPreview).not.toHaveBeenCalled()
    expect(within(panel).queryByRole('button', { name: '确认导入' })).not.toBeInTheDocument()
    // A fresh preview must still work with the new CSV draft.
    fireEvent.click(within(panel).getByRole('button', { name: '预览变更' }))
    expect(await within(panel).findByRole('button', { name: '确认导入' })).toBeEnabled()
    expect(previewHostImport.mock.calls[1][0].csv).toBe(btoa('hostname,set:env\nweb-01,new'))
  } finally {
    previewHostImport.mockRestore()
    getPreview.mockRestore()
  }
})


it('invalidates the pending CSV preview immediately on file selection before FileReader completes', async () => {
  const readers: ControlledReader[] = []
  class ControlledReader {
    onload: (() => void) | null = null
    result: string | null = null
    readAsText() { readers.push(this) }
  }
  const originalReader = globalThis.FileReader
  vi.stubGlobal('FileReader', ControlledReader)
  const pending = deferred<Awaited<ReturnType<typeof api.previewHostImport>>>()
  const previewHostImport = vi.spyOn(api, 'previewHostImport').mockReturnValueOnce(pending.promise)
  const getPreview = vi.spyOn(api, 'getHostImportPreview')
  try {
    await openHosts('CSV 导入标签')
    const panel = screen.getByRole('heading', { name: 'CSV 导入标签' }).closest('section')!
    const textarea = within(panel).getByLabelText('CSV 内容')
    fireEvent.change(textarea, { target: { value: 'hostname,set:env\nweb-01,old' } })
    fireEvent.click(within(panel).getByRole('button', { name: '预览变更' }))
    await waitFor(() => expect(previewHostImport).toHaveBeenCalledTimes(1))
    fireEvent.change(within(panel).getByLabelText('选择 CSV 文件'), {
      target: { files: [new File(['hostname,set:env\nweb-01,new'], 'replacement.csv', { type: 'text/csv' })] },
    })
    expect(textarea).toHaveValue('hostname,set:env\nweb-01,old')
    await act(async () => {
      pending.resolve({ preview: { previewId: 'stale-before-file-load', csvSha256: 'old', rowCount: '1', invalidRowCount: '0', expiresAt: '2099-01-01T00:00:00Z' } })
      await pending.promise
    })
    await waitFor(() => expect(within(panel).getByRole('button', { name: '预览变更' })).toBeEnabled())
    expect(getPreview).not.toHaveBeenCalled()
    expect(within(panel).queryByRole('button', { name: '确认导入' })).not.toBeInTheDocument()
    act(() => {
      readers[0].result = 'hostname,set:env\nweb-01,new'
      readers[0].onload?.()
    })
    expect(textarea).toHaveValue('hostname,set:env\nweb-01,new')
    expect(within(panel).queryByRole('button', { name: '确认导入' })).not.toBeInTheDocument()
  } finally {
    previewHostImport.mockRestore()
    getPreview.mockRestore()
    vi.stubGlobal('FileReader', originalReader)
  }
})
