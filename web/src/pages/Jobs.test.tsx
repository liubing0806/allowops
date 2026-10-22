import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api, ApiError } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

async function openOutput() {
  const button = await screen.findByRole('button', {
    name: '查看输出 web-01',
  })
  await waitFor(() => expect(button).toBeEnabled())
  fireEvent.click(button)
  return screen.findByRole('dialog', { name: '主机输出：web-01' })
}

describe('job cancellation notifications', () => {
  it.each([
    { language: 'zh-CN', cancel: '取消 job', confirm: '确认', denied: '无权限', close: '关闭' },
    { language: 'en', cancel: 'Cancel job', confirm: 'Confirm', denied: 'Permission denied', close: 'Close' },
  ])('exposes a denial while the $language confirmation stays open', async ({ language, cancel, confirm, denied, close }) => {
    await i18n.changeLanguage(language)
    const cancellation = vi.spyOn(api, 'cancelJob')
      .mockRejectedValue(new ApiError('error.permissionDenied'))
    try {
      window.history.replaceState({}, '', '/jobs/job-20261013-0043')
      render(<App />)
      fireEvent.click(await screen.findByRole('button', { name: cancel }))
      const dialog = await screen.findByRole('dialog', { name: cancel })
      fireEvent.click(within(dialog).getByRole('button', { name: confirm }))
      await screen.findByText(denied)
      expect(cancellation).toHaveBeenCalledExactlyOnceWith({ jobId: 'job-20261013-0043' })
      const alert = screen.getByRole('alert')
      expect(alert).toHaveTextContent(denied)
      expect(alert).toBeVisible()
      const dismiss = within(alert).getByRole('button', { name: close })
      dismiss.focus()
      expect(dismiss).toHaveFocus()
      fireEvent.click(dismiss, { detail: 0 })
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
      expect(dialog).toBeInTheDocument()
      expect(within(dialog).getByRole('button', { name: confirm })).toBeEnabled()
      expect((await api.getJob({ jobId: 'job-20261013-0043' })).job.status).toBe('JOB_STATUS_RUNNING')
    } finally {
      cancellation.mockRestore()
    }
  })
})

describe('job output page limits', () => {
  it.each([
    { defaultOutputPageBytes: 16384, maxOutputPageBytes: 24576, expected: 16384 },
    { defaultOutputPageBytes: 8192, maxOutputPageBytes: 12288, expected: 8192 },
    { defaultOutputPageBytes: 32768, maxOutputPageBytes: 24576, expected: 24576 },
  ])(
    'uses system limits $defaultOutputPageBytes / $maxOutputPageBytes',
    async ({ defaultOutputPageBytes, maxOutputPageBytes, expected }) => {
      const status = await api.getSystemStatus()
      const system = vi.spyOn(api, 'getSystemStatus').mockResolvedValue({
        ...status,
        limits: { ...status.limits, defaultOutputPageBytes, maxOutputPageBytes },
      })
      const output = vi.spyOn(api, 'getJobOutput')
      try {
        window.history.replaceState({}, '', '/')
        render(<App />)
        // Prime the same system-status cache used by Overview and System.
        await screen.findByText('在线主机')
        fireEvent.click(
          within(screen.getByRole('navigation')).getByRole('link', {
            name: 'Job',
          }),
        )
        fireEvent.click(
          await screen.findByRole('link', { name: 'job-20261013-0042' }),
        )
        await openOutput()
        await waitFor(() => expect(output).toHaveBeenCalledTimes(2))
        for (const [request] of output.mock.calls) {
          expect(request.limitBytes).toBe(expected)
          expect(request.limitBytes).toBeLessThanOrEqual(maxOutputPageBytes)
        }
      } finally {
        system.mockRestore()
        output.mockRestore()
      }
    },
  )

  it.each(['pending', 'permission denied'])(
    'omits limitBytes while system information is %s',
    async (state) => {
      const system = vi.spyOn(api, 'getSystemStatus')
      if (state === 'pending')
        system.mockImplementation(() => new Promise(() => {}))
      else
        system.mockRejectedValue(new ApiError('error.permissionDenied'))
      const output = vi.spyOn(api, 'getJobOutput')
      try {
        window.history.replaceState({}, '', '/jobs/job-20261013-0042')
        render(<App />)
        await openOutput()
        await waitFor(() => expect(output).toHaveBeenCalledTimes(2))
        for (const [request] of output.mock.calls)
          expect(request).not.toHaveProperty('limitBytes')
      } finally {
        system.mockRestore()
        output.mockRestore()
      }
    },
  )
})
