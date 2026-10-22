import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { act } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

const JOB = 'job-20261013-0043'
const OTHER_JOB = 'job-20261013-0042'

type Output = Awaited<ReturnType<typeof api.getJobOutput>>

describe('output dialog state belongs to one job', () => {
  it('starts the next job at offset 0 and drops the previous job text', async () => {
    const base = await api.listTasks({ jobId: JOB })
    vi.spyOn(api, 'listTasks').mockImplementation(async ({ jobId }) => ({
      ...base,
      tasks: base.tasks.map((task) => ({
        ...task,
        jobId,
        result: {
          ...task.result,
          status: 'TASK_STATUS_SUCCEEDED' as const,
          exitCode: 0,
        },
        outputStored: true,
      })),
    }))
    const calls: { jobId: string; offset: string }[] = []
    vi.spyOn(api, 'getJobOutput').mockImplementation(async (request) => {
      // Requests sent before the page-size limit is known are not counted.
      if (request.limitBytes === undefined) throw new Error('unsized')
      if (request.stream === 'OUTPUT_STREAM_STDOUT')
        calls.push({ jobId: request.jobId, offset: request.offset })
      const first = request.offset === '0'
      return {
        data: btoa(`${request.jobId}-${first ? 'first' : 'second'}`),
        nextOffset: first ? '100' : '200',
        eof: !first,
        truncated: false,
        scanLimitReached: false,
        outputStored: true,
        outputTrust: 'OUTPUT_TRUST_UNTRUSTED',
      } as unknown as Output
    })
    window.history.replaceState({}, '', `/jobs/${JOB}`)
    render(<App />)
    const open = async () => {
      const button = (
        await screen.findAllByRole(
          'button',
          { name: /查看输出/ },
          { timeout: 5000 },
        )
      )[0]
      await waitFor(() => expect(button).toBeEnabled())
      fireEvent.click(button)
    }
    await open()
    await screen.findAllByText(`${JOB}-first`, {}, { timeout: 5000 })
    fireEvent.click(screen.getAllByRole('button', { name: '读取下一页输出' })[0])
    await screen.findAllByText(`${JOB}-first${JOB}-second`)

    // Same route element, new :jobId parameter.
    await act(async () => {
      window.history.pushState({}, '', `/jobs/${OTHER_JOB}`)
      window.dispatchEvent(new PopStateEvent('popstate'))
    })
    await waitFor(() =>
      expect(window.location.pathname).toBe(`/jobs/${OTHER_JOB}`),
    )
    // Either the dialog of the first job is still open, or the table of the new
    // job is shown and its output is opened by hand.
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog') !== null ||
          screen.queryAllByRole('button', { name: /查看输出/ }).length > 0,
      ).toBe(true),
    )
    if (!screen.queryByRole('dialog')) await open()
    await waitFor(() =>
      expect(calls.some((call) => call.jobId === OTHER_JOB)).toBe(true),
    )
    expect(calls.filter((call) => call.jobId === OTHER_JOB)[0].offset).toBe('0')
    await screen.findAllByText(`${OTHER_JOB}-first`)
    expect(screen.queryAllByText(new RegExp(JOB))).toHaveLength(0)
  }, 30000)
})
