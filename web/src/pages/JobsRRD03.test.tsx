import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

const JOB = 'job-20261013-0043'
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

it('RR-d-03: stored multi-page output is not polled while the dialog is open', async () => {
  const tasks = await api.listTasks({ jobId: JOB })
  const listTasks = vi.spyOn(api, 'listTasks').mockResolvedValue({
    ...tasks,
    tasks: tasks.tasks.map((task) => ({
      ...task,
      result: {
        ...task.result,
        status: 'TASK_STATUS_SUCCEEDED' as const,
        exitCode: 0,
      },
      outputStored: true,
    })),
  })
  const base = await api.getJob({ jobId: JOB })
  const getJob = vi.spyOn(api, 'getJob').mockResolvedValue({
    job: { ...base.job, status: 'JOB_STATUS_SUCCEEDED' as const },
  })
  const output = vi.spyOn(api, 'getJobOutput').mockImplementation(
    async () =>
      ({
        data: btoa('page-1'),
        nextOffset: '6',
        eof: false,
        truncated: false,
        scanLimitReached: false,
        outputStored: true,
        outputTrust: 'OUTPUT_TRUST_UNTRUSTED',
      }) as never,
  )
  try {
    window.history.replaceState({}, '', `/jobs/${JOB}`)
    render(<App />)
    const button = (
      await screen.findAllByRole('button', { name: /查看输出/ }, { timeout: 5000 })
    )[0]
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)
    // Wait for the page-size limits to load so the query key is stable.
    await waitFor(() =>
      expect(
        output.mock.calls.some(([request]) => request.limitBytes !== undefined),
      ).toBe(true),
    )
    await sleep(300)
    const first = output.mock.calls.length
    await sleep(4500)
    expect(output.mock.calls.length).toBe(first)
  } finally {
    listTasks.mockRestore()
    getJob.mockRestore()
    output.mockRestore()
  }
}, 15000)
