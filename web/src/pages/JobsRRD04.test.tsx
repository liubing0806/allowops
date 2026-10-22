import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api, ApiError } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

const JOB = 'job-20261013-0043'
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

type Output = Awaited<ReturnType<typeof api.getJobOutput>>

async function finishedTasks(stored: boolean) {
  const base = await api.listTasks({ jobId: JOB })
  return {
    ...base,
    tasks: base.tasks.map((task) => ({
      ...task,
      result: {
        ...task.result,
        status: 'TASK_STATUS_SUCCEEDED' as const,
        exitCode: 0,
      },
      outputStored: stored,
    })),
  }
}

describe('RR-d-04 task list polls until output is stored', () => {
  it('shows the stored flag after the task became terminal first', async () => {
    const base = await api.listTasks({ jobId: JOB })
    const unstored = await finishedTasks(false)
    const stored = await finishedTasks(true)
    let calls = 0
    const listTasks = vi
      .spyOn(api, 'listTasks')
      .mockImplementation(async () => {
        calls += 1
        if (calls === 1) return base
        if (calls === 2) return unstored
        return stored
      })
    try {
      window.history.replaceState({}, '', `/jobs/${JOB}`)
      render(<App />)
      await screen.findByRole(
        'heading',
        { name: '主机执行结果' },
        { timeout: 5000 },
      )
      expect(await screen.findAllByText('否')).not.toHaveLength(0)
      await waitFor(() => expect(screen.queryAllByText('否')).toHaveLength(0), {
        timeout: 9000,
      })
      expect(screen.getAllByText('是').length).toBeGreaterThan(0)
    } finally {
      listTasks.mockRestore()
    }
  }, 20000)

  it('stops polling 30 s after the last data change', async () => {
    const unstored = await finishedTasks(false)
    let calls = 0
    const listTasks = vi
      .spyOn(api, 'listTasks')
      .mockImplementation(async () => {
        calls += 1
        return unstored
      })
    const realNow = Date.now.bind(Date)
    let skew = 0
    const now = vi.spyOn(Date, 'now').mockImplementation(() => realNow() + skew)
    try {
      window.history.replaceState({}, '', `/jobs/${JOB}`)
      render(<App />)
      await screen.findByRole(
        'heading',
        { name: '主机执行结果' },
        { timeout: 5000 },
      )
      await waitFor(() => expect(calls).toBeGreaterThanOrEqual(2), {
        timeout: 5000,
      })
      skew = 31000
      await waitFor(() => expect(calls).toBeGreaterThanOrEqual(3), {
        timeout: 5000,
      })
      const settled = calls
      await sleep(4500)
      expect(calls).toBe(settled)
    } finally {
      now.mockRestore()
      listTasks.mockRestore()
    }
  }, 25000)
})

describe('RR-d-04 output retries while storage is pending', () => {
  async function openOutput() {
    const tasks = await finishedTasks(false)
    const listTasks = vi.spyOn(api, 'listTasks').mockResolvedValue(tasks)
    window.history.replaceState({}, '', `/jobs/${JOB}`)
    render(<App />)
    const button = (
      await screen.findAllByRole(
        'button',
        { name: /查看输出/ },
        { timeout: 5000 },
      )
    )[0]
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)
    return listTasks
  }
  // The first requests are sent before the page-size limit is known. Only the
  // requests that carry the limit are scripted.
  const sized = (request: { limitBytes?: number }) =>
    request.limitBytes !== undefined

  it('retries OUTPUT_PENDING after retryAfter and then shows the output', async () => {
    let attempts = 0
    const out = vi
      .spyOn(api, 'getJobOutput')
      .mockImplementation(async (request) => {
        if (!sized(request)) throw new ApiError('error.unavailable', 14)
        attempts += 1
        if (attempts <= 2) {
          throw Object.assign(new ApiError('error.unavailable', 14), {
            reason: 'OUTPUT_PENDING',
            retryAfterMs: 200,
          })
        }
        return {
          data: btoa('stored-output-text'),
          nextOffset: '18',
          eof: true,
          truncated: false,
          scanLimitReached: false,
          outputStored: true,
          outputTrust: 'OUTPUT_TRUST_UNTRUSTED',
        } as unknown as Output
      })
    const listTasks = await openOutput()
    try {
      expect(
        (
          await screen.findAllByText(
            'stored-output-text',
            {},
            { timeout: 5000 },
          )
        ).length,
      ).toBeGreaterThan(0)
    } finally {
      out.mockRestore()
      listTasks.mockRestore()
    }
  }, 15000)

  it('RR-d-04a treats a zero retryAfter as missing and keeps retrying', async () => {
    let attempts = 0
    const out = vi
      .spyOn(api, 'getJobOutput')
      .mockImplementation(async (request) => {
        if (!sized(request)) throw new ApiError('error.unavailable', 14)
        attempts += 1
        if (attempts <= 2) {
          throw Object.assign(new ApiError('error.unavailable', 14), {
            reason: 'OUTPUT_PENDING',
            retryAfterMs: 0,
          })
        }
        return {
          data: btoa('stored-output-text'),
          nextOffset: '18',
          eof: true,
          truncated: false,
          scanLimitReached: false,
          outputStored: true,
          outputTrust: 'OUTPUT_TRUST_UNTRUSTED',
        } as unknown as Output
      })
    const listTasks = await openOutput()
    try {
      expect(
        (
          await screen.findAllByText(
            'stored-output-text',
            {},
            { timeout: 5000 },
          )
        ).length,
      ).toBeGreaterThan(0)
    } finally {
      out.mockRestore()
      listTasks.mockRestore()
    }
  }, 15000)

  it('waits one second when OUTPUT_PENDING has no retryAfter', async () => {
    const times: number[] = []
    const out = vi
      .spyOn(api, 'getJobOutput')
      .mockImplementation(async (request) => {
        if (!sized(request)) throw new ApiError('error.unavailable', 14)
        if (request.stream === 'OUTPUT_STREAM_STDOUT') times.push(Date.now())
        if (request.stream === 'OUTPUT_STREAM_STDOUT' && times.length === 1) {
          throw Object.assign(new ApiError('error.unavailable', 14), {
            reason: 'OUTPUT_PENDING',
          })
        }
        return {
          data: btoa('stored-output-text'),
          nextOffset: '18',
          eof: true,
          truncated: false,
          scanLimitReached: false,
          outputStored: true,
          outputTrust: 'OUTPUT_TRUST_UNTRUSTED',
        } as unknown as Output
      })
    const listTasks = await openOutput()
    try {
      await waitFor(() => expect(times).toHaveLength(2), { timeout: 5000 })
      expect(times[1] - times[0]).toBeGreaterThanOrEqual(900)
    } finally {
      out.mockRestore()
      listTasks.mockRestore()
    }
  }, 15000)

  it('stops retrying on OUTPUT_UNAVAILABLE', async () => {
    let attempts = 0
    const out = vi
      .spyOn(api, 'getJobOutput')
      .mockImplementation(async (request) => {
        if (!sized(request)) throw new ApiError('error.unavailable', 14)
        attempts += 1
        throw Object.assign(new ApiError('error.notFound', 5), {
          reason: 'OUTPUT_UNAVAILABLE',
        })
      })
    const listTasks = await openOutput()
    try {
      await waitFor(() => expect(attempts).toBeGreaterThan(0))
      await sleep(3500)
      expect(attempts).toBe(2)
    } finally {
      out.mockRestore()
      listTasks.mockRestore()
    }
  }, 15000)
})
