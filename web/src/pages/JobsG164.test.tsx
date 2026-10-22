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
type Tasks = Awaited<ReturnType<typeof api.listTasks>>

// Terminal tasks on several hosts. storedHosts lists the hosts whose output is
// already stored.
async function finishedTasks(storedHosts: string[]): Promise<Tasks> {
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
      outputStored: storedHosts.includes(task.hostname),
    })),
  }
}

// The 30 s window is measured with Date.now. Tests move the clock instead of
// waiting. The 2 s poll timers stay real.
function skewedClock() {
  const realNow = Date.now.bind(Date)
  const clock = { skew: 0 }
  const spy = vi
    .spyOn(Date, 'now')
    .mockImplementation(() => realNow() + clock.skew)
  return { clock, restore: () => spy.mockRestore() }
}

describe('G164 output query polls while output is not stored', () => {
  it.each([true, false])(
    'keeps polling about every 2 s when outputStored is false and eof is %s',
    async (eof) => {
      const tasks = await finishedTasks(['web-01', 'web-02', 'web-03'])
      const listTasks = vi.spyOn(api, 'listTasks').mockResolvedValue(tasks)
      const times: number[] = []
      const out = vi
        .spyOn(api, 'getJobOutput')
        .mockImplementation(async (request) => {
          // Requests sent before the page-size limit is known are not counted.
          if (request.limitBytes === undefined) throw new Error('unsized')
          if (
            request.hostname === 'web-01' &&
            request.stream === 'OUTPUT_STREAM_STDOUT'
          )
            times.push(Date.now())
          return {
            data: btoa('partial-output'),
            nextOffset: '14',
            eof,
            truncated: false,
            scanLimitReached: false,
            outputStored: false,
            outputTrust: 'OUTPUT_TRUST_UNTRUSTED',
          } as unknown as Output
        })
      try {
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
        await waitFor(() => expect(times.length).toBeGreaterThanOrEqual(3), {
          timeout: 8000,
        })
        const gaps = times.slice(1, 3).map((time, i) => time - times[i])
        for (const gap of gaps) {
          expect(gap).toBeGreaterThanOrEqual(1500)
          expect(gap).toBeLessThan(3500)
        }
      } finally {
        out.mockRestore()
        listTasks.mockRestore()
      }
    },
    20000,
  )
})

describe('G164 task list 30 s window signature', () => {
  it('restarts the window when only some hosts become stored', async () => {
    const unstored = await finishedTasks([])
    const partial = await finishedTasks(['web-01'])
    expect(partial.tasks.length).toBeGreaterThan(1)
    expect(partial.tasks.some((task) => !task.outputStored)).toBe(true)
    let phase: 'unstored' | 'partial' = 'unstored'
    let calls = 0
    let partialCalls = 0
    const listTasks = vi
      .spyOn(api, 'listTasks')
      .mockImplementation(async () => {
        calls += 1
        if (phase === 'partial') {
          partialCalls += 1
          return partial
        }
        return unstored
      })
    const { clock, restore } = skewedClock()
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
      // 25 s after the first data: the window is still open.
      clock.skew = 25000
      phase = 'partial'
      // Two partial responses: the first changes the signature, the second is
      // evaluated at the shifted clock.
      await waitFor(() => expect(partialCalls).toBeGreaterThanOrEqual(2), {
        timeout: 8000,
      })
      // 31 s after the first data, 6 s after the partial change.
      clock.skew = 31000
      const before = calls
      await waitFor(() => expect(calls).toBeGreaterThanOrEqual(before + 2), {
        timeout: 8000,
      })
    } finally {
      restore()
      listTasks.mockRestore()
    }
  }, 30000)

  it('restarts the window when the same component switches job', async () => {
    const tasks = await finishedTasks([])
    const callsByJob: Record<string, number> = {}
    const listTasks = vi
      .spyOn(api, 'listTasks')
      .mockImplementation(async ({ jobId }) => {
        callsByJob[jobId] = (callsByJob[jobId] ?? 0) + 1
        return { ...tasks, tasks: tasks.tasks.map((t) => ({ ...t, jobId })) }
      })
    const { clock, restore } = skewedClock()
    try {
      window.history.replaceState({}, '', `/jobs/${JOB}`)
      render(<App />)
      await screen.findByRole(
        'heading',
        { name: '主机执行结果' },
        { timeout: 5000 },
      )
      await waitFor(() => expect(callsByJob[JOB]).toBeGreaterThanOrEqual(2), {
        timeout: 5000,
      })
      clock.skew = 25000
      // Same route element, new :jobId parameter.
      await act(async () => {
        window.history.pushState({}, '', `/jobs/${OTHER_JOB}`)
        window.dispatchEvent(new PopStateEvent('popstate'))
      })
      await waitFor(
        () => expect(callsByJob[OTHER_JOB]).toBeGreaterThanOrEqual(2),
        { timeout: 8000 },
      )
      // 31 s after the first job's data, 6 s after the switch.
      clock.skew = 31000
      const before = callsByJob[OTHER_JOB]
      await waitFor(
        () => expect(callsByJob[OTHER_JOB]).toBeGreaterThanOrEqual(before + 2),
        { timeout: 8000 },
      )
    } finally {
      restore()
      listTasks.mockRestore()
    }
  }, 30000)
})
