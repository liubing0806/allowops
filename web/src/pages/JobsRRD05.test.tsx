import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api, ApiError } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

const JOB = 'job-20261013-0043'
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

// Connect codes: Unauthenticated 16, PermissionDenied 7, NotFound 5, Unavailable 14.
describe('RR-d-05 polling stops on authorization and not-found errors', () => {
  it.each([
    ['error.unauthenticated', 16],
    ['error.permissionDenied', 7],
    ['error.notFound', 5],
  ])(
    'getJob stops polling after %s',
    async (key, code) => {
      const base = await api.getJob({ jobId: JOB })
      let calls = 0
      const getJob = vi.spyOn(api, 'getJob').mockImplementation(async () => {
        calls += 1
        if (calls === 1) {
          return { job: { ...base.job, status: 'JOB_STATUS_RUNNING' as const } }
        }
        throw new ApiError(key, code)
      })
      try {
        window.history.replaceState({}, '', `/jobs/${JOB}`)
        render(<App />)
        await screen.findByText('取消 job', {}, { timeout: 5000 })
        await sleep(4500)
        expect(calls).toBe(2)
      } finally {
        getJob.mockRestore()
      }
    },
    15000,
  )

  it.each([
    ['error.unauthenticated', 16],
    ['error.permissionDenied', 7],
    ['error.notFound', 5],
  ])(
    'listTasks stops polling after %s',
    async (key, code) => {
      const base = await api.listTasks({ jobId: JOB })
      let calls = 0
      const listTasks = vi
        .spyOn(api, 'listTasks')
        .mockImplementation(async () => {
          calls += 1
          if (calls === 1) return base
          throw new ApiError(key, code)
        })
      try {
        window.history.replaceState({}, '', `/jobs/${JOB}`)
        render(<App />)
        await screen.findByRole(
          'heading',
          { name: '主机执行结果' },
          { timeout: 5000 },
        )
        await sleep(4500)
        expect(calls).toBe(2)
      } finally {
        listTasks.mockRestore()
      }
    },
    15000,
  )

  it('getJob keeps polling after a transient unavailable error', async () => {
    const base = await api.getJob({ jobId: JOB })
    let calls = 0
    const getJob = vi.spyOn(api, 'getJob').mockImplementation(async () => {
      calls += 1
      if (calls === 1) {
        return { job: { ...base.job, status: 'JOB_STATUS_RUNNING' as const } }
      }
      throw new ApiError('error.unavailable', 14)
    })
    try {
      window.history.replaceState({}, '', `/jobs/${JOB}`)
      render(<App />)
      await screen.findByText('取消 job', {}, { timeout: 5000 })
      await sleep(4500)
      expect(calls).toBeGreaterThanOrEqual(3)
    } finally {
      getJob.mockRestore()
    }
  }, 15000)
})
