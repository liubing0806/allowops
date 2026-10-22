import { render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

describe('D05 running job auto refresh', () => {
  it(
    'updates a running job to succeeded without a page reload',
    async () => {
      const base = await api.getJob({ jobId: 'job-20261013-0043' })
      let calls = 0
      const getJob = vi.spyOn(api, 'getJob').mockImplementation(async () => {
        calls += 1
        if (calls === 1) {
          return {
            job: { ...base.job, status: 'JOB_STATUS_RUNNING' as const },
          }
        }
        return {
          job: {
            ...base.job,
            status: 'JOB_STATUS_SUCCEEDED' as const,
            finishedAt: new Date().toISOString(),
          },
        }
      })
      try {
        window.history.replaceState({}, '', '/jobs/job-20261013-0043')
        render(<App />)
        expect(
          await screen.findAllByText('运行中', {}, { timeout: 5000 }),
        ).not.toHaveLength(0)
        expect(await screen.findByText('取消 job')).toBeInTheDocument()
        // Polling must pick up the backend transition on its own.
        expect(
          await screen.findByText('成功', {}, { timeout: 8000 }),
        ).toBeInTheDocument()
        expect(calls).toBeGreaterThan(1)
      } finally {
        getJob.mockRestore()
      }
    },
    15000,
  )

  it(
    'updates running tasks and pending output persistence without a reload',
    async () => {
      const baseTasks = await api.listTasks({ jobId: 'job-20261013-0043' })
      let calls = 0
      const listTasks = vi
        .spyOn(api, 'listTasks')
        .mockImplementation(async () => {
          calls += 1
          if (calls === 1) return baseTasks
          return {
            tasks: baseTasks.tasks.map((task) => ({
              ...task,
              result: {
                ...task.result,
                status: 'TASK_STATUS_SUCCEEDED' as const,
                exitCode: 0,
              },
              outputStored: true,
            })),
            page: baseTasks.page,
          }
        })
      try {
        window.history.replaceState({}, '', '/jobs/job-20261013-0043')
        render(<App />)
        expect(
          await screen.findAllByText('运行中', {}, { timeout: 5000 }),
        ).not.toHaveLength(0)
        // Initially the running task shows output not yet persisted.
        await screen.findByRole('heading', { name: '主机执行结果' })
        expect(await screen.findAllByText('否')).toHaveLength(2)
        // Polling must refresh tasks and persisted output state.
        await waitFor(
          () => expect(screen.queryAllByText('否')).toHaveLength(0),
          { timeout: 8000 },
        )
        expect(await screen.findAllByText('是')).toHaveLength(2)
        expect(calls).toBeGreaterThan(1)
      } finally {
        listTasks.mockRestore()
      }
    },
    15000,
  )
})
