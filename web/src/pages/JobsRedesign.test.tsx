import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})
afterEach(() => vi.restoreAllMocks())

const FINISHED = 'job-20261013-0042'
const RUNNING = 'job-20261013-0043'

function open(path: string) {
  window.history.replaceState({}, '', path)
  render(<App />)
}

async function openOutput(host = 'web-01') {
  const button = await screen.findByRole('button', { name: `查看输出 ${host}` })
  await waitFor(() => expect(button).toBeEnabled())
  fireEvent.click(button)
  return screen.findByRole('region', { name: `主机输出：${host}` })
}

describe('job list and detail side by side', () => {
  it('keeps the list filter while a job is opened', async () => {
    open('/jobs')
    expect(await screen.findByText('从列表中选择一个 job 查看详情')).toBeInTheDocument()
    const status = screen.getByRole('group', { name: 'Job 状态' })
    fireEvent.click(within(status).getByRole('button', { name: '运行中' }))
    await waitFor(() =>
      expect(screen.queryByRole('link', { name: FINISHED })).not.toBeInTheDocument(),
    )
    fireEvent.click(screen.getByRole('link', { name: RUNNING }))
    expect(
      await screen.findByRole('heading', { name: RUNNING, level: 2 }),
    ).toBeInTheDocument()
    expect(screen.getByRole('link', { name: RUNNING })).toHaveAttribute(
      'aria-current',
      'page',
    )
    expect(within(status).getByRole('button', { name: '运行中' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )
    expect(screen.queryByRole('link', { name: FINISHED })).not.toBeInTheDocument()
  })

  it('offers cancel only for an active job', async () => {
    open(`/jobs/${FINISHED}`)
    expect(
      await screen.findByRole('heading', { name: FINISHED, level: 2 }),
    ).toBeInTheDocument()
    await screen.findByRole('heading', { name: '主机执行结果' })
    expect(screen.queryByRole('button', { name: '取消 job' })).not.toBeInTheDocument()
  })

  it('explains a denied job and shows no task table', async () => {
    const { job } = await api.getJob({ jobId: FINISHED })
    vi.spyOn(api, 'getJob').mockResolvedValue({
      job: {
        ...job,
        status: 'JOB_STATUS_DENIED',
        totalTasks: '0',
        counts: [],
      },
    })
    open(`/jobs/${FINISHED}`)
    expect(
      await screen.findByText(
        '策略拒绝，没有下发到任何主机。匹配的拒绝规则记录在审计事件中。',
      ),
    ).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '主机执行结果' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '取消 job' })).not.toBeInTheDocument()
  })

  it('shows no output button for a host that never ran the task', async () => {
    open(`/jobs/${FINISHED}`)
    await screen.findByRole('button', { name: '查看输出 web-01' })
    // web-02 was offline.
    expect(
      screen.queryByRole('button', { name: '查看输出 web-02' }),
    ).not.toBeInTheDocument()
  })
})

describe('job output viewer', () => {
  it('switches between stdout and stderr and keeps the untrusted warning', async () => {
    open(`/jobs/${FINISHED}`)
    const viewer = await openOutput()
    expect(within(viewer).getByText('主机输出是不可信数据')).toBeInTheDocument()
    expect(
      await within(viewer).findByText('service=api status=active'),
    ).toBeVisible()
    const streams = within(viewer).getByRole('group', { name: '输出流' })
    fireEvent.click(within(streams).getByRole('button', { name: '标准错误' }))
    expect(within(viewer).getByText('service=api status=active')).not.toBeVisible()
    expect(within(streams).getByRole('button', { name: '标准错误' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )
  })

  it('omits step_index for a single-command action', async () => {
    const output = vi.spyOn(api, 'getJobOutput')
    open(`/jobs/${FINISHED}`)
    await openOutput()
    await waitFor(() => expect(output).toHaveBeenCalled())
    for (const [request] of output.mock.calls)
      expect(request).not.toHaveProperty('stepIndex')
    expect(screen.queryByRole('group', { name: '步骤' })).not.toBeInTheDocument()
  })

  it('reads each step of a composite action with step_index', async () => {
    const base = await api.listTasks({ jobId: FINISHED })
    vi.spyOn(api, 'listTasks').mockResolvedValue({
      ...base,
      tasks: base.tasks.map((task) =>
        task.hostname === 'web-01' ? { ...task, stepCount: 2 } : task,
      ),
    })
    const original = api.getJobOutput
    const output = vi
      .spyOn(api, 'getJobOutput')
      .mockImplementation(async (request) => ({
        ...(await original(request)),
        data: btoa(`step-${request.stepIndex}`),
      }))
    open(`/jobs/${FINISHED}`)
    const viewer = await openOutput()
    expect((await within(viewer).findAllByText('step-0')).length).toBeGreaterThan(0)
    const steps = within(viewer).getByRole('group', { name: '步骤' })
    fireEvent.click(within(steps).getByRole('button', { name: '步骤 2' }))
    expect((await within(viewer).findAllByText('step-1')).length).toBeGreaterThan(0)
    const indexes = output.mock.calls.map(([request]) => request.stepIndex)
    expect(indexes).toContain(0)
    expect(indexes).toContain(1)
    expect(indexes).not.toContain(undefined)
  })

  it('closes the output viewer when another job is opened', async () => {
    open(`/jobs/${FINISHED}`)
    await openOutput()
    fireEvent.click(screen.getByRole('link', { name: RUNNING }))
    expect(
      await screen.findByRole('heading', { name: RUNNING, level: 2 }),
    ).toBeInTheDocument()
    expect(
      screen.queryByRole('region', { name: /^主机输出/ }),
    ).not.toBeInTheDocument()
  })
})
