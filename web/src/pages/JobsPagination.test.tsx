import { fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api, type Job } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})
afterEach(() => vi.restoreAllMocks())

const total = 25
const name = (index: number) => `job-page-${String(index + 1).padStart(2, '0')}`

// The gateway returns one page per request and a token for the next one.
async function serveJobs() {
  const { job } = await api.getJob({ jobId: 'job-20261013-0042' })
  const all: Job[] = Array.from({ length: total }, (_, index) => ({
    ...job,
    jobId: name(index),
    status: 'JOB_STATUS_RUNNING',
  }))
  return vi.spyOn(api, 'listJobs').mockImplementation(async (input) => {
    const size = input?.page?.pageSize || 50
    const start = Number(input?.page?.pageToken || 0)
    const end = Math.min(start + size, total)
    return {
      jobs: all.slice(start, end),
      page: { nextPageToken: end < total ? String(end) : '' },
    }
  })
}

async function ids() {
  const table = await screen.findByRole('table')
  await screen.findAllByRole('link', { name: /^job-page-/ })
  return within(table)
    .getAllByRole('link')
    .map((link) => link.textContent)
}

function open() {
  window.history.replaceState({}, '', '/jobs')
  render(<App />)
}

describe('jobs list server pagination', () => {
  it('requests one page of ten jobs and does not read the rest', async () => {
    const list = await serveJobs()
    open()
    expect(await ids()).toEqual(Array.from({ length: 10 }, (_, i) => name(i)))
    expect(list).toHaveBeenCalledTimes(1)
    expect(list.mock.calls[0][0]?.page?.pageSize).toBe(10)
    expect(list.mock.calls[0][0]?.page?.pageToken || '').toBe('')
    expect(screen.getByRole('button', { name: '上一页' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '下一页' })).toBeEnabled()
  })

  it('moves between pages with the next page token', async () => {
    const list = await serveJobs()
    open()
    await ids()
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('第 2 页')).toBeInTheDocument()
    expect(await ids()).toEqual(
      Array.from({ length: 10 }, (_, i) => name(10 + i)),
    )
    expect(list.mock.calls.at(-1)?.[0]?.page?.pageToken).toBe('10')
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('第 3 页')).toBeInTheDocument()
    expect(await ids()).toEqual(
      Array.from({ length: 5 }, (_, i) => name(20 + i)),
    )
    // The last page has no token, so there is no further page.
    expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '上一页' }))
    expect(await screen.findByText('第 2 页')).toBeInTheDocument()
    expect(await ids()).toEqual(
      Array.from({ length: 10 }, (_, i) => name(10 + i)),
    )
  })

  it('returns to the first page when a filter changes', async () => {
    const list = await serveJobs()
    open()
    await ids()
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('第 2 页')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Job 状态'), {
      target: { value: 'JOB_STATUS_RUNNING' },
    })
    expect(await screen.findByText('第 1 页')).toBeInTheDocument()
    expect(await ids()).toEqual(Array.from({ length: 10 }, (_, i) => name(i)))
    const last = list.mock.calls.at(-1)?.[0]
    expect(last?.statuses).toEqual(['JOB_STATUS_RUNNING'])
    expect(last?.page?.pageToken || '').toBe('')
  })

  it('stays on the first page when a filter is changed and restored', async () => {
    const list = await serveJobs()
    open()
    await ids()
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('第 2 页')).toBeInTheDocument()
    const status = screen.getByLabelText('Job 状态')
    fireEvent.change(status, { target: { value: 'JOB_STATUS_RUNNING' } })
    expect(await screen.findByText('第 1 页')).toBeInTheDocument()
    fireEvent.change(status, { target: { value: '' } })
    expect(await screen.findByText('第 1 页')).toBeInTheDocument()
    expect(await ids()).toEqual(Array.from({ length: 10 }, (_, i) => name(i)))
    expect(list.mock.calls.at(-1)?.[0]?.page?.pageToken || '').toBe('')
  })

  // Sorting one server page would misorder the list across pages.
  it('does not sort a server page in the browser', async () => {
    await serveJobs()
    open()
    await ids()
    expect(
      screen.queryAllByRole('button', { name: /^按 .* 排序$/ }),
    ).toHaveLength(0)
  })
})
