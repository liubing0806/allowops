import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

async function openAudit() {
  window.history.replaceState({}, '', '/audit')
  render(<App />)
  await screen.findByRole('heading', { name: '审计', level: 1 }, { timeout: 5000 })
  await screen.findByRole('button', { name: '打开审计事件 3 详情' })
}

function panel(seq: string) {
  return screen.getByRole('heading', { name: `#${seq}`, level: 2 }).closest('aside')!
}

describe('audit redesign', () => {
  it('lists the newest event first with its matched rules', async () => {
    await openAudit()
    const buttons = screen.getAllByRole('button', { name: /^打开审计事件 \d+ 详情$/ })
    expect(buttons.map((button) => button.textContent)).toEqual(['3', '2', '1'])
    expect(screen.getAllByText('readonly-all')).toHaveLength(3)
  })
  it('shows the hash chain around an event and closes on Escape', async () => {
    const events = (await api.listAuditEvents()).events
    await openAudit()
    const opener = screen.getByRole('button', { name: '打开审计事件 2 详情' })
    opener.focus()
    fireEvent.click(opener)
    const detail = panel('2')
    expect(within(detail).getByText('#1')).toBeInTheDocument()
    expect(within(detail).getByText('#3')).toBeInTheDocument()
    const current = detail.querySelector('[aria-current]')!
    expect(current).toHaveTextContent('#2')
    expect(current).toHaveTextContent(`prev ${events[0].hash}`)
    expect(current).toHaveTextContent(`hash ${events[1].hash}`)
    expect(within(detail).getByRole('link', { name: 'job-20261013-0042' })).toHaveAttribute(
      'href',
      '/jobs/job-20261013-0042',
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() =>
      expect(screen.queryByRole('heading', { name: '#2', level: 2 })).not.toBeInTheDocument(),
    )
    expect(document.activeElement).toBe(opener)
  })
  it('shows the recorded previous hash when that event is outside the results', async () => {
    const events = (await api.listAuditEvents()).events
    await openAudit()
    fireEvent.change(screen.getByLabelText('主机'), { target: { value: 'web-02' } })
    fireEvent.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: '打开审计事件 3 详情' })).not.toBeInTheDocument(),
    )
    fireEvent.click(await screen.findByRole('button', { name: '打开审计事件 2 详情' }))
    const previous = within(panel('2')).getByText('#1').closest('div')!
    expect(previous).toHaveTextContent('不在当前查询结果中')
    expect(previous).toHaveTextContent(`hash ${events[1].prevHash}`)
    expect(within(panel('2')).queryByText('#3')).not.toBeInTheDocument()
  })
  it('opens verification with the loaded range and keeps the internal-only note', async () => {
    await openAudit()
    fireEvent.click(screen.getByRole('button', { name: '校验哈希链' }))
    expect(screen.getByLabelText('起始序列号')).toHaveValue('1')
    expect(screen.getByLabelText('结束序列号')).toHaveValue('3')
    expect(screen.getByText('仅校验内部一致性，未验证外部可信锚。')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '开始校验' }))
    const region = screen.getByRole('region', { name: '校验哈希链' })
    expect(await within(region).findByText('哈希链校验通过，已校验 3 条')).toBeInTheDocument()
  })
})
