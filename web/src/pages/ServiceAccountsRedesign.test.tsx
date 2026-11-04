import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

async function openAccounts() {
  window.history.replaceState({}, '', '/service-accounts')
  render(<App />)
  await screen.findByRole('heading', { name: '服务账号', level: 1 }, { timeout: 5000 })
  return screen.findByRole('button', { name: '管理 agent-readonly' })
}

describe('service account cards', () => {
  it('marks accounts with a running job as calling now', async () => {
    const listJobs = vi.spyOn(api, 'listJobs')
    try {
      const readonly = await openAccounts()
      expect(await within(readonly).findByText('正在调用')).toBeInTheDocument()
      const publisher = screen.getByRole('button', { name: '管理 catalog-publisher' })
      expect(within(publisher).queryByText('正在调用')).not.toBeInTheDocument()
      expect(listJobs).toHaveBeenCalledWith({
        statuses: ['JOB_STATUS_RUNNING'],
        subjectId: 'sa-01',
        page: { pageSize: 1 },
      })
    } finally {
      listJobs.mockRestore()
    }
  })
  it('creates an account with the roles picked as toggles', async () => {
    const create = vi.spyOn(api, 'createServiceAccount')
    try {
      await openAccounts()
      fireEvent.click(screen.getByRole('button', { name: '创建服务账号' }))
      const panel = screen
        .getByRole('heading', { name: '创建服务账号' })
        .closest('section')!
      const roles = within(panel).getByRole('group', { name: '角色' })
      const auditor = await within(roles).findByRole('button', { name: 'auditor' })
      expect(auditor).toHaveAttribute('aria-pressed', 'true')
      fireEvent.click(auditor)
      fireEvent.change(within(panel).getByLabelText('名称'), {
        target: { value: 'agent-ops' },
      })
      await within(panel).findByRole('option', { name: 'console-user' })
      fireEvent.change(within(panel).getByLabelText('负责人'), {
        target: { value: 'user-01' },
      })
      fireEvent.click(within(panel).getByRole('button', { name: '创建服务账号' }))
      expect(await within(panel).findByText('请至少选择一个角色')).toBeInTheDocument()
      expect(create).not.toHaveBeenCalled()
      fireEvent.click(within(roles).getByRole('button', { name: 'operator' }))
      fireEvent.click(within(panel).getByRole('button', { name: '创建服务账号' }))
      await waitFor(() =>
        expect(create).toHaveBeenCalledWith({
          name: 'agent-ops',
          ownerUserId: 'user-01',
          description: '',
          roles: ['operator'],
          teams: [],
        }),
      )
    } finally {
      create.mockRestore()
    }
  })
})

describe('service account panel', () => {
  it('shows the MCP config for this gateway and closes on Escape', async () => {
    const card = await openAccounts()
    card.focus()
    fireEvent.click(card)
    const panel = await screen.findByRole('complementary', { name: 'agent-readonly' })
    expect(
      within(panel).getByText(new RegExp(`${window.location.origin}/mcp`)),
    ).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() =>
      expect(
        screen.queryByRole('complementary', { name: 'agent-readonly' }),
      ).not.toBeInTheDocument(),
    )
    expect(document.activeElement).toBe(card)
  })
  it('shows the new token once with an export line', async () => {
    fireEvent.click(await openAccounts())
    fireEvent.click(screen.getByRole('button', { name: '创建 token' }))
    const dialog = await screen.findByRole('dialog', { name: '请保存 token' })
    const secret = within(dialog).getByText(/^aops_[a-f0-9]{64}$/).textContent
    expect(
      within(dialog).getByText(`export ALLOWOPS_MCP_TOKEN='${secret}'`),
    ).toBeInTheDocument()
    // Escape closes the dialog first; the panel stays open.
    fireEvent.keyDown(dialog, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.queryByText(/aops_[a-f0-9]{64}/)).not.toBeInTheDocument()
    expect(
      screen.getByRole('complementary', { name: 'agent-readonly' }),
    ).toBeInTheDocument()
  })
})
