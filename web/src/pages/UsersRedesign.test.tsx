import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

async function openUsers() {
  window.history.replaceState({}, '', '/users')
  render(<App />)
  await screen.findByRole('heading', { name: '用户与角色', level: 1 }, { timeout: 5000 })
  await screen.findByRole('button', { name: '分配角色 audit-user' })
}

describe('users redesign', () => {
  it('shows role cards with member counts', async () => {
    await openUsers()
    const roles = screen.getByRole('region', { name: '角色' })
    const auditor = within(roles).getByText('auditor').parentElement!
    expect(auditor).toHaveTextContent('1 人')
  })
  it('filters users by name', async () => {
    await openUsers()
    fireEvent.change(screen.getByLabelText('搜索用户'), { target: { value: 'view' } })
    expect(screen.getByRole('button', { name: '分配角色 view-user' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '分配角色 audit-user' })).not.toBeInTheDocument()
  })
  it('locks mapping-derived roles and keeps manual roles when saving', async () => {
    const setRoles = vi.spyOn(api, 'setUserRoles')
    try {
      await openUsers()
      const opener = screen.getByRole('button', { name: '分配角色 audit-user' })
      opener.focus()
      fireEvent.click(opener)
      const panel = screen.getByRole('heading', { name: '分配角色 audit-user', level: 2 }).closest('aside')!
      const auditor = within(panel).getByLabelText('auditor')
      expect(auditor).toBeDisabled()
      expect(auditor).toHaveAttribute('aria-checked', 'true')
      expect(within(panel).getByText('来自组映射')).toBeInTheDocument()
      fireEvent.click(within(panel).getByLabelText('operator'))
      expect(panel).toHaveTextContent('auditor, operator')
      fireEvent.click(within(panel).getByRole('button', { name: '保存角色' }))
      await waitFor(() =>
        expect(setRoles).toHaveBeenCalledWith({
          userId: 'user-02',
          manualRoles: ['operator'],
          expectedRevision: '1',
        }),
      )
      await waitFor(() =>
        expect(screen.queryByRole('heading', { name: '分配角色 audit-user', level: 2 })).not.toBeInTheDocument(),
      )
    } finally {
      setRoles.mockRestore()
    }
  })
  it('marks unsaved mapping changes', async () => {
    await openUsers()
    const groups = await screen.findAllByLabelText('组名')
    expect(screen.queryByText('有未保存修改')).not.toBeInTheDocument()
    fireEvent.change(groups[0], { target: { value: 'changed-group' } })
    expect(await screen.findByText('有未保存修改')).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: '删除这条映射' })[0])
    expect(screen.getAllByLabelText('组名')).toHaveLength(groups.length - 1)
  })
})
