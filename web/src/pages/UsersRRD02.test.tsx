import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import App from '@/App'
import { api, ApiError } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => { await i18n.changeLanguage('zh-CN') })

it('RR-d-02: display matches submitted provider after login methods recover from an error', async () => {
  const methods = vi.spyOn(api, 'getLoginMethods')
    .mockRejectedValueOnce(new ApiError('error.unavailable'))
    .mockResolvedValue({ methods: [
      { providerId: 'demo', displayName: 'Demo', kind: 'ldap' },
      { providerId: 'oidc-beta', displayName: 'Beta', kind: 'oidc' },
    ] })
  const mappings = vi.spyOn(api, 'getRoleMappings').mockResolvedValue({
    revision: '1', mappings: [{ providerId: 'oidc-beta', group: 'beta-team', roles: ['viewer'] }],
  })
  const saved = vi.spyOn(api, 'saveRoleMappings').mockResolvedValue({ revision: '1' })
  try {
    window.history.replaceState({}, '', '/users')
    render(<App />)
    await screen.findByRole('heading', { name: '组到角色的映射' }, { timeout: 5000 })
    const select = await screen.findByLabelText('身份源') as HTMLSelectElement
    expect(select).toHaveValue('oidc-beta')
    fireEvent.click(screen.getByRole('button', { name: '保存映射' }))
    await waitFor(() => expect(saved).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(methods).toHaveBeenCalledTimes(2))
    await screen.findByRole('option', { name: 'Beta' })
    const sel2 = screen.getByLabelText('身份源') as HTMLSelectElement
    fireEvent.click(screen.getByRole('button', { name: '保存映射' }))
    await waitFor(() => expect(saved).toHaveBeenCalledTimes(2))
    expect(sel2.value).toBe(saved.mock.calls[1][0].mappings[0].providerId)
  } finally { methods.mockRestore(); mappings.mockRestore(); saved.mockRestore() }
})
