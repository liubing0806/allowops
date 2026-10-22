import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api, ApiError } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

async function openUsers() {
  window.history.replaceState({}, '', '/users')
  render(<App />)
  await screen.findByRole('heading', { level: 1 }, { timeout: 5000 })
  await screen.findByRole('heading', { name: '组到角色的映射' })
}

describe('D01 role mapping provider identity', () => {
  it('uses real providerId/displayName and preserves unknown mapping IDs', async () => {
    const methods = vi.spyOn(api, 'getLoginMethods').mockResolvedValue({
      methods: [
        { providerId: 'demo', displayName: 'Local LDAPS demo', kind: 'ldap' },
        { providerId: 'oidc-alpha', displayName: 'Alpha', kind: 'oidc' },
        { providerId: 'oidc-beta', displayName: 'Beta', kind: 'oidc' },
      ],
    })
    const mappings = vi.spyOn(api, 'getRoleMappings').mockResolvedValue({
      mappings: [
        { providerId: 'demo', group: 'demo-admins', roles: ['admin'] },
        { providerId: 'legacy-id', group: 'old-team', roles: ['viewer'] },
      ],
      revision: '1',
    })
    const saved = vi.spyOn(api, 'saveRoleMappings')
    try {
      await openUsers()
      const providerSelects = await screen.findAllByLabelText('身份源')
      expect(providerSelects).toHaveLength(2)
      // First row keeps demo.
      expect((providerSelects[0] as HTMLSelectElement).value).toBe('demo')
      // Unknown legacy ID is preserved, not coerced to a kind.
      expect((providerSelects[1] as HTMLSelectElement).value).toBe(
        'legacy-id',
      )
      for (const select of providerSelects) {
        const options = within(select as HTMLElement).getAllByRole('option')
        const values = options.map((o) => (o as HTMLOptionElement).value)
        expect(values).toEqual(
          expect.arrayContaining(['demo', 'oidc-alpha', 'oidc-beta']),
        )
        // kind must not appear as an option value.
        expect(values).not.toContain('oidc')
        expect(values).not.toContain('ldap')
      }
      // Display names come from GetLoginMethods.
      expect(
        within(providerSelects[0] as HTMLElement).getByRole('option', {
          name: 'Local LDAPS demo',
        }),
      ).toBeInTheDocument()
      expect(
        within(providerSelects[0] as HTMLElement).getByRole('option', {
          name: 'Alpha',
        }),
      ).toBeInTheDocument()
      expect(
        within(providerSelects[0] as HTMLElement).getByRole('option', {
          name: 'Beta',
        }),
      ).toBeInTheDocument()
      // Unknown ID remains selectable with its own value.
      expect(
        within(providerSelects[1] as HTMLElement).getByRole('option', {
          name: 'legacy-id（未配置）',
        }),
      ).toBeInTheDocument()
      // Saving keeps real IDs end to end (before adding an empty draft row).
      const groupInputs = await screen.findAllByLabelText('组名')
      fireEvent.change(groupInputs[0], { target: { value: 'demo-admins' } })
      fireEvent.click(screen.getByRole('button', { name: '保存映射' }))
      await waitFor(() => expect(saved).toHaveBeenCalled())
      expect(saved.mock.calls[0][0].mappings.map((m) => m.providerId)).toEqual(
        expect.arrayContaining(['demo', 'legacy-id']),
      )
      // Adding a row uses a real provider ID, not the kind placeholder.
      fireEvent.click(screen.getByRole('button', { name: '添加映射' }))
      await waitFor(async () => {
        const after = await screen.findAllByLabelText('身份源')
        expect(after).toHaveLength(3)
        expect((after[2] as HTMLSelectElement).value).toBe('demo')
        expect((after[2] as HTMLSelectElement).value).not.toBe('oidc')
      })
    } finally {
      methods.mockRestore()
      mappings.mockRestore()
      saved.mockRestore()
    }
  })
})


it('keeps the displayed and submitted non-first provider after deferred login methods resolve', async () => {
  let resolve!: (value: Awaited<ReturnType<typeof api.getLoginMethods>>) => void
  const pending = new Promise<Awaited<ReturnType<typeof api.getLoginMethods>>>((done) => {
    resolve = done
  })
  const methods = vi.spyOn(api, 'getLoginMethods').mockReturnValue(pending)
  const mappings = vi.spyOn(api, 'getRoleMappings').mockResolvedValue({
    revision: '1',
    mappings: [{ providerId: 'oidc-beta', group: 'beta-team', roles: ['viewer'] }],
  })
  const saved = vi.spyOn(api, 'saveRoleMappings').mockResolvedValue({ revision: '1' })
  try {
    await openUsers()
    await waitFor(() => expect(methods).toHaveBeenCalledTimes(1))
    await act(async () => {
      resolve({ methods: [
        { providerId: 'demo', displayName: 'Demo', kind: 'ldap' },
        { providerId: 'oidc-beta', displayName: 'Beta', kind: 'oidc' },
      ] })
      await pending
    })
    await screen.findByRole('option', { name: 'Beta' })
    const select = screen.getByLabelText('身份源')
    expect(select).toHaveValue('oidc-beta')
    fireEvent.click(screen.getByRole('button', { name: '保存映射' }))
    await waitFor(() => expect(saved).toHaveBeenCalledTimes(1))
    expect(saved.mock.calls[0][0]).toEqual({
      expectedRevision: '1',
      mappings: [{ providerId: 'oidc-beta', group: 'beta-team', roles: ['viewer'] }],
    })
    expect(select).toHaveValue(saved.mock.calls[0][0].mappings[0].providerId)
    fireEvent.change(select, { target: { value: 'demo' } })
    fireEvent.click(screen.getByRole('button', { name: '保存映射' }))
    await waitFor(() => expect(saved).toHaveBeenCalledTimes(2))
    expect(select).toHaveValue('demo')
    expect(saved.mock.calls[1][0].mappings[0].providerId).toBe('demo')
  } finally {
    methods.mockRestore()
    mappings.mockRestore()
    saved.mockRestore()
  }
})

it.each([
  { language: 'zh-CN', provider: '身份源', label: 'legacy-id（未配置）', save: '保存映射' },
  { language: 'en', provider: 'Provider', label: 'legacy-id (not configured)', save: 'Save mappings' },
])('keeps the original unconfigured provider selectable after switching away in $language', async ({ language, provider, label, save }) => {
  const methods = vi.spyOn(api, 'getLoginMethods').mockResolvedValue({ methods: [
    { providerId: 'demo', displayName: 'Demo', kind: 'ldap' },
  ] })
  const mappings = vi.spyOn(api, 'getRoleMappings').mockResolvedValue({
    revision: '1',
    mappings: [{ providerId: 'legacy-id', group: 'old-team', roles: ['viewer'] }],
  })
  const saved = vi.spyOn(api, 'saveRoleMappings').mockResolvedValue({ revision: '1' })
  try {
    await openUsers()
    await screen.findByRole('option', { name: 'Demo' })
    await act(async () => { await i18n.changeLanguage(language) })
    const select = screen.getByLabelText(provider)
    expect(select).toHaveValue('legacy-id')
    fireEvent.change(select, { target: { value: 'demo' } })
    expect(select).toHaveValue('demo')
    expect(within(select).getAllByRole('option').map((option) => (option as HTMLOptionElement).value)).toContain('legacy-id')
    fireEvent.change(select, { target: { value: 'legacy-id' } })
    expect(select).toHaveValue('legacy-id')
    expect(within(select).getByRole('option', { name: label })).toHaveValue('legacy-id')
    fireEvent.click(screen.getByRole('button', { name: save }))
    await waitFor(() => expect(saved).toHaveBeenCalledTimes(1))
    expect(saved.mock.calls[0][0].mappings[0].providerId).toBe('legacy-id')
  } finally {
    methods.mockRestore()
    mappings.mockRestore()
    saved.mockRestore()
  }
})

it.each(['failed', 'empty'])('preserves existing mapping values when login methods are %s', async (state) => {
  const methods = vi.spyOn(api, 'getLoginMethods')
  if (state === 'failed') methods.mockRejectedValue(new ApiError('error.permissionDenied'))
  else methods.mockResolvedValue({ methods: [] })
  const mappings = vi.spyOn(api, 'getRoleMappings').mockResolvedValue({
    revision: '1',
    mappings: [{ providerId: 'legacy-id', group: 'old-team', roles: ['viewer'] }],
  })
  try {
    await openUsers()
    if (state === 'failed') expect(await screen.findByRole('alert')).toHaveTextContent('无权限')
    expect(await screen.findByLabelText('身份源')).toHaveValue('legacy-id')
    expect(screen.getByLabelText('组名')).toHaveValue('old-team')
    expect(screen.getByLabelText('映射角色（逗号分隔）')).toHaveValue('viewer')
  } finally {
    methods.mockRestore()
    mappings.mockRestore()
  }
})
