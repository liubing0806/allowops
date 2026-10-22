import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

// Replaces one label of the draft without assuming how labels are separated,
// so the edit works for any label text format.
function editLabel(from: string, to: string) {
  const field = screen.getByLabelText('授权标签') as HTMLInputElement
  expect(field.value).toContain(from)
  fireEvent.change(field, { target: { value: field.value.replace(from, to) } })
}

describe('editing labels whose values contain punctuation or spaces', () => {
  it('saves the other host labels with the original value intact', async () => {
    const { host } = await api.getHost({ hostname: 'web-01' })
    vi.spyOn(api, 'getHost').mockResolvedValue({
      host: { ...host, authorizationLabels: { team: '研发 团队', env: 'prod' } },
    })
    const setLabels = vi.spyOn(api, 'setHostLabels')
    window.history.replaceState({}, '', '/hosts/web-01')
    render(<App />)
    await screen.findByLabelText('授权标签')
    editLabel('env=prod', 'env=stage')
    fireEvent.click(screen.getByRole('button', { name: '保存标签' }))
    await waitFor(() => expect(setLabels).toHaveBeenCalledTimes(1))
    expect(setLabels.mock.calls[0][0].changes.set).toEqual({
      team: '研发 团队',
      env: 'stage',
    })
  })
  it('saves the other rule host labels with the original value intact', async () => {
    const { policy } = await api.getPolicy()
    const seeded = {
      rules: [
        ...policy.rules.rules,
        {
          ...policy.rules.rules[0],
          name: 'seeded-rule',
          hostLabels: { team: 'ops,platform', env: 'prod' },
        },
      ],
    }
    const seedTest = await api.testPolicy({
      baseVersion: policy.version,
      rules: seeded,
      cases: [],
    })
    await api.savePolicy({
      baseVersion: policy.version,
      rules: seeded,
      testId: seedTest.test.testId,
      reason: 'seed',
    })
    window.history.replaceState({}, '', '/policies')
    render(<App />)
    fireEvent.click(
      await screen.findByRole('button', { name: '编辑 seeded-rule' }),
    )
    editLabel('env=prod', 'env=stage')
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '试算' })).toBeEnabled(),
    )
    fireEvent.click(screen.getByRole('button', { name: '试算' }))
    await screen.findByRole('heading', { name: '试算结果' })
    fireEvent.change(screen.getByLabelText('变更原因'), {
      target: { value: 'edit labels' },
    })
    fireEvent.click(screen.getByRole('button', { name: '保存策略' }))
    expect(await screen.findByRole('status')).toHaveTextContent('策略已保存')
    const saved = (await api.getPolicy()).policy.rules.rules.find(
      (rule) => rule.name === 'seeded-rule',
    )!
    expect(saved.hostLabels).toEqual({ team: 'ops,platform', env: 'stage' })
  })
})
