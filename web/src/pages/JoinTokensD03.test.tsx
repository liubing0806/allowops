import { fireEvent, render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'
import App from '@/App'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

describe('D03 join install command', () => {
  it('never embeds the real join secret in the install command', async () => {
    window.history.replaceState({}, '', '/join-tokens')
    render(<App />)
    await screen.findByRole('heading', { level: 1 }, { timeout: 5000 })
    fireEvent.click(screen.getByRole('button', { name: '创建 join token' }))
    const dialog = await screen.findByRole('dialog', { name: '请保存 token' })
    const secretText =
      within(dialog).getByText(/^aops_join_/).textContent ?? ''
    expect(secretText).toMatch(/^aops_join_[a-f0-9]{64}$/)
    const installText =
      within(dialog).getByText(/allowops-agent join/).textContent ?? ''
    // Real secret must not appear in the install command (argv/history).
    expect(installText).not.toContain(secretText)
    expect(installText).toContain('--token-file')
    expect(installText).toContain('/absolute/path/join-token.txt')
    expect(installText).not.toMatch(/--token(?![-\w])/)
    expect(installText).toContain('--ca-pin')
    // One-time secret is shown separately and cleared on close.
    expect(
      within(dialog).getByText(/^aops_join_[a-f0-9]{64}$/),
    ).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '我已保存' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByText(/^aops_join_/)).not.toBeInTheDocument()
    expect(screen.queryByText(/allowops-agent join/)).not.toBeInTheDocument()
  })

  it('RR-d-06: shows the token-file hint before the install command', async () => {
    window.history.replaceState({}, '', '/join-tokens')
    render(<App />)
    await screen.findByRole('heading', { level: 1 }, { timeout: 5000 })
    fireEvent.click(screen.getByRole('button', { name: '创建 join token' }))
    const dialog = await screen.findByRole('dialog', { name: '请保存 token' })
    const hint = within(dialog).getByText(/先将 secret 以 0600 权限保存到文件/)
    const title = within(dialog).getByRole('heading', { name: '安装命令' })
    const command = within(dialog).getByText(/allowops-agent join/)
    const before = Node.DOCUMENT_POSITION_FOLLOWING
    expect(hint.compareDocumentPosition(title) & before).toBe(before)
    expect(hint.compareDocumentPosition(command) & before).toBe(before)
  })
})
