import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api, ApiError } from '@/api'
import i18n from '@/i18n'

describe('console session after LDAP login', () => {
  it('opens the overview after an unauthenticated session was cached', async () => {
    await i18n.changeLanguage('zh-CN')
    const current = await api.getCurrentSession()
    const session = vi
      .spyOn(api, 'getCurrentSession')
      .mockRejectedValue(
        Object.assign(new ApiError('error.unauthenticated'), { code: 16 }),
      )
    const login = vi.spyOn(api, 'loginLdap').mockImplementation(async () => {
      session.mockResolvedValue(current)
      return { user: current.user }
    })
    try {
      window.history.replaceState({}, '', '/')
      render(<App />)
      await screen.findByRole(
        'heading',
        { name: '登录控制台' },
        { timeout: 5000 },
      )
      fireEvent.change(screen.getByLabelText('用户名'), {
        target: { value: 'console-user' },
      })
      fireEvent.change(screen.getByLabelText('密码'), {
        target: { value: 'fixture-password' },
      })
      await waitFor(() =>
        expect(screen.getByRole('button', { name: '登录' })).toBeEnabled(),
      )
      fireEvent.click(screen.getByRole('button', { name: '登录' }))
      expect(
        await screen.findByRole('heading', { name: '概览' }, { timeout: 5000 }),
      ).toBeInTheDocument()
    } finally {
      session.mockRestore()
      login.mockRestore()
    }
  })
  it('discards the previous identity data before opening the new session', async () => {
    await i18n.changeLanguage('zh-CN')
    const status = await api.getSystemStatus()
    const system = vi
      .spyOn(api, 'getSystemStatus')
      .mockResolvedValueOnce(status)
      .mockImplementation(() => new Promise(() => {}))
    try {
      window.history.replaceState({}, '', '/')
      render(<App />)
      await screen.findByText('在线主机', {}, { timeout: 5000 })
      fireEvent.click(screen.getByRole('link', { name: '当前用户' }))
      await screen.findByRole('heading', { name: '登录控制台' })
      fireEvent.change(screen.getByLabelText('用户名'), {
        target: { value: 'view-user' },
      })
      fireEvent.change(screen.getByLabelText('密码'), {
        target: { value: 'fixture-password' },
      })
      await waitFor(() =>
        expect(screen.getByRole('button', { name: '登录' })).toBeEnabled(),
      )
      fireEvent.click(screen.getByRole('button', { name: '登录' }))
      await screen.findByRole('heading', { name: '概览' })
      expect(screen.queryByText('在线主机')).not.toBeInTheDocument()
    } finally {
      system.mockRestore()
    }
  })
})


describe('console theme before authentication', () => {
  it('follows the system theme on direct login and later system changes', async () => {
    await i18n.changeLanguage('zh-CN')
    const originalMatchMedia = Object.getOwnPropertyDescriptor(window, 'matchMedia')
    const originalClassName = document.documentElement.className
    const originalColorScheme = document.documentElement.style.colorScheme
    const originalUrl = window.location.href
    const media = Object.assign(new EventTarget(), {
      matches: true,
      media: '(prefers-color-scheme: dark)',
    })
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: vi.fn(() => media),
    })
    document.documentElement.classList.remove('dark')
    document.documentElement.style.colorScheme = ''
    window.history.replaceState({}, '', '/login')
    const app = render(<App />)
    try {
      await screen.findByRole('heading', { name: '登录控制台' })
      expect(document.documentElement).toHaveClass('dark')
      expect(document.documentElement.style.colorScheme).toBe('dark')

      media.matches = false
      media.dispatchEvent(new Event('change'))
      expect(document.documentElement).not.toHaveClass('dark')
      expect(document.documentElement.style.colorScheme).toBe('light')

      media.matches = true
      media.dispatchEvent(new Event('change'))
      expect(document.documentElement).toHaveClass('dark')
    } finally {
      app.unmount()
      if (originalMatchMedia) {
        Object.defineProperty(window, 'matchMedia', originalMatchMedia)
      } else {
        Reflect.deleteProperty(window, 'matchMedia')
      }
      document.documentElement.className = originalClassName
      document.documentElement.style.colorScheme = originalColorScheme
      window.history.replaceState({}, '', originalUrl)
    }
  })
})
