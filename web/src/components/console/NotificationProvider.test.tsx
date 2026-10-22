import { useState } from 'react'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'
import { NotificationProvider } from '@/components/console/NotificationProvider'
import { ConfirmDialog, DialogShell, SecretDialog } from '@/components/console/common'
import { useNotify } from '@/lib/notifications'
import i18n from '@/i18n'

function Example() {
  const notify = useNotify()
  const [modal, setModal] = useState<'confirm' | 'form' | 'secret' | null>(null)
  const [nested, setNested] = useState(false)
  const [count, setCount] = useState(0)
  const fail = () => notify({ key: 'error.permissionDenied', error: true })
  return (
    <>
      <button onClick={fail}>Global error</button>
      <button onClick={() => notify({ key: 'job.cancelled' })}>Global success</button>
      <button onClick={() => setModal('confirm')}>Open confirmation</button>
      <button onClick={() => setModal('form')}>Open form</button>
      <button onClick={() => setModal('secret')}>Open secret</button>
      {modal === 'confirm' && (
        <ConfirmDialog title="Confirmation" description="Confirm operation"
          onConfirm={fail} onClose={() => setModal(null)} />
      )}
      {modal === 'form' && (
        <DialogShell title="Form" onClose={() => setModal(null)}>
          <button onClick={fail}>Save</button>
          <button onClick={() => notify({ key: 'job.cancelled' })}>Success</button>
          <button onClick={() => setNested(true)}>Open nested</button>
          <button aria-label="Rerender" onClick={() => setCount((value) => value + 1)}>Rerender {count}</button>
          {nested && (
            <ConfirmDialog title="Nested" description="Nested operation"
              onConfirm={fail} onClose={() => setNested(false)} />
          )}
        </DialogShell>
      )}
      {modal === 'secret' && (
        <SecretDialog secret="test-only-value" onClose={() => setModal(null)} />
      )}
    </>
  )
}

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
  render(<NotificationProvider><Example /></NotificationProvider>)
})

// Include pointerdown, which Radix uses to classify outside interactions.
async function pointerClick(element: HTMLElement) {
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)) })
  fireEvent(element, new MouseEvent('pointerdown', { bubbles: true, button: 0 }))
  fireEvent.mouseDown(element)
  act(() => element.focus())
  fireEvent.mouseUp(element)
  fireEvent.click(element)
}

describe('shared notifications with real Radix dialogs', () => {
  it('keeps ordinary global error and success notifications dismissible', async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Global error' }))
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('无权限')
    await pointerClick(within(alert).getByRole('button', { name: '关闭' }))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Global success' }))
    const status = screen.getByRole('status')
    expect(status).toHaveTextContent('已发送取消请求')
    await pointerClick(within(status).getByRole('button', { name: '关闭' }))
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it.each([
    { open: 'Open confirmation', title: 'Confirmation', action: '确认' },
    { open: 'Open form', title: 'Form', action: 'Save' },
  ])('exposes and dismisses errors inside $title without releasing the focus trap', async ({ open, title, action }) => {
    const background = screen.getByRole('button', { name: open })
    fireEvent.click(background)
    const dialog = screen.getByRole('dialog', { name: title })
    await pointerClick(within(dialog).getByRole('button', { name: action }))
    await screen.findByText('无权限')
    const alert = screen.getByRole('alert')
    expect(alert).toBeVisible()
    expect(alert.closest('[aria-hidden="true"]')).toBeNull()
    const dismiss = within(alert).getByRole('button', { name: '关闭' })
    expect(getComputedStyle(dismiss).pointerEvents).not.toBe('none')
    act(() => dismiss.focus())
    expect(dismiss).toHaveFocus()
    act(() => background.focus())
    expect(dismiss).toHaveFocus()
    const buttons = within(dialog).getAllByRole('button')
    act(() => buttons[buttons.length - 1].focus())
    fireEvent.keyDown(document.activeElement!, { key: 'Tab' })
    expect(buttons[0]).toHaveFocus()
    fireEvent.keyDown(document.activeElement!, { key: 'Tab', shiftKey: true })
    expect(buttons[buttons.length - 1]).toHaveFocus()
    await pointerClick(dismiss)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByRole('dialog', { name: title })).toBe(dialog)
    await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true))
  })

  it('keeps an undismissed error accessible after the dialog closes', async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Open confirmation' }))
    const dialog = screen.getByRole('dialog', { name: 'Confirmation' })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认' }))
    expect(screen.getByRole('alert')).toHaveTextContent('无权限')
    fireEvent.click(within(dialog).getByRole('button', { name: '取消' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    const alert = screen.getByRole('alert')
    expect(alert).toBeVisible()
    await pointerClick(within(alert).getByRole('button', { name: '关闭' }))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it.each(['Open confirmation', 'Open form', 'Open secret'])(
    'clears an old global notification when opening %s', async (open) => {
      fireEvent.click(screen.getByRole('button', { name: 'Global error' }))
      expect(screen.getByRole('alert')).toHaveTextContent('无权限')
      fireEvent.click(screen.getByRole('button', { name: open }))
      expect(screen.getByRole('dialog')).toBeInTheDocument()
      expect(screen.queryByRole('alert', { hidden: true })).not.toBeInTheDocument()
    },
  )

  it('clears the parent notice on nested open but preserves a new nested notice on close', async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Open form' }))
    const parent = screen.getByRole('dialog', { name: 'Form' })
    fireEvent.click(within(parent).getByRole('button', { name: 'Save' }))
    expect(screen.getByRole('alert')).toHaveTextContent('无权限')
    fireEvent.click(within(parent).getByRole('button', { name: 'Open nested' }))
    const nested = screen.getByRole('dialog', { name: 'Nested' })
    expect(screen.queryByRole('alert', { hidden: true })).not.toBeInTheDocument()
    fireEvent.click(within(nested).getByRole('button', { name: '确认' }))
    expect(within(nested).getByRole('alert')).toHaveTextContent('无权限')
    fireEvent.click(within(nested).getByRole('button', { name: '取消' }))
    expect(within(parent).getByRole('alert')).toHaveTextContent('无权限')
    fireEvent.click(within(parent).getByRole('button', { name: 'Open nested' }))
    expect(screen.queryByRole('alert', { hidden: true })).not.toBeInTheDocument()
  })

  it('clears a restored global notice on reopen and retains new notices during ordinary rerenders', async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Open form' }))
    const dialog = screen.getByRole('dialog', { name: 'Form' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    expect(within(dialog).getByRole('alert')).toHaveTextContent('无权限')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Success' }))
    expect(within(dialog).getByRole('status')).toHaveTextContent('已发送取消请求')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Rerender' }))
    expect(within(dialog).getByRole('status')).toHaveTextContent('已发送取消请求')
    expect(within(dialog).getByRole('button', { name: 'Rerender' })).toHaveTextContent('Rerender 1')
    fireEvent.click(within(dialog).getAllByRole('button', { name: '关闭' }).find((button) => !button.closest('[role="status"]'))!)
    expect(screen.getByRole('status')).toHaveTextContent('已发送取消请求')
    fireEvent.click(screen.getByRole('button', { name: 'Open form' }))
    expect(screen.getByRole('dialog', { name: 'Form' })).toBeInTheDocument()
    expect(screen.queryByRole('status', { hidden: true })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('无权限')
    await pointerClick(within(alert).getByRole('button', { name: '关闭' }))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByRole('dialog', { name: 'Form' })).toBeInTheDocument()
  })

  it('keeps success notifications accessible in an open form', async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Open form' }))
    const dialog = screen.getByRole('dialog', { name: 'Form' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Success' }))
    const status = screen.getByRole('status')
    expect(status).toHaveTextContent('已发送取消请求')
    await pointerClick(within(status).getByRole('button', { name: '关闭' }))
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    expect(dialog).toBeInTheDocument()
  })

  it('shows one accessible notification in the top dialog and restores its parent', async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Open form' }))
    const parent = screen.getByRole('dialog', { name: 'Form' })
    fireEvent.click(within(parent).getByRole('button', { name: 'Open nested' }))
    const nested = screen.getByRole('dialog', { name: 'Nested' })
    fireEvent.click(within(nested).getByRole('button', { name: '确认' }))
    const alert = screen.getByRole('alert')
    expect(screen.getAllByRole('alert', { hidden: true })).toHaveLength(1)
    const dismiss = within(alert).getByRole('button', { name: '关闭' })
    act(() => dismiss.focus())
    expect(dismiss).toHaveFocus()
    fireEvent.click(within(nested).getByRole('button', { name: '取消' }))
    expect(screen.queryByRole('dialog', { name: 'Nested' })).not.toBeInTheDocument()
    expect(screen.getByRole('dialog', { name: 'Form' })).toBe(parent)
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('无权限'))
    const restored = within(screen.getByRole('alert')).getByRole('button', { name: '关闭' })
    await pointerClick(restored)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(parent).toBeInTheDocument()
  })

  it('places a confirmation notice before its footer', () => {
    fireEvent.click(screen.getByRole('button', { name: 'Open confirmation' }))
    const dialog = screen.getByRole('dialog', { name: 'Confirmation' })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认' }))
    const notice = within(dialog).getByRole('alert')
    const footer = dialog.querySelector('[data-slot="dialog-footer"]')!
    expect(notice.compareDocumentPosition(footer) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('places a form notice ahead of potentially long content', () => {
    fireEvent.click(screen.getByRole('button', { name: 'Open form' }))
    const dialog = screen.getByRole('dialog', { name: 'Form' })
    const action = within(dialog).getByRole('button', { name: 'Save' })
    fireEvent.click(action)
    const notice = within(dialog).getByRole('alert')
    expect(notice.compareDocumentPosition(action) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

})
