import { Code } from '@connectrpc/connect'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api, ApiError } from '@/api'
import i18n from '@/i18n'

const approvalId = 'apr-20261013-0001'
const action = 'systemd_restart_service'

beforeEach(async () => {
  await i18n.changeLanguage('en')
})
afterEach(() => vi.restoreAllMocks())

function open(path = `/approvals/${approvalId}`) {
  window.history.replaceState({}, '', path)
  render(<App />)
}

async function openDecision(name: string) {
  const detail = await screen.findByRole('region', { name: 'Approval details' })
  fireEvent.click(await within(detail).findByRole('button', { name }))
  return screen.findByRole('dialog', { name })
}

describe('approval queue', () => {
  it('filters by status, action and eligibility and keeps filters on navigation', async () => {
    const list = vi.spyOn(api, 'listApprovals')
    open('/approvals')
    await screen.findByRole('link', { name: approvalId })
    const status = screen.getByLabelText('Approval status')
    expect(status).toHaveValue('APPROVAL_STATUS_PENDING')
    fireEvent.change(status, { target: { value: 'APPROVAL_STATUS_REJECTED' } })
    expect(await screen.findByText('No approval requests match these filters.')).toBeVisible()
    fireEvent.change(status, { target: { value: '' } })
    const actionFilter = screen.getByRole('textbox', { name: 'Action' })
    fireEvent.change(actionFilter, { target: { value: action } })
    const onlyActionable = screen.getByRole('checkbox', { name: 'Only requests I can decide' })
    fireEvent.click(onlyActionable)
    await waitFor(() => expect(list).toHaveBeenLastCalledWith({
      statuses: [],
      action,
      onlyActionable: true,
      page: { pageSize: 10, pageToken: '' },
    }))
    fireEvent.click(await screen.findByRole('link', { name: approvalId }))
    expect(await screen.findByRole('heading', { name: approvalId })).toBeVisible()
    expect(status).toHaveValue('')
    expect(actionFilter).toHaveValue(action)
    expect(onlyActionable).toBeChecked()
    expect(screen.getByRole('link', { name: approvalId })).toHaveAttribute('aria-current', 'page')
  })

  it('uses the next-page token and resets it when filters change', async () => {
    const { approval } = await api.getApproval({ approvalId })
    const list = vi.spyOn(api, 'listApprovals').mockImplementation(async (input) =>
      input?.page?.pageToken === 'opaque-cursor'
        ? { approvals: [{ ...approval, approvalId: 'apr-next' }], page: { nextPageToken: '' } }
        : { approvals: [approval], page: { nextPageToken: 'opaque-cursor' } },
    )
    open('/approvals')
    fireEvent.click(await screen.findByRole('button', { name: 'Next' }))
    expect(await screen.findByRole('link', { name: 'apr-next' })).toBeVisible()
    expect(list).toHaveBeenLastCalledWith(expect.objectContaining({
      page: { pageSize: 10, pageToken: 'opaque-cursor' },
    }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Action' }), { target: { value: action } })
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({
      action, page: { pageSize: 10, pageToken: '' },
    })))
  })

  it('shows permission errors in the queue and direct detail', async () => {
    const denied = new ApiError('error.permissionDenied', Code.PermissionDenied)
    vi.spyOn(api, 'listApprovals').mockRejectedValue(denied)
    vi.spyOn(api, 'getApproval').mockRejectedValue(denied)
    open()
    for (const name of ['Approval queue', 'Approval details']) {
      const pane = await screen.findByRole('region', { name })
      expect(await within(pane).findByRole('alert')).toHaveTextContent('Permission denied')
    }
  })
})

describe('approval detail', () => {
  it('opens a deep link and shows the exact frozen execution plan', async () => {
    const get = vi.spyOn(api, 'getApproval')
    open()
    const plan = await screen.findByRole('region', { name: 'Execution plan' })
    expect(get).toHaveBeenCalledWith({ approvalId })
    expect(within(plan).getByText('Gateway verified')).toBeVisible()
    expect(within(plan).getByText('default@20261013090000')).toBeVisible()
    expect(within(plan).getByText('(admin ∨ operator) ∧ (admin)')).toBeVisible()
    expect(within(plan).getByText('env=prod')).toBeVisible()
    expect(within(plan).getByText('{"service":"api"}')).toBeVisible()
    expect(within(plan).getAllByRole('listitem')).toHaveLength(2)
    expect(within(plan).getByText('host-01')).toBeVisible()
    expect(within(plan).getByText('host-02')).toBeVisible()
    expect(await within(plan).findByText('Offline')).toBeVisible()
    expect(screen.getByRole('link', { name: 'job-20261013-0044' }))
      .toHaveAttribute('href', '/jobs/job-20261013-0044')
  })

  it('renders supplied context and decision reasons literally and only links valid job IDs', async () => {
    const reason = '<img src=x onerror=alert(1)> [click](javascript:alert(1)) {{status}} $t(app.name)'
    const { approval } = await api.getApproval({ approvalId })
    vi.spyOn(api, 'getApproval').mockResolvedValue({
      approval: {
        ...approval,
        reason,
        evidence: { summary: reason, jobIds: ['job-20261013-0042', '../../policies', 'javascript:alert(1)'] },
        decisionReason: reason,
        decisions: [{ ...approval.decisions[0], reason }],
      },
    })
    open()
    const context = await screen.findByRole('region', { name: 'Requester context' })
    const history = screen.getByRole('region', { name: 'Decision history' })
    expect(within(context).getByRole('note')).toHaveTextContent('Untrusted content')
    expect(within(context).getAllByText(reason)).toHaveLength(2)
    expect(within(history).getAllByText(reason)).toHaveLength(2)
    expect(context.querySelector('img')).toBeNull()
    expect(history.querySelector('img, a')).toBeNull()
    const links = within(context).getAllByRole('link')
    expect(links).toHaveLength(1)
    expect(links[0]).toHaveAttribute('href', '/jobs/job-20261013-0042')
    expect(within(context).getByText('../../policies')).toBeVisible()
    expect(within(context).getByText('javascript:alert(1)')).toBeVisible()
  })

  it('sends the exact digest shown in confirmation with the optional comment', async () => {
    const { approval } = await api.getApproval({ approvalId })
    const approve = vi.spyOn(api, 'approveRequest')
    open()
    const dialog = await openDecision('Approve')
    expect(within(dialog).getByText(action)).toBeVisible()
    expect(within(dialog).getByText(approval.requestDigest)).toBeVisible()
    expect(within(dialog).getByText('2')).toBeVisible()
    fireEvent.change(within(dialog).getByLabelText('Comment (optional)'), { target: { value: 'Reviewed' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(approve).toHaveBeenCalledWith({
      approvalId,
      expectedRequestDigest: approval.requestDigest,
      reason: 'Reviewed',
    }))
    expect(await screen.findByText('Approval recorded')).toBeVisible()
  })

  it('refreshes the detail and asks the user to review again on a digest mismatch', async () => {
    const get = vi.spyOn(api, 'getApproval')
    vi.spyOn(api, 'approveRequest').mockRejectedValue(
      new ApiError('common.error', Code.FailedPrecondition, 'APPROVAL_DIGEST_MISMATCH'),
    )
    open()
    const dialog = await openDecision('Approve')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByText(/The reviewed execution plan changed/)).toBeVisible()
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('requires a non-blank reason to reject', async () => {
    const reject = vi.spyOn(api, 'rejectRequest')
    open()
    const dialog = await openDecision('Reject')
    const confirm = within(dialog).getByRole('button', { name: 'Confirm' })
    const reason = within(dialog).getByLabelText('Rejection reason (required)')
    expect(confirm).toBeDisabled()
    fireEvent.change(reason, { target: { value: '   ' } })
    expect(confirm).toBeDisabled()
    expect(reject).not.toHaveBeenCalled()
    fireEvent.change(reason, { target: { value: 'Wrong maintenance window' } })
    fireEvent.click(confirm)
    await waitFor(() => expect(reject).toHaveBeenCalledWith({ approvalId, reason: 'Wrong maintenance window' }))
    expect(await screen.findByText('Request rejected')).toBeVisible()
  })

  it('allows the requester to withdraw even when they cannot vote', async () => {
    const { approval } = await api.getApproval({ approvalId })
    const { user } = await api.getCurrentSession()
    vi.spyOn(api, 'getApproval').mockResolvedValueOnce({
      approval: {
        ...approval,
        requesterSubjectId: user.userId,
        canApprove: false,
        cannotApproveReason: 'SELF_APPROVAL_FORBIDDEN',
      },
    })
    const cancel = vi.spyOn(api, 'cancelApproval')
    open()
    const dialog = await openDecision('Withdraw request')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(cancel).toHaveBeenCalledWith({ approvalId }))
    expect(await screen.findByText('Request cancelled')).toBeVisible()
  })

  it('disables both votes and explains the gateway eligibility reason', async () => {
    const { approval } = await api.getApproval({ approvalId })
    vi.spyOn(api, 'getApproval').mockResolvedValue({
      approval: { ...approval, canApprove: false, cannotApproveReason: 'APPROVER_ROLES_REQUIRED' },
    })
    open()
    expect(await screen.findByText('Your roles do not satisfy all approval role groups.')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Approve' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Reject' })).toBeDisabled()
  })
})
