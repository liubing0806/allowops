import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api } from '@/api'
import i18n from '@/i18n'

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
})

async function openPolicies() {
  window.history.replaceState({}, '', '/policies')
  render(<App />)
  await screen.findByRole('heading', { name: '策略', level: 1 }, { timeout: 5000 })
  await screen.findByRole('button', { name: '编辑 readonly-all' })
}

async function editRisks(value: string) {
  fireEvent.click(screen.getByRole('button', { name: '编辑 readonly-all' }))
  fireEvent.change(screen.getByLabelText('风险（逗号分隔）'), {
    target: { value },
  })
  fireEvent.click(screen.getByRole('button', { name: '保存' }))
  await waitFor(() =>
    expect(screen.getByRole('button', { name: '试算' })).toBeEnabled(),
  )
}

describe('policy save conditions', () => {
  it('keeps save disabled after a simulation without changes', async () => {
    await openPolicies()
    fireEvent.click(screen.getByRole('button', { name: '试算' }))
    expect(await screen.findByRole('heading', { name: '试算结果' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '保存策略' })).toBeDisabled()
    expect(screen.getByText('没有修改。')).toBeInTheDocument()
  })
  it('marks the simulation stale when the rule form changes', async () => {
    const save = vi.spyOn(api, 'savePolicy')
    try {
      await openPolicies()
      await editRisks('read,write')
      fireEvent.click(screen.getByRole('button', { name: '试算' }))
      await screen.findByRole('heading', { name: '试算结果' })
      expect(screen.getByRole('button', { name: '保存策略' })).toBeEnabled()
      fireEvent.change(screen.getByLabelText('角色（逗号分隔）'), {
        target: { value: 'operator' },
      })
      expect(
        screen.getByText('策略、试算或资源快照已变化，请重新试算'),
      ).toBeInTheDocument()
      expect(screen.queryByRole('heading', { name: '试算结果' })).not.toBeInTheDocument()
      expect(screen.getByRole('button', { name: '保存策略' })).toBeDisabled()
      expect(screen.getByRole('button', { name: '试算' })).toBeDisabled()
      expect(save).not.toHaveBeenCalled()
    } finally {
      save.mockRestore()
    }
  })
  it('saves a draft without a deleted rule after simulating it', async () => {
    await openPolicies()
    fireEvent.click(screen.getByRole('button', { name: '编辑 deny-core' }))
    fireEvent.click(screen.getByRole('button', { name: '删除规则' }))
    expect(
      screen.queryByRole('button', { name: '编辑 deny-core' }),
    ).not.toBeInTheDocument()
    expect(screen.getByText('未保存修改')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '试算' }))
    await screen.findByRole('heading', { name: '试算结果' })
    fireEvent.change(screen.getByLabelText('变更原因'), {
      target: { value: 'drop deny-core' },
    })
    fireEvent.click(screen.getByRole('button', { name: '保存策略' }))
    expect(await screen.findByRole('status')).toHaveTextContent('策略已保存')
    const { rules } = (await api.getPolicy()).policy.rules
    expect(rules.map((rule) => rule.name)).toEqual(['readonly-all', 'prod-restart'])
  })
})

describe('policy simulation scope', () => {
  it('simulates one subject, operation, action and selector', async () => {
    const testPolicy = vi.spyOn(api, 'testPolicy')
    try {
      await openPolicies()
      await editRisks('read,write')
      const scope = screen.getByRole('group', { name: '试算范围' })
      fireEvent.click(within(scope).getByRole('button', { name: '指定主体' }))
      const run = screen.getByRole('button', { name: '试算' })
      expect(run).toBeDisabled()
      const subject = screen.getByLabelText('主体')
      await within(subject).findByRole('option', { name: 'agent-readonly' })
      fireEvent.change(subject, { target: { value: 'sa-01' } })
      fireEvent.change(screen.getByLabelText('Action'), {
        target: { value: 'systemd_restart_service' },
      })
      fireEvent.change(screen.getByLabelText('目标选择器'), {
        target: { value: 'env=prod' },
      })
      expect(run).toBeEnabled()
      fireEvent.click(run)
      await screen.findByRole('heading', { name: '试算结果' })
      expect(testPolicy).toHaveBeenCalledWith(
        expect.objectContaining({
          cases: [
            expect.objectContaining({
              subjectId: 'sa-01',
              operation: 'execute_action',
              action: 'systemd_restart_service',
              targets: { selector: 'env=prod' },
            }),
          ],
        }),
      )
      expect(
        screen.getByText('2 处判定改变：2 处变为允许，0 处变为拒绝'),
      ).toBeInTheDocument()
      // Changing the scope inputs invalidates the shown result.
      fireEvent.change(screen.getByLabelText('目标选择器'), {
        target: { value: 'env=stage' },
      })
      expect(screen.queryByRole('heading', { name: '试算结果' })).not.toBeInTheDocument()
    } finally {
      testPolicy.mockRestore()
    }
  })
})

describe('approval policies', () => {
  it('validates approval configuration and sends it to the simulation', async () => {
    const testPolicy = vi.spyOn(api, 'testPolicy')
    try {
      await openPolicies()
      fireEvent.click(screen.getByRole('button', { name: '编辑 readonly-all' }))
      fireEvent.click(screen.getByRole('button', { name: '要求审批' }))
      const operations = screen.getByLabelText('操作（逗号分隔）')
      const roles = screen.getByLabelText('审批人角色（逗号分隔）')
      const minimum = screen.getByLabelText('最低批准票数')
      const ttl = screen.getByLabelText('审批有效期（秒）')
      const owner = screen.getByRole('checkbox', { name: '允许服务账号所有者批准' })
      const save = screen.getByRole('button', { name: '保存' })
      expect(minimum).toHaveValue(1)
      expect(ttl).toHaveValue(1800)
      expect(owner).not.toBeChecked()
      fireEvent.change(operations, { target: { value: 'execute_action,view_approvals' } })
      fireEvent.change(minimum, { target: { value: '1.5' } })
      fireEvent.change(ttl, { target: { value: '86401' } })
      fireEvent.click(save)
      expect(await screen.findByText('审批规则只允许使用 execute_action 操作。')).toBeVisible()
      expect(screen.getByText(/请输入 1–16 个角色名/)).toBeVisible()
      expect(screen.getByText('请输入 1 到 5 的整数。')).toBeVisible()
      expect(screen.getByText(/请输入 60 到 86400 秒的整数/)).toBeVisible()
      fireEvent.change(operations, { target: { value: 'execute_action' } })
      fireEvent.change(roles, { target: { value: 'admin, operator' } })
      fireEvent.change(minimum, { target: { value: '2' } })
      fireEvent.change(ttl, { target: { value: '1200' } })
      fireEvent.click(owner)
      fireEvent.click(save)
      const run = screen.getByRole('button', { name: '试算' })
      await waitFor(() => expect(run).toBeEnabled())
      fireEvent.click(run)
      await screen.findByRole('heading', { name: '试算结果' })
      expect(testPolicy).toHaveBeenCalledWith(expect.objectContaining({
        rules: {
          rules: expect.arrayContaining([expect.objectContaining({
            name: 'readonly-all',
            effect: 'POLICY_EFFECT_REQUIRE_APPROVAL',
            operations: ['execute_action'],
            approval: {
              approverRoles: ['admin', 'operator'],
              minApprovals: 2,
              ttlSeconds: 1200,
              allowOwnerApprove: true,
            },
          })]),
        },
      }))
    } finally {
      testPolicy.mockRestore()
    }
  })

  it('shows a requirement change when both decisions require approval', async () => {
    const approval = {
      requiredApproverRoleSets: [{ roles: ['admin', 'operator'] }],
      minApprovals: 1,
      ttlSeconds: 1800,
      allowOwnerApprove: false,
    }
    const before = {
      effect: 'POLICY_EFFECT_REQUIRE_APPROVAL' as const,
      matchedRules: ['prod-restart'],
      errorReason: '',
      approval,
    }
    const changes = vi.spyOn(api, 'getPolicyTestChanges').mockResolvedValue({
      changes: [{
        caseIndex: 0,
        host: 'web-01',
        before,
        after: {
          ...before,
          approval: {
            ...approval,
            requiredApproverRoleSets: [...approval.requiredApproverRoleSets, { roles: ['security'] }],
            minApprovals: 2,
            ttlSeconds: 600,
            allowOwnerApprove: true,
          },
        },
      }],
      page: { nextPageToken: '' },
    })
    try {
      await openPolicies()
      fireEvent.click(screen.getByRole('button', { name: '试算' }))
      expect(await screen.findByText('1 处判定改变，其中 1 处涉及审批约束')).toBeVisible()
      const row = screen.getByRole('row', { name: /web-01/ })
      expect(within(row).getAllByText('要求审批')).toHaveLength(2)
      expect(within(row).getByText('(admin ∨ operator)')).toBeVisible()
      expect(within(row).getByText('(admin ∨ operator) ∧ (security)')).toBeVisible()
      expect(within(row).getByText('1800')).toBeVisible()
      expect(within(row).getByText('600')).toBeVisible()
    } finally {
      changes.mockRestore()
    }
  })
})

describe('policy rollback draft', () => {
  it('loads historical rules and turns into a normal save after an edit', async () => {
    await openPolicies()
    fireEvent.click(screen.getByRole('button', { name: '版本历史' }))
    fireEvent.click(await screen.findByRole('button', { name: '试算回滚到 1' }))
    await screen.findByRole('heading', { name: '试算结果' })
    expect(
      screen.queryByRole('button', { name: '编辑 deny-core' }),
    ).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '确认回滚' })).toBeEnabled()
    await editRisks('read,write')
    expect(screen.getByRole('button', { name: '保存策略' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: '确认回滚' })).not.toBeInTheDocument()
  })
})
