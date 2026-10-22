import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, vi } from 'vitest'
import { resetMock } from '@/test/fixtures/mock'
import i18n from '@/i18n'

// Demo-only copy belongs to the test fixtures, not the production console.
i18n.addResources('zh-CN', 'translation', {
  'token.description.demo': '演示凭据',
  'error.mockCidr': '本地 mock 尚未实现 CIDR 求值，此规则无法试算',
  'error.auditRange': '本地校验区间必须为 1–3',
})
i18n.addResources('en', 'translation', {
  'token.description.demo': 'Demo credential',
  'error.mockCidr': 'CIDR evaluation is not implemented in this local mock',
  'error.auditRange': 'Local verification range must be 1–3',
})

vi.mock('@/api/navigation', () => ({ redirectToLogin: vi.fn() }))

vi.mock('@/api', async () => ({
  ...(await vi.importActual<typeof import('@/api')>('@/api')),
  api: (await import('@/test/fixtures/mock')).mockApi,
}))

afterEach(cleanup)
beforeEach(resetMock)
vi.stubGlobal('crypto', webcrypto)
vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  },
)
HTMLDialogElement.prototype.showModal = function () {
  this.open = true
}
HTMLDialogElement.prototype.close = function () {
  this.open = false
}
