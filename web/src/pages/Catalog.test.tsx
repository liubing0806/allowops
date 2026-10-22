import { fireEvent, render, screen, within } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'
import { describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { api, toBase64 } from '@/api'
import i18n from '@/i18n'

describe('gateway catalog definitions', () => {
  it.each([
    {
      definition: {
        exec: ['/usr/bin/df', '-h'],
        timeout: '10s',
        max_output: 65536,
      },
      text: '/usr/bin/df -h',
    },
    {
      definition: {
        params: {},
        builtin: 'redis_command',
        builtin_config: { commands: ['GET'] },
        timeout: '10s',
        max_output: 65536,
        redact: { builtin: ['secrets'] },
      },
      text: /redis_command/,
    },
  ])(
    'renders a canonical action with optional fields or another execution mode',
    async ({ definition, text }) => {
      await i18n.changeLanguage('zh-CN')
      const current = await api.getAction({
        catalog: { catalogId: 'operations', version: '20261013093000' },
        action: 'journal_view_log',
      })
      const getAction = vi.spyOn(api, 'getAction').mockResolvedValue({
        ...current,
        definitionJson: toBase64(JSON.stringify(definition)),
      })
      try {
        window.history.replaceState({}, '', '/catalog')
        render(<App />)
        fireEvent.click(
          await screen.findByRole('button', { name: 'journal_view_log' }),
        )
        const dialog = await screen.findByRole('dialog', {
          name: 'journal_view_log',
        })
        expect(await within(dialog).findByText(text)).toBeInTheDocument()
        if (!('redact' in definition))
          expect(
            await within(dialog).findByText('未指定（使用目录全局规则）'),
          ).toBeInTheDocument()
      } finally {
        getAction.mockRestore()
      }
    },
  )
  it.each([
    ['host_snapshot', 'steps', '/usr/bin/hostname'],
    ['nginx_access_stats', 'script', 'scripts/nginx_access_stats.py'],
    ['redis_get', 'builtin', 'redis_command'],
  ])(
    'renders the %s example as read-only %s configuration',
    async (name, mode, expected) => {
      await i18n.changeLanguage('zh-CN')
      const definition = parse(
        readFileSync(
          resolve(
            dirname(fileURLToPath(import.meta.url)),
            '../../../examples/catalog/actions',
            `${name}.yaml`,
          ),
          'utf8',
        ),
      ) as Record<string, unknown>
      const current = await api.getAction({
        catalog: { catalogId: 'operations', version: '20261013093000' },
        action: 'journal_view_log',
      })
      const summary = {
        ...current.action,
        name,
        description: String(definition.description),
        executionMode: mode,
      }
      const listActions = vi
        .spyOn(api, 'listActions')
        .mockResolvedValue({ actions: [summary], page: { nextPageToken: '' } })
      const getAction = vi.spyOn(api, 'getAction').mockResolvedValue({
        ...current,
        action: summary,
        definitionJson: toBase64(JSON.stringify(definition)),
      })
      try {
        window.history.replaceState({}, '', '/catalog')
        render(<App />)
        fireEvent.click(await screen.findByRole('button', { name }))
        const dialog = await screen.findByRole('dialog', { name })
        const config = await within(dialog).findByText(
          (text, element) =>
            element?.tagName === 'PRE' && text.includes(expected),
        )
        expect(config).toHaveTextContent(expected)
        expect(config).toHaveTextContent(mode)
        expect(config.querySelector('script')).toBeNull()
      } finally {
        listActions.mockRestore()
        getAction.mockRestore()
      }
    },
  )
})
