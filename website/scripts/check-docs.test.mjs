import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { checkMarkdownLinks, scanSensitiveText } from './check-docs.mjs'

test('relative links resolve from their document and directories are valid', () => {
  const root = mkdtempSync(join(tmpdir(), 'allowops-docs-'))
  try {
    mkdirSync(join(root, 'website'))
    mkdirSync(join(root, 'examples'))
    writeFileSync(join(root, 'LICENSE'), 'license')
    writeFileSync(join(root, 'website', 'index.md'), '# Start')
    writeFileSync(join(root, 'README.md'), '[site](website/index.md) [examples](examples)')
    writeFileSync(join(root, 'website', 'guide.md'), '[license](../LICENSE) [home](/) [site](/index) [missing](missing.md)')
    assert.deepEqual(checkMarkdownLinks(root, ['README.md', 'website/guide.md']), [
      { file: 'website/guide.md', line: 1, kind: 'broken-link' },
    ])
  } finally {
    rmSync(root, { recursive: true })
  }
})

test('code examples and external links are ignored and local headings resolve', () => {
  const root = mkdtempSync(join(tmpdir(), 'allowops-docs-'))
  try {
    writeFileSync(join(root, 'README.md'), '# Example\n[web](https://example.org) [section](#example)\n```md\n[fake](absent.md)\n```\n`[fake](absent.md)`')
    assert.deepEqual(checkMarkdownLinks(root, ['README.md']), [])
  } finally {
    rmSync(root, { recursive: true })
  }
})

test('repository links validate Chinese GitHub heading fragments and reject old titles', () => {
  const root = mkdtempSync(join(tmpdir(), 'allowops-docs-'))
  try {
    mkdirSync(join(root, 'docs'))
    writeFileSync(join(root, 'docs', 'decisions.md'), '## 21. 实施期间确认的行为（A7~A28）')
    const current = '21-实施期间确认的行为a7a28'
    writeFileSync(join(root, 'README.md'), [
      `[current](docs/decisions.md#${current})`,
      `[encoded](docs/decisions.md#${encodeURIComponent(current)})`,
      '[old](docs/decisions.md#21-实施期间确认的行为a7a17)',
    ].join('\n'))
    assert.deepEqual(checkMarkdownLinks(root, ['README.md']), [
      { file: 'README.md', line: 3, kind: 'broken-anchor' },
    ])
  } finally {
    rmSync(root, { recursive: true })
  }
})

test('site anchors follow VitePress IDs including repeated and explicit headings', () => {
  const root = mkdtempSync(join(tmpdir(), 'allowops-docs-'))
  try {
    mkdirSync(join(root, 'website'))
    writeFileSync(join(root, 'website', 'guide.md'), [
      '## Repeated',
      '## Repeated',
      '## Named {#custom-name}',
      '<a id="html-anchor"></a>',
      '## 21. Numbered',
      '[repeat](#repeated-1) [custom](#custom-name) [html](#html-anchor)',
      '[numbered](#_21-numbered)',
      '```md',
      '## Only in code',
      '```',
      '[code](#only-in-code)',
      '[missing](#not-found)',
    ].join('\n'))
    assert.deepEqual(checkMarkdownLinks(root, ['website/guide.md']), [
      { file: 'website/guide.md', line: 11, kind: 'broken-anchor' },
      { file: 'website/guide.md', line: 12, kind: 'broken-anchor' },
    ])
  } finally {
    rmSync(root, { recursive: true })
  }
})

test('fragments are checked in LICENSE files and across site routes', () => {
  const root = mkdtempSync(join(tmpdir(), 'allowops-docs-'))
  try {
    mkdirSync(join(root, 'website'))
    writeFileSync(join(root, 'LICENSE'), '# License options')
    writeFileSync(join(root, 'website', 'index.md'), '# Start')
    writeFileSync(join(root, 'website', 'guide.md'), [
      '[license](../LICENSE#license-options)',
      '[home](/index#start)',
      '[missing](/index#absent)',
    ].join('\n'))
    assert.deepEqual(checkMarkdownLinks(root, ['website/guide.md']), [
      { file: 'website/guide.md', line: 3, kind: 'broken-anchor' },
    ])
  } finally {
    rmSync(root, { recursive: true })
  }
})

test('scanner detects address literals without treating version numbers as addresses', () => {
  const address = [192, 0, 2, 1].join('.')
  const ipv6 = ['2001', 'db8', '', '1'].join(':')
  const hits = scanSensitiveText(`Go 1.27.2\n${address}\n${ipv6}`)
  assert.deepEqual(hits, [
    { line: 2, kind: 'ip-address' },
    { line: 3, kind: 'ip-address' },
  ])
})

test('scanner rejects private locations and credential values without returning them', () => {
  const privateDomain = ['host', 'internal'].join('.')
  const privatePath = ['', 'home', 'user', 'project'].join('/')
  const token = ['aops_', 'A'.repeat(43)].join('')
  const hits = scanSensitiveText(`${privateDomain}\n${privatePath}\n${token}`)
  assert.deepEqual(hits, [
    { line: 1, kind: 'private-domain' },
    { line: 2, kind: 'private-path' },
    { line: 3, kind: 'credential' },
  ])
  assert.ok(!JSON.stringify(hits).includes(token))
})

test('generic paths and environment references remain valid public examples', () => {
  assert.deepEqual(scanSensitiveText('https://gateway.example.org /etc/allowops/ /var/lib/allowops/ .local/\n"Authorization": "Bearer ${ALLOWOPS_MCP_TOKEN}"'), [])
})
