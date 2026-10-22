import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { isIP } from 'node:net'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import GithubSlugger from 'github-slugger'
import { createMarkdownRenderer } from 'vitepress'

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const markdownRenderer = await createMarkdownRenderer(repositoryRoot, {
  highlight: () => '',
  anchor: { permalink: false },
})

export function checkMarkdownLinks(root, files) {
  const findings = []
  const anchorsByPath = new Map()
  const anchors = path => {
    if (anchorsByPath.has(path)) return anchorsByPath.get(path)
    const tokens = markdownRenderer.parse(readFileSync(path, 'utf8'), { path })
    const ids = new Set()
    const slugger = new GithubSlugger()
    const sitePage = relative(root, path).startsWith('website/')
    for (const [index, token] of tokens.entries()) {
      if (token.type === 'heading_open') {
        const title = tokens[index + 1].children
          .filter(child => ['text', 'code_inline'].includes(child.type))
          .map(child => child.content).join('')
        ids.add(sitePage ? token.attrGet('id') : slugger.slug(title))
      }
      for (const html of [token, ...(token.children || [])]) {
        if (!['html_block', 'html_inline'].includes(html.type)) continue
        for (const match of html.content.matchAll(/\b(?:id|name)=["']([^"']+)["']/g)) ids.add(match[1])
      }
    }
    anchorsByPath.set(path, ids)
    return ids
  }
  for (const file of files) {
    const text = readFileSync(join(root, file), 'utf8')
      .replace(/^(`{3,}|~{3,})[^\n]*\n[\s\S]*?^\1[^\n]*$/gm, block => block.replace(/[^\n]/g, ' '))
      .replace(/`[^`\n]+`/g, code => ' '.repeat(code.length))
    for (const match of text.matchAll(/\[[^\]\n]*\]\(<?([^\s)>]+)>?(?:\s+"[^"]*")?\)/g)) {
      const [href, fragment = ''] = match[1].split('#', 2)
      const target = href.split('?', 1)[0]
      if (/^[a-z][a-z\d+.-]*:/i.test(href)) continue
      const path = !target ? resolve(root, file) : target.startsWith('/') && file.startsWith('website/')
        ? join(root, 'website', decodeURIComponent(target))
        : resolve(root, dirname(file), decodeURIComponent(target))
      const candidates = [path]
      if (file.startsWith('website/')) candidates.push(`${path}.md`, join(path, 'index.md'))
      let resolved = candidates.find(candidate => existsSync(candidate))
      const line = text.slice(0, match.index).split('\n').length
      if (!resolved) {
        findings.push({ file, line, kind: 'broken-link' })
        continue
      }
      if (!fragment) continue
      if (statSync(resolved).isDirectory()) {
        resolved = [join(resolved, 'index.md'), join(resolved, 'README.md')].find(candidate => existsSync(candidate))
      }
      if (!resolved || !anchors(resolved).has(decodeURIComponent(fragment))) {
        findings.push({ file, line, kind: 'broken-anchor' })
      }
    }
  }
  return findings
}

export function scanSensitiveText(text) {
  const findings = []
  for (const [index, line] of text.split('\n').entries()) {
    const kinds = new Set()
    const addresses = line.match(/(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])[\da-f]*:[\da-f:]+(?![\w:])/gi) || []
    if (addresses.some(address => isIP(address))) kinds.add('ip-address')
    if (/\b[\w-]+(?:\.[\w-]+)*\.(?:internal|corp|lan|local|intranet)\b/i.test(line)) kinds.add('private-domain')
    if (/\/(?:home|Users)\/[^\s/]+\/|\/(?:srv|opt)\/(?:internal|private)\//.test(line)) kinds.add('private-path')
    if (/action-usage-analysis\.md/.test(line)) kinds.add('internal-analysis')
    if (/aops_[A-Za-z0-9_-]{32,}|(?:AKIA|ASIA)[A-Z\d]{16}|LTAI[A-Za-z\d]{12,}|gh[pousr]_[A-Za-z\d]{30,}|-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----|eyJ[A-Za-z\d_-]{12,}\.[A-Za-z\d_-]{12,}\.[A-Za-z\d_-]{12,}/.test(line)) kinds.add('credential')
    if (/\b(?:password|secret|token|api_key|access_key)\b["']?\s*[:=]\s*["']?(?!\$|<|\{|null\b|true\b|false\b)[A-Za-z\d/+_-]{8,}/i.test(line)) kinds.add('credential')
    if (/Bearer\s+[A-Za-z\d._-]{16,}/i.test(line)) kinds.add('credential')
    for (const kind of kinds) findings.push({ line: index + 1, kind })
  }
  return findings
}

function publicFiles(root) {
  const files = ['LICENSE', '.goreleaser.yaml', 'README.md', 'README.zh-CN.md', 'SECURITY.md', 'CONTRIBUTING.md', '.github/workflows/docs-pages.yml']
  const walk = dir => {
    for (const entry of readdirSync(join(root, dir), { withFileTypes: true })) {
      if (['node_modules', 'cache', 'dist', '.git'].includes(entry.name)) continue
      const path = join(dir, entry.name)
      if (entry.isDirectory()) walk(path)
      else if (entry.name !== 'pnpm-lock.yaml') files.push(path)
    }
  }
  for (const dir of ['website', 'examples/policy', 'examples/pipelines']) walk(dir)
  return files
}

function main() {
  const root = repositoryRoot
  const publicPaths = publicFiles(root)
  const markdown = ['LICENSE']
  const walk = dir => {
    for (const entry of readdirSync(join(root, dir), { withFileTypes: true })) {
      if (['.git', 'node_modules', 'bin', 'dist', 'cache', '.local'].includes(entry.name)) continue
      const path = join(dir, entry.name)
      if (entry.isDirectory()) walk(path)
      else if (entry.name.endsWith('.md')) markdown.push(path)
    }
  }
  walk('.')
  const findings = checkMarkdownLinks(root, markdown)
  for (const file of publicPaths) {
    findings.push(...scanSensitiveText(readFileSync(join(root, file), 'utf8')).map(hit => ({ file, ...hit })))
  }
  for (const finding of findings) {
    // Report locations/categories only; never print a matched credential value.
    console.error(`${relative(root, join(root, finding.file))}:${finding.line}: ${finding.kind}`)
  }
  console.log(`Checked ${markdown.length} Markdown files for relative links and anchors; scanned ${publicPaths.length} public files in memory; findings: ${findings.length}.`)
  process.exitCode = findings.length ? 1 : 0
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main()
