# Documentation site development

Use Node.js 24.19.0 or newer and pnpm 10.33.2. Direct dependencies are exact
versions; commit `pnpm-lock.yaml` when changing them. From this directory:

```sh
pnpm install --frozen-lockfile
pnpm docs:check
pnpm docs:build
pnpm docs:preview
```

`docs:check` checks repository-relative Markdown file links and local fragments,
including headings, explicit anchors and LICENSE links. Repository pages use
GitHub heading IDs; site pages use VitePress heading IDs. It also scans public
documentation, examples and site configuration in memory for address literals,
private domains/paths and credential patterns. It reports filenames, line numbers
and categories, never matched values. It excludes dependencies, generated output,
the lockfile and existing internal design documents. Pattern scanning cannot
prove that arbitrary encoded or unfamiliar sensitive data is absent; review
generic examples as well.

VitePress also rejects dead site links during build. Keep documentation commands
aligned with built binaries and MCP inputs aligned with `internal/gateway/mcp`.
Do not copy private operational analysis into public pages.

The [Pages workflow](https://github.com/liubing0806/allowops/blob/main/.github/workflows/docs-pages.yml) is configuration for a
later authorized release. It runs manually, requires the protected main branch,
and uses the `github-pages` environment. Configure Pages to use GitHub Actions
and set environment protections before enabling it. No publication occurs from
local installation/build. The base path is `/allowops/`; change it deliberately
if the public repository or custom-domain layout changes. See the
[VitePress deployment guide](https://vitepress.dev/guide/deploy#github-pages).
