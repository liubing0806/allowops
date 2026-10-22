import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/
const heading = /^## v(\S+) — (\d{4}-\d{2}-\d{2})(?: .*)?$/m

// Returns the manifest JSON text for the first release heading of a changelog.
export function releaseManifest(changelog) {
  const match = heading.exec(changelog)
  if (!match) throw new Error('no release heading like "## v<version> — <YYYY-MM-DD>" found in CHANGELOG.md')
  const [, version, date] = match
  if (!semver.test(version)) throw new Error(`release version "${version}" is not strict SemVer 2.0`)
  const publishedAt = `${date}T00:00:00Z`
  if (new Date(publishedAt).toISOString().slice(0, 10) !== date) throw new Error(`release date "${date}" is not a valid calendar date`)
  return `${JSON.stringify({ version, published_at: publishedAt })}\n`
}

function main() {
  const output = resolve(root, 'website/public/version.json')
  try {
    const manifest = releaseManifest(readFileSync(resolve(root, 'CHANGELOG.md'), 'utf8'))
    mkdirSync(dirname(output), { recursive: true })
    writeFileSync(output, manifest)
  } catch (error) {
    console.error(`release-manifest: ${error.message}`)
    process.exit(1)
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main()
