// Semantic-version comparison for agent and gateway versions. Returns null when
// either side is not a release version (for example "dev"), so callers make no
// upgrade claim they cannot back.
const pattern = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$/

export function compareVersions(a: string, b: string): number | null {
  const x = pattern.exec(a.trim())
  const y = pattern.exec(b.trim())
  if (!x || !y) return null
  for (let i = 1; i <= 3; i++) {
    const d = Number(x[i]) - Number(y[i])
    if (d) return Math.sign(d)
  }
  if (x[4] === y[4]) return 0
  if (!x[4]) return 1
  if (!y[4]) return -1
  return x[4] < y[4] ? -1 : 1
}

export function newestVersion(versions: string[]): string | undefined {
  let best: string | undefined
  for (const version of versions) {
    if (compareVersions(version, version) === null) continue
    if (!best || (compareVersions(version, best) ?? 0) > 0) best = version
  }
  return best
}
