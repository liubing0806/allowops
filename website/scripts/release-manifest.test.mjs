import assert from 'node:assert/strict'
import { test } from 'node:test'
import { releaseManifest } from './release-manifest.mjs'

const expected = '{"version":"0.1.0","published_at":"2026-10-22T00:00:00Z"}\n'

test('first valid release heading becomes the manifest', () => {
  const text = '# Release notes\n\n## v0.1.0 — 2026-10-22\n\nBody\n\n## v0.0.9 — 2026-10-01\n'
  assert.equal(releaseManifest(text), expected)
})

test('a suffix after the date is allowed', () => {
  assert.equal(releaseManifest('# Release notes\n\n## v0.1.0 — 2026-10-22 (pre-release)\n'), expected)
})

test('prerelease and build metadata are strict SemVer', () => {
  const out = releaseManifest('## v1.2.3-rc.1+build.5 — 2026-11-01\n')
  assert.deepEqual(JSON.parse(out), { version: '1.2.3-rc.1+build.5', published_at: '2026-11-01T00:00:00Z' })
})

test('a missing heading is an error', () => {
  assert.throws(() => releaseManifest('# Release notes\n\nNo releases yet.\n'), /no release heading/)
})

test('a non-SemVer version is an error', () => {
  assert.throws(() => releaseManifest('## v1.2 — 2026-10-22\n'), /SemVer/)
  assert.throws(() => releaseManifest('## v01.2.3 — 2026-10-22\n'), /SemVer/)
  assert.throws(() => releaseManifest('## v1.2.3-01 — 2026-10-22\n'), /SemVer/)
})

test('an impossible calendar date is an error', () => {
  assert.throws(() => releaseManifest('## v0.1.0 — 2026-02-30\n'), /date/)
})
