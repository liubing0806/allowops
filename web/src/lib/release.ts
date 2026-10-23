// Release notes live on GitHub; the manifest only carries the version.
export function releaseNotesUrl(version: string) {
  return `https://github.com/liubing0806/allowops/releases/tag/v${version}`
}

// An older gateway omits the version during a rolling upgrade.
export function displayVersion(version: string) {
  if (!version) return ''
  return version === 'dev' ? 'dev' : `v${version}`
}
