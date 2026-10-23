// Release notes live on GitHub; the manifest only carries the version.
export function releaseNotesUrl(version: string) {
  return `https://github.com/liubing0806/allowops/releases/tag/v${version}`
}

export function displayVersion(version: string) {
  return version === 'dev' ? 'dev' : `v${version}`
}
