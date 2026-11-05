const units: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 31536000],
  ['month', 2592000],
  ['day', 86400],
  ['hour', 3600],
  ['minute', 60],
  ['second', 1],
]

// `justNow` replaces Intl's "now" wording for the last few seconds.
export function relativeTime(
  value: string,
  locale: string,
  justNow: string,
  now = Date.now(),
) {
  const seconds = Math.round((Date.parse(value) - now) / 1000)
  const format = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' })
  if (Math.abs(seconds) < 10) return justNow
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size || unit === 'second')
      return format.format(Math.trunc(seconds / size), unit)
  }
  return format.format(seconds, 'second')
}
