import type { Labels } from './types'
import { ApiError } from './error'
export const toBase64 = (text: string) =>
  bytesToBase64(new TextEncoder().encode(text))
export const fromBase64 = (text: string) =>
  new TextDecoder().decode(base64ToBytes(text))
export const bytesToBase64 = (bytes: Uint8Array) =>
  btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(''))
export const base64ToBytes = (value: string) =>
  Uint8Array.from(atob(value), (c) => c.charCodeAt(0))

export function validateLabel(key: string, value: string) {
  const keyBytes = new TextEncoder().encode(key).length
  if (
    keyBytes < 1 ||
    keyBytes > 128 ||
    /[\r\n\0]/.test(key) ||
    ['__proto__', 'constructor', 'prototype'].includes(key) ||
    new TextEncoder().encode(value).length > 1024 ||
    /[\r\n\0]/.test(value)
  )
    throw new ApiError('error.labels')
}
// Label text holds one key=value per line. Only the first "=" separates key
// from value, so values may hold any character except line breaks and NUL.
// Surrounding whitespace is trimmed from the key; the value is kept as typed
// apart from the CR left by CRLF line endings.
export function parseLabels(text: string): Labels {
  const result: Labels = {}
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '')
    if (!line.trim()) continue
    const eq = line.indexOf('=')
    const key = line.slice(0, Math.max(eq, 0)).trim()
    if (eq < 0 || Object.hasOwn(result, key))
      throw new ApiError('error.labels')
    const value = line.slice(eq + 1)
    validateLabel(key, value)
    result[key] = value
  }
  return result
}
export const formatLabels = (labels: Labels) =>
  Object.entries(labels)
    .map(([k, v]) => `${k}=${v}`)
    .join('\n')
// Host selectors are a separate comma separated key=value format with a
// conservative charset; they are not label text.
export function parseSelector(text: string): Labels {
  const result: Labels = {}
  if (!text.trim()) return result
  for (const part of text.split(',')) {
    const match = /^\s*([a-zA-Z0-9_.-]+)\s*=\s*([a-zA-Z0-9_.-]*)\s*$/.exec(part)
    if (!match || Object.hasOwn(result, match[1]))
      throw new ApiError('error.labels')
    validateLabel(match[1], match[2])
    result[match[1]] = match[2]
  }
  return result
}
