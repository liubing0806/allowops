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
  if (
    !/^[a-zA-Z0-9_.-]{1,128}$/.test(key) ||
    ['__proto__', 'constructor', 'prototype'].includes(key) ||
    new TextEncoder().encode(value).length > 1024 ||
    /[\r\n\0]/.test(value)
  )
    throw new ApiError('error.labels')
}
export function parseLabels(text: string): Labels {
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
export const formatLabels = (labels: Labels) =>
  Object.entries(labels)
    .map(([k, v]) => `${k}=${v}`)
    .join(',')
