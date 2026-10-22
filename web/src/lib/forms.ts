import { z } from 'zod'
import { parseLabels } from '@/api'
export const requiredText = z.string().trim().min(1, 'error.required')
export const positiveInteger = z
  .number({ error: 'error.positiveInteger' })
  .int('error.positiveInteger')
  .min(1, 'error.positiveInteger')
export const labelsText = z.string().refine((value) => {
  try {
    parseLabels(value)
    return true
  } catch {
    return false
  }
}, 'error.labels')
export const commaList = (text: string) => [
  ...new Set(
    text
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean),
  ),
]
