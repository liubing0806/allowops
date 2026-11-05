import type { LabelChanges, Labels } from '@/api'

export interface DiffLine {
  kind: 'add' | 'remove'
  text: string
}

// Mirrors A10 label semantics: remove named keys, then set named keys.
export function labelDiff(before: Labels, changes: LabelChanges): DiffLine[] {
  const lines: DiffLine[] = []
  for (const key of changes.remove) {
    if (Object.hasOwn(before, key) && !Object.hasOwn(changes.set, key))
      lines.push({ kind: 'remove', text: `${key}=${before[key]}` })
  }
  for (const [key, value] of Object.entries(changes.set)) {
    if (before[key] === value) continue
    if (Object.hasOwn(before, key))
      lines.push({ kind: 'remove', text: `${key}=${before[key]}` })
    lines.push({ kind: 'add', text: `${key}=${value}` })
  }
  return lines
}

// Diff between two complete label sets (CSV import preview rows).
export function labelsDelta(before: Labels, after: Labels): DiffLine[] {
  const lines: DiffLine[] = []
  for (const [key, value] of Object.entries(before)) {
    if (after[key] !== value) lines.push({ kind: 'remove', text: `${key}=${value}` })
  }
  for (const [key, value] of Object.entries(after)) {
    if (before[key] !== value) lines.push({ kind: 'add', text: `${key}=${value}` })
  }
  return lines
}
