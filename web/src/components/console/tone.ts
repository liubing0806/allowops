export type Tone = 'success' | 'warning' | 'info' | 'destructive' | 'neutral'

export const textTone: Record<Tone, string> = {
  success: 'text-success',
  warning: 'text-warning',
  info: 'text-info',
  destructive: 'text-destructive',
  neutral: 'text-foreground-2',
}

export const softTone: Record<Tone, string> = {
  success: 'bg-success-soft text-success',
  warning: 'bg-warning-soft text-warning',
  info: 'bg-info-soft text-info',
  destructive: 'bg-destructive-soft text-destructive',
  neutral: 'bg-muted text-foreground-2',
}

// Maps API enum names (job, task, health, decision) to a semantic tone.
export function statusTone(value: string): Tone {
  const upper = value.toUpperCase()
  if (upper === 'PENDING' || /(PARTIALLY_FAILED|DEGRADED|EXPIRING|PENDING_APPROVAL|APPROVAL_STATUS_PENDING|REQUIRE_APPROVAL)$/.test(upper))
    return 'warning'
  if (/(SUCCEEDED|HEALTHY|ALLOW|APPROVED|APPROVAL_VOTE_APPROVE)$/.test(upper)) return 'success'
  if (/(FAILED|DENIED|DENY|UNAVAILABLE|TIMEOUT|UNSUPPORTED|REJECTED|EXPIRED|APPROVAL_VOTE_REJECT)$/.test(upper))
    return 'destructive'
  if (/RUNNING$/.test(upper)) return 'info'
  return 'neutral'
}
