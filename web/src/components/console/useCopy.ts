import { useEffect, useRef, useState } from 'react'
import { useNotify } from '@/lib/notifications'

// Clipboard writes need a secure context; failures are reported, not hidden.
export function useCopy(successKey?: string) {
  const notify = useNotify()
  const [copied, setCopied] = useState(false)
  const timer = useRef<number | undefined>(undefined)
  useEffect(() => () => window.clearTimeout(timer.current), [])
  const copy = async (text: string, values?: Record<string, string | number>) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      window.clearTimeout(timer.current)
      timer.current = window.setTimeout(() => setCopied(false), 2000)
      if (successKey) notify({ key: successKey, values })
    } catch {
      notify({ key: 'common.copyFailed', error: true })
    }
  }
  return { copied, copy }
}
