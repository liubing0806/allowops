import { createContext } from 'react'
export interface Notice {
  key: string
  values?: Record<string, string | number>
  error?: boolean
}
export const NotificationContext = createContext<(notice: Notice) => void>(
  () => {},
)
export const NotificationDisplayContext = createContext<{
  notice: Notice | null
  dismiss: () => void
  dialogId: string | undefined
  registerDialog: (id: string) => () => void
} | null>(null)
