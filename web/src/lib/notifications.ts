import { useContext } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ApiError } from '@/api'
import { NotificationContext } from '@/lib/notification-context'
export const useNotify = () => useContext(NotificationContext)
// Commands return void so plaintext tokens never enter mutation data.
// Login reads its form inside the command so passwords are not mutation variables.
export function useCommand<T = void>(
  command: (input: T) => Promise<void>,
  successKey?: string,
) {
  const notify = useNotify()
  const client = useQueryClient()
  return useMutation({
    mutationFn: command,
    onSuccess: async () => {
      await client.invalidateQueries()
      if (successKey) notify({ key: successKey })
    },
    onError: (error) =>
      notify({
        key: error instanceof ApiError ? error.key : 'common.error',
        error: true,
      }),
  })
}
