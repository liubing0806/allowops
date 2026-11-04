import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { XIcon } from 'lucide-react'
import { CodeBlock } from '@/components/console/CodeBlock'
import { DialogNotification } from '@/components/console/NotificationProvider'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

// A secret the gateway returns once. The plaintext lives only in the caller's
// state and disappears when the dialog closes.
export function OnceSecretDialog({
  secret,
  children,
  onClose,
}: {
  secret: string
  children?: ReactNode
  onClose: () => void
}) {
  const { t } = useTranslation()
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        showCloseButton={false}
        className="sm:max-w-lg"
        onEscapeKeyDown={(event) => {
          event.preventDefault()
          onClose()
        }}
      >
        <DialogHeader>
          <DialogTitle>{t('token.title')}</DialogTitle>
          <DialogDescription className="text-warning">
            {t('token.warning')}
          </DialogDescription>
        </DialogHeader>
        <DialogNotification />
        <CodeBlock code={secret} label="secret" className="secret" />
        {children}
        <DialogFooter>
          <Button onClick={onClose}>{t('token.saved')}</Button>
        </DialogFooter>
        <Button
          variant="ghost"
          size="icon-sm"
          className="absolute top-2 right-2"
          onClick={onClose}
          aria-label={t('common.close')}
        >
          <XIcon />
        </Button>
      </DialogContent>
    </Dialog>
  )
}
