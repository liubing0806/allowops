import { useEffect, useState, type ReactNode } from 'react'
import {
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from '@tanstack/react-table'
import { useTranslation } from 'react-i18next'
import { XIcon } from 'lucide-react'
import { ApiError } from '@/api'
import { DialogNotification } from '@/components/console/NotificationProvider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardHeader,
} from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { cn } from '@/lib/utils'

export function PageTitle({
  title,
  description,
  action,
}: {
  title: string
  description?: string
  action?: ReactNode
}) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-3 pb-1">
      <div className="min-w-0 flex-1">
        <h1 title={title} className="truncate text-lg font-semibold">
          {title}
        </h1>
        {description && (
          <p className="text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      {action}
    </header>
  )
}

export function Panel({
  title,
  children,
  className = '',
}: {
  title?: string
  children: ReactNode
  className?: string
}) {
  return (
    <section className={cn('panel min-w-0', className)}>
      <Card>
        {title && (
          <CardHeader>
            <h2 className="text-base leading-snug font-medium group-data-[size=sm]/card:text-sm">
              {title}
            </h2>
          </CardHeader>
        )}
        <CardContent className="flex min-w-0 flex-col gap-3">
          {children}
        </CardContent>
      </Card>
    </section>
  )
}

export function Field({
  label,
  error,
  children,
  hint,
}: {
  label: string
  error?: string
  children: ReactNode
  hint?: string
}) {
  const { t } = useTranslation()
  return (
    <Label className="flex min-w-0 flex-col items-stretch gap-1.5 text-xs">
      <span className="font-medium text-muted-foreground">{label}</span>
      {children}
      {hint && (
        <small className="text-xs text-muted-foreground">{hint}</small>
      )}
      {error && (
        <small className="text-xs text-destructive" role="alert">
          {t(error)}
        </small>
      )}
    </Label>
  )
}

function statusVariant(value: string): 'default' | 'secondary' | 'destructive' | 'outline' {
  const upper = value.toUpperCase()
  if (/(SUCCEEDED|HEALTHY|ALLOW)$/.test(upper)) return 'default'
  if (/(FAILED|DENIED|DENY|UNAVAILABLE|TIMEOUT)$/.test(upper))
    return 'destructive'
  if (/(PENDING|QUEUED|RUNNING|OFFLINE|DEGRADED|EXPIRING)$/.test(upper))
    return 'secondary'
  return 'outline'
}

export function Status({ value }: { value: string }) {
  const { t } = useTranslation()
  return (
    <Badge variant={statusVariant(value)}>
      {t(`status.${value}`, { defaultValue: value })}
    </Badge>
  )
}

export function MonoId({
  value,
  className = 'mono-id',
}: {
  value: string
  className?: 'mono-id' | 'hash'
}) {
  return (
    <code
      title={value}
      className={cn(
        'inline-block max-w-44 truncate align-bottom font-mono text-xs',
        className === 'hash' &&
          'rounded bg-muted px-1.5 py-0.5 text-muted-foreground',
      )}
    >
      {value}
    </code>
  )
}

export function QueryState({
  pending,
  error,
}: {
  pending: boolean
  error?: Error | null
}) {
  const { t } = useTranslation()
  if (error)
    return (
      <p role="alert" className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
        {t(error instanceof ApiError ? error.key : 'common.error')}
      </p>
    )
  if (pending)
    return (
      <p aria-live="polite" className="py-2 text-sm text-muted-foreground">
        {t('common.loading')}
      </p>
    )
  return null
}

export function Time({ value }: { value?: string }) {
  const { t, i18n } = useTranslation()
  return (
    <>
      {value
        ? new Intl.DateTimeFormat(i18n.language, {
            dateStyle: 'medium',
            timeStyle: 'short',
          }).format(new Date(value))
        : t('common.none')}
    </>
  )
}

// Paging state of a list that the server pages by token. DataTable then shows
// the rows it is given and only renders the controls.
export interface ServerPager {
  page: number
  hasNext: boolean
  pending?: boolean
  onPrevious: () => void
  onNext: () => void
}

function PagerFooter({
  label,
  canPrevious,
  canNext,
  onPrevious,
  onNext,
}: {
  label: string
  canPrevious: boolean
  canNext: boolean
  onPrevious: () => void
  onNext: () => void
}) {
  const { t } = useTranslation()
  return (
    <footer className="flex items-center justify-end gap-2 border-t pt-2 text-xs text-muted-foreground">
      <span>{label}</span>
      <Button
        variant="outline"
        size="sm"
        disabled={!canPrevious}
        onClick={onPrevious}
      >
        {t('common.previous')}
      </Button>
      <Button variant="outline" size="sm" disabled={!canNext} onClick={onNext}>
        {t('common.next')}
      </Button>
    </footer>
  )
}

export function DataTable<T>({
  data,
  columns,
  pager,
}: {
  data: T[]
  columns: ColumnDef<T>[]
  pager?: ServerPager
}) {
  const { t } = useTranslation()
  const [sorting, setSorting] = useState<SortingState>([])
  // eslint-disable-next-line react-hooks/incompatible-library -- Table 8 has mutable methods; this Vite project does not enable React Compiler.
  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    manualPagination: !!pager,
    initialState: { pagination: { pageSize: 10 } },
  })
  return (
    <div className="min-w-0">
      <Table>
        <TableHeader>
          {table.getHeaderGroups().map((group) => (
            <TableRow key={group.id}>
              {group.headers.map((header) => (
                <TableHead
                  key={header.id}
                  aria-sort={
                    header.column.getIsSorted() === 'asc'
                      ? 'ascending'
                      : header.column.getIsSorted() === 'desc'
                        ? 'descending'
                        : undefined
                  }
                >
                  {header.isPlaceholder ? null : header.column.getCanSort() ? (
                    <button
                      type="button"
                      className="inline-flex items-center gap-1 font-medium text-muted-foreground hover:text-foreground"
                      onClick={header.column.getToggleSortingHandler()}
                      aria-label={t('common.sort', {
                        column: String(header.column.columnDef.header),
                      })}
                    >
                      {flexRender(
                        header.column.columnDef.header,
                        header.getContext(),
                      )}
                      <span aria-hidden="true">
                        {header.column.getIsSorted() === 'desc'
                          ? ' ↓'
                          : header.column.getIsSorted() === 'asc'
                            ? ' ↑'
                            : ''}
                      </span>
                    </button>
                  ) : (
                    flexRender(
                      header.column.columnDef.header,
                      header.getContext(),
                    )
                  )}
                </TableHead>
              ))}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows.map((row) => (
            <TableRow key={row.id}>
              {row.getVisibleCells().map((cell) => (
                <TableCell key={cell.id}>
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </TableCell>
              ))}
            </TableRow>
          ))}
          {!data.length && (
            <TableRow>
              <TableCell colSpan={columns.length} className="text-center text-muted-foreground">
                {t('common.empty')}
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
      {pager ? (
        (pager.page > 1 || pager.hasNext) && (
          <PagerFooter
            label={t('common.page', { page: pager.page })}
            canPrevious={pager.page > 1 && !pager.pending}
            canNext={pager.hasNext && !pager.pending}
            onPrevious={pager.onPrevious}
            onNext={pager.onNext}
          />
        )
      ) : (
        data.length > 10 && (
          <PagerFooter
            label={t('common.pagination', {
              page: table.getState().pagination.pageIndex + 1,
              total: table.getPageCount(),
              count: data.length,
            })}
            canPrevious={table.getCanPreviousPage()}
            canNext={table.getCanNextPage()}
            onPrevious={() => table.previousPage()}
            onNext={() => table.nextPage()}
          />
        )
      )}
    </div>
  )
}

export function DialogShell({
  title,
  children,
  onClose,
}: {
  title: string
  children: ReactNode
  onClose: () => void
}) {
  const { t } = useTranslation()
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
    >
      <DialogContent
        aria-describedby={undefined}
        showCloseButton={false}
        onEscapeKeyDown={(event) => {
          event.preventDefault()
          onClose()
        }}
      >
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>
        <DialogNotification />
        {children}
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

export function DialogLegacy({
  title,
  children,
  onClose,
}: {
  title: string
  children: ReactNode
  onClose: () => void
}) {
  return (
    <DialogShell title={title} onClose={onClose}>
      {children}
    </DialogShell>
  )
}

export { DialogLegacy as Dialog }

export function ConfirmDialog({
  title,
  description,
  onClose,
  onConfirm,
  pending = false,
}: {
  title: string
  description: string
  onClose: () => void
  onConfirm: () => void
  pending?: boolean
}) {
  const { t } = useTranslation()
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        showCloseButton={false}
        onEscapeKeyDown={(event) => {
          event.preventDefault()
          onClose()
        }}
      >
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogNotification />
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button variant="destructive" onClick={onConfirm} disabled={pending}>
            {t('common.confirm')}
          </Button>
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

export function SecretDialog({
  secret,
  install,
  installHint,
  onClose,
}: {
  secret: string
  install?: string
  installHint?: string
  onClose: () => void
}) {
  const { t } = useTranslation()
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        showCloseButton={false}
        onEscapeKeyDown={(event) => {
          event.preventDefault()
          onClose()
        }}
      >
        <DialogHeader>
          <DialogTitle>{t('token.title')}</DialogTitle>
          <DialogDescription>{t('token.warning')}</DialogDescription>
        </DialogHeader>
        <DialogNotification />
        <pre className="secret overflow-x-auto rounded-lg bg-muted p-3 font-mono text-xs break-all whitespace-pre-wrap text-primary">
          {secret}
        </pre>
        {install && (
          <>
            {installHint && (
              <p className="text-xs text-muted-foreground">{installHint}</p>
            )}
            <h3 className="text-xs font-semibold text-muted-foreground">
              {t('join.install')}
            </h3>
            <pre className="overflow-x-auto rounded-lg bg-muted p-3 font-mono text-xs whitespace-pre-wrap">
              {install}
            </pre>
          </>
        )}
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

export function TokenStatus({
  expiresAt,
  revokedAt,
}: {
  expiresAt: string
  revokedAt?: string
}) {
  const { t } = useTranslation()
  const [now, setNow] = useState(Date.now)
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 60000)
    return () => window.clearInterval(timer)
  }, [])
  const left = Date.parse(expiresAt) - now
  const key = revokedAt
    ? 'common.revoked'
    : left <= 0
      ? 'common.expired'
      : left <= 7 * 86400000
        ? 'common.expiring'
        : 'common.active'
  return (
    <Badge
      variant={
        revokedAt || left <= 0
          ? 'outline'
          : left <= 7 * 86400000
            ? 'secondary'
            : 'default'
      }
    >
      {t(key)}
    </Badge>
  )
}
