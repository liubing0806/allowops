import { useEffect, useRef, useState } from 'react'
import { useForm, useWatch } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Trash2Icon } from 'lucide-react'
import {
  api,
  formatLabels,
  parseLabels,
  toBase64,
  type Host,
  type HostImportRow,
  type LabelChanges,
} from '@/api'
import {
  ConfirmDialog,
  DataTable,
  Field,
  MonoId,
  PageTitle,
  Panel,
  QueryState,
  Time,
} from '@/components/console/common'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { commaList, labelsText, requiredText } from '@/lib/forms'
import { useHostsFilterStore } from '@/lib/hosts-filter-store'
import { useCommand, useNotify } from '@/lib/notifications'

const filterSchema = z.object({
  selector: labelsText,
  hostname: z.string(),
  online: z.string(),
  agentVersion: z.string(),
})
const labelSchema = z.object({ labels: labelsText, remove: z.string() })
const bulkSchema = labelSchema.extend({
  selector: requiredText.pipe(labelsText),
})
const csvSchema = z.object({ csv: requiredText })

export default function Hosts() {
  const { t } = useTranslation()
  const filterStore = useHostsFilterStore()
  const form = useForm<z.infer<typeof filterSchema>>({
    resolver: zodResolver(filterSchema),
    mode: 'onChange',
    defaultValues: { selector: '', hostname: '', online: '', agentVersion: '' },
  })
  const values = useWatch({ control: form.control })
  useEffect(() => {
    filterStore.setFilter({
      selector: values.selector ?? '',
      hostname: values.hostname ?? '',
      online: values.online ?? '',
      agentVersion: values.agentVersion ?? '',
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [values.selector, values.hostname, values.online, values.agentVersion])
  useEffect(
    () => () => {
      useHostsFilterStore.getState().reset()
    },
    [],
  )
  const query = {
    selector: filterStore.selector,
    hostname: filterStore.hostname,
    online: filterStore.online
      ? filterStore.online === 'true'
      : undefined,
    agentVersion: filterStore.agentVersion,
  }
  const hosts = useQuery({
    queryKey: ['hosts', query],
    queryFn: () => api.listHosts({ query }),
  })
  const options = useQuery({
    queryKey: ['hostOptions'],
    queryFn: () => api.listHosts(),
  })
  const [tool, setTool] = useState<'bulk' | 'csv' | null>(null)
  const [deleting, setDeleting] = useState<Host | null>(null)
  const deletion = useCommand(async () => {
    if (deleting) {
      await api.deleteHost({
        hostId: deleting.hostId,
        expectedRevision: deleting.revision,
      })
      setDeleting(null)
    }
  }, 'host.deleted')
  return (
    <div className="flex flex-col gap-3">
      <PageTitle
        title={t('nav.hosts')}
        description={t('host.description')}
        action={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              onClick={() => setTool(tool === 'csv' ? null : 'csv')}
            >
              {t('host.csv')}
            </Button>
            <Button onClick={() => setTool(tool === 'bulk' ? null : 'bulk')}>
              {t('host.bulk')}
            </Button>
          </div>
        }
      />
      <Panel>
        <form
          noValidate
          className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4"
          onSubmit={(event) => event.preventDefault()}
        >
          <Field label={t('host.hostname')}>
            <Input {...form.register('hostname')} />
          </Field>
          <Field
            label={t('host.selector')}
            error={form.formState.errors.selector?.message}
          >
            <Input placeholder="env=prod" {...form.register('selector')} />
          </Field>
          <Field label={t('host.connection')}>
            <Select
              value={values.online === '' ? 'all' : (values.online ?? 'all')}
              onValueChange={(value) =>
                form.setValue('online', value === 'all' ? '' : value, {
                  shouldValidate: true,
                })
              }
            >
              <SelectTrigger aria-label={t('host.connection')}>
                <SelectValue placeholder={t('host.all')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('host.all')}</SelectItem>
                <SelectItem value="true">{t('host.online')}</SelectItem>
                <SelectItem value="false">{t('host.offline')}</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field label={t('host.agentVersion')}>
            <Select
              value={
                values.agentVersion === ''
                  ? 'all'
                  : (values.agentVersion ?? 'all')
              }
              onValueChange={(value) =>
                form.setValue(
                  'agentVersion',
                  value === 'all' ? '' : value,
                  { shouldValidate: true },
                )
              }
            >
              <SelectTrigger aria-label={t('host.agentVersion')}>
                <SelectValue placeholder={t('host.all')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('host.all')}</SelectItem>
                {[...new Set(options.data?.hosts.map((h) => h.agentVersion))].map(
                  (v) => (
                    <SelectItem key={v} value={v}>
                      {v}
                    </SelectItem>
                  ),
                )}
              </SelectContent>
            </Select>
          </Field>
        </form>
        <small className="text-xs text-muted-foreground">{t('host.selectorHint')}</small>
      </Panel>
      {tool === 'bulk' && <BulkLabels />}
      {tool === 'csv' && <ImportLabels />}
      <Panel>
        <QueryState pending={hosts.isPending} error={hosts.error} />
        {hosts.data && (
          <DataTable<Host>
            data={hosts.data.hosts}
            columns={[
              {
                accessorKey: 'hostname',
                header: t('host.hostname'),
                cell: ({ row }) => (
                  <Link
                    to={`/hosts/${row.original.hostname}`}
                    className="font-medium text-primary underline-offset-4 hover:underline"
                  >
                    {row.original.hostname}
                  </Link>
                ),
              },
              {
                accessorKey: 'online',
                header: t('host.connection'),
                cell: ({ row }) => (
                  <Badge
                    variant={row.original.online ? 'default' : 'secondary'}
                  >
                    {t(row.original.online ? 'host.online' : 'host.offline')}
                  </Badge>
                ),
              },
              {
                id: 'labels',
                header: t('host.labels'),
                cell: ({ row }) => (
                  <span className="font-mono text-xs text-muted-foreground">
                    {formatLabels(row.original.authorizationLabels) ||
                      t('common.none')}
                  </span>
                ),
              },
              { accessorKey: 'agentVersion', header: t('host.agentVersion') },
              {
                id: 'catalog',
                header: t('host.catalogVersion'),
                cell: ({ row }) =>
                  row.original.loadedCatalogs.map((c) => c.version).join(', '),
              },
              {
                id: 'delete',
                header: t('common.actions'),
                cell: ({ row }) => (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-muted-foreground hover:text-destructive"
                    aria-label={t('host.deleteTitle', {
                      name: row.original.hostname,
                    })}
                    onClick={() => setDeleting(row.original)}
                  >
                    <Trash2Icon />
                    {t('common.delete')}
                  </Button>
                ),
              },
            ]}
          />
        )}
      </Panel>
      {deleting && (
        <ConfirmDialog
          title={t('host.deleteTitle', { name: deleting.hostname })}
          description={t('host.deleteHint')}
          onClose={() => setDeleting(null)}
          onConfirm={() => deletion.mutate()}
          pending={deletion.isPending}
        />
      )}
    </div>
  )
}

function BulkLabels() {
  const { t } = useTranslation()
  const notify = useNotify()
  const form = useForm<z.infer<typeof bulkSchema>>({
    resolver: zodResolver(bulkSchema),
    defaultValues: { selector: '', labels: '', remove: '' },
  })
  const seq = useRef(0)
  const [preview, setPreview] = useState<{
    hosts: Host[]
    selector: string
    changes: LabelChanges
    seq: number
  } | null>(null)
  const previewing = useCommand(async (values: z.infer<typeof bulkSchema>) => {
    const my = ++seq.current
    const result = await api.listHosts({ query: { selector: values.selector } })
    if (seq.current !== my) return
    setPreview({
      hosts: result.hosts,
      selector: values.selector,
      changes: {
        set: parseLabels(values.labels),
        remove: commaList(values.remove),
      },
      seq: my,
    })
  })
  const applying = useCommand(async () => {
    if (!preview) return
    if (preview.seq !== seq.current) {
      setPreview(null)
      return
    }
    const result = await api.setHostLabels({
      targets: { selector: preview.selector },
      expectedCount: String(preview.hosts.length),
      changes: preview.changes,
      expectedRevisions: preview.hosts.map((h) => ({
        hostId: h.hostId,
        revision: h.revision,
      })),
    })
    setPreview(null)
    notify({ key: 'host.bulkSaved', values: { count: result.updatedCount } })
  })
  return (
    <Panel title={t('host.bulk')}>
      <p className="text-sm text-muted-foreground">{t('host.bulkHint')}</p>
      <form
        noValidate
        className="grid grid-cols-1 gap-3 md:grid-cols-3"
        onChange={() => {
          seq.current += 1
          setPreview(null)
        }}
        onSubmit={form.handleSubmit((values) => previewing.mutate(values))}
      >
        <Field
          label={t('host.selector')}
          error={form.formState.errors.selector?.message}
        >
          <Input {...form.register('selector')} />
        </Field>
        <Field
          label={t('host.labels')}
          error={form.formState.errors.labels?.message}
        >
          <Input placeholder="env=prod" {...form.register('labels')} />
        </Field>
        <Field label={t('host.removeKeys')}>
          <Input {...form.register('remove')} />
        </Field>
        <div className="md:col-span-3">
          <Button type="submit" disabled={previewing.isPending}>
            {t('host.bulkPreview')}
          </Button>
        </div>
      </form>
      {preview && (
        <div className="flex flex-col gap-2 border-t pt-3">
          <p className="text-sm text-muted-foreground">
            {preview.hosts.map((h) => h.hostname).join(', ') ||
              t('common.empty')}
          </p>
          <div>
            <Button
              disabled={!preview.hosts.length || applying.isPending}
              onClick={() => applying.mutate()}
            >
              {t('host.bulkApply', { count: preview.hosts.length })}
            </Button>
          </div>
        </div>
      )}
    </Panel>
  )
}

function ImportLabels() {
  const { t } = useTranslation()
  const notify = useNotify()
  const form = useForm<z.infer<typeof csvSchema>>({
    resolver: zodResolver(csvSchema),
    defaultValues: { csv: '' },
  })
  const seq = useRef(0)
  const [preview, setPreview] = useState<
    | (Awaited<ReturnType<typeof api.getHostImportPreview>> & {
        seq: number
      })
    | null
  >(null)
  const previewing = useCommand(async (values: z.infer<typeof csvSchema>) => {
    const my = ++seq.current
    const result = await api.previewHostImport({ csv: toBase64(values.csv) })
    if (seq.current !== my) return
    const detailed = await api.getHostImportPreview({
      previewId: result.preview.previewId,
    })
    if (seq.current !== my) return
    setPreview({ ...detailed, seq: my })
  })
  const applying = useCommand(async () => {
    if (!preview) return
    if (preview.seq !== seq.current) {
      setPreview(null)
      return
    }
    const result = await api.executeHostImport({
      previewId: preview.preview.previewId,
    })
    setPreview(null)
    notify({ key: 'host.imported', values: { count: result.updatedCount } })
  })
  return (
    <Panel title={t('host.csv')}>
      <p className="text-sm text-muted-foreground">{t('host.csvHint')}</p>
      <Field label={t('host.csvFile')}>
        <Input
          type="file"
          accept=".csv,text/csv"
          onChange={(event) => {
            const file = event.target.files?.[0]
            seq.current += 1
            setPreview(null)
            if (!file) return
            if (file.size > 524288) {
              notify({ key: 'error.csvLimit', error: true })
              return
            }
            const myFile = seq.current
            const reader = new FileReader()
            reader.onload = () => {
              if (seq.current !== myFile) return
              form.setValue('csv', String(reader.result), {
                shouldValidate: true,
              })
            }
            reader.onerror = () => notify({ key: 'error.file', error: true })
            reader.readAsText(file, 'UTF-8')
          }}
        />
      </Field>
      <form
        noValidate
        className="flex flex-col gap-3"
        onChange={() => {
          seq.current += 1
          setPreview(null)
        }}
        onSubmit={form.handleSubmit((values) => previewing.mutate(values))}
      >
        <Field
          label={t('host.csvText')}
          error={form.formState.errors.csv?.message}
        >
          <Textarea
            rows={4}
            placeholder={'hostname,set:env,remove:tier\nweb-01,prod,true'}
            {...form.register('csv')}
          />
        </Field>
        <div>
          <Button disabled={previewing.isPending}>{t('host.preview')}</Button>
        </div>
      </form>
      {preview && (
        <div className="flex flex-col gap-2 border-t pt-3">
          <p className="text-sm text-muted-foreground">
            {t('host.previewExpiry')}:{' '}
            <Time value={preview.preview.expiresAt} />
          </p>
          <DataTable<HostImportRow>
            data={preview.rows}
            columns={[
              { accessorKey: 'line', header: t('host.row') },
              { accessorKey: 'hostname', header: t('host.hostname') },
              {
                id: 'before',
                header: t('host.before'),
                cell: ({ row }) => formatLabels(row.original.before),
              },
              {
                id: 'after',
                header: t('host.after'),
                cell: ({ row }) => formatLabels(row.original.after),
              },
              {
                id: 'errors',
                header: t('host.violations'),
                cell: ({ row }) =>
                  row.original.violations
                    .map((v) => t(v.description))
                    .join('; ') || t('common.none'),
              },
            ]}
          />
          <div>
            <Button
              disabled={
                preview.preview.invalidRowCount !== '0' || applying.isPending
              }
              onClick={() => applying.mutate()}
            >
              {t('host.import')}
            </Button>
          </div>
        </div>
      )}
    </Panel>
  )
}

export function HostDetail() {
  const { hostname = '' } = useParams()
  const { t } = useTranslation()
  const query = useQuery({
    queryKey: ['host', hostname],
    queryFn: () => api.getHost({ hostname }),
  })
  return (
    <div className="flex flex-col gap-3">
      <Link
        to="/hosts"
        className="text-sm text-muted-foreground hover:text-foreground hover:no-underline"
      >
        {t('common.back')}
      </Link>
      <PageTitle title={hostname} />
      <QueryState pending={query.isPending} error={query.error} />
      {query.data && (
        <HostEditor key={query.data.host.revision} host={query.data.host} />
      )}
    </div>
  )
}

function HostEditor({ host }: { host: Host }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [deleting, setDeleting] = useState(false)
  const form = useForm<z.infer<typeof labelSchema>>({
    resolver: zodResolver(labelSchema),
    defaultValues: {
      labels: formatLabels(host.authorizationLabels),
      remove: '',
    },
  })
  const saving = useCommand(async (values: z.infer<typeof labelSchema>) => {
    await api.setHostLabels({
      targets: { hosts: { names: [host.hostname] } },
      expectedCount: '1',
      changes: {
        set: parseLabels(values.labels),
        remove: commaList(values.remove),
      },
      expectedRevisions: [{ hostId: host.hostId, revision: host.revision }],
    })
  }, 'host.labelsSaved')
  const deletion = useCommand(async () => {
    await api.deleteHost({
      hostId: host.hostId,
      expectedRevision: host.revision,
    })
    navigate('/hosts')
  }, 'host.deleted')
  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
      <Panel title={t('host.labels')}>
        {!Object.keys(host.authorizationLabels).length && (
          <p
            role="note"
            className="rounded-lg bg-secondary px-3 py-2 text-sm text-secondary-foreground"
          >
            {t('host.noLabels')}
          </p>
        )}
        <form
          noValidate
          className="flex flex-col gap-3"
          onSubmit={form.handleSubmit((values) => saving.mutate(values))}
        >
          <Field
            label={t('host.labels')}
            error={form.formState.errors.labels?.message}
          >
            <Input {...form.register('labels')} />
          </Field>
          <Field label={t('host.removeKeys')}>
            <Input {...form.register('remove')} />
          </Field>
          <div>
            <Button disabled={saving.isPending}>{t('host.saveLabels')}</Button>
          </div>
        </form>
      </Panel>
      <Panel>
        <dl className="grid grid-cols-[88px_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm">
          <dt className="text-muted-foreground">{t('host.id')}</dt>
          <dd className="min-w-0">
            <MonoId value={host.hostId} />
          </dd>
          <dt className="text-muted-foreground">{t('host.connection')}</dt>
          <dd className="min-w-0">
            <Badge variant={host.online ? 'default' : 'secondary'}>
              {t(host.online ? 'host.online' : 'host.offline')}
            </Badge>
          </dd>
          <dt className="text-muted-foreground">{t('host.reportedLabels')}</dt>
          <dd className="min-w-0 font-mono text-xs break-all">
            {formatLabels(host.reportedLabels)}
          </dd>
          <dt className="text-muted-foreground">{t('host.catalogVersion')}</dt>
          <dd className="min-w-0 break-words">{host.loadedCatalogs.map((c) => c.version).join(', ')}</dd>
          <dt className="text-muted-foreground">{t('host.agentVersion')}</dt>
          <dd className="min-w-0 break-words">{host.agentVersion}</dd>
          <dt className="text-muted-foreground">{t('host.lastSeen')}</dt>
          <dd className="min-w-0">
            <Time value={host.lastSeen} />
          </dd>
          <dt className="text-muted-foreground">{t('host.revision')}</dt>
          <dd className="min-w-0 break-words">{host.revision}</dd>
        </dl>
        <div className="pt-1">
          <Button variant="destructive" onClick={() => setDeleting(true)}>
            {t('common.delete')}
          </Button>
        </div>
      </Panel>
      {deleting && (
        <ConfirmDialog
          title={t('host.deleteTitle', { name: host.hostname })}
          description={t('host.deleteHint')}
          onClose={() => setDeleting(false)}
          onConfirm={() => deletion.mutate()}
          pending={deletion.isPending}
        />
      )}
    </div>
  )
}
