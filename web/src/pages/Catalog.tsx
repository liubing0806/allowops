import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  api,
  fromBase64,
  type ActionDefinition,
  type ActionSummary,
  type CatalogVersion,
} from '@/api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import {
  DataTable,
  Dialog,
  MonoId,
  PageTitle,
  Panel,
  QueryState,
  Time,
} from '@/components/console/common'

export default function Catalog() {
  const { t } = useTranslation()
  const catalogs = useQuery({
    queryKey: ['catalogs'],
    queryFn: () => api.listCatalogs(),
  })
  const current = catalogs.data?.catalogs.find((c) => c.current)
  const [version, setVersion] = useState<CatalogVersion['catalog'] | null>(null)
  const selected =
    catalogs.data?.catalogs.find(
      (c) =>
        c.catalog.version === version?.version &&
        c.catalog.catalogId === version.catalogId,
    ) ?? current
  const actions = useQuery({
    queryKey: ['actions', selected?.catalog],
    queryFn: () => api.listActions({ catalog: selected!.catalog }),
    enabled: !!selected,
  })
  const distribution = useQuery({
    queryKey: ['catalogDistribution', selected?.catalog.catalogId],
    queryFn: () =>
      api.getCatalogDistribution({ catalogId: selected!.catalog.catalogId }),
    enabled: !!selected,
  })
  const [action, setAction] = useState<string | null>(null)
  const [now, setNow] = useState(Date.now)
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 60000)
    return () => window.clearInterval(timer)
  }, [])
  const hours = selected
    ? Math.max(0, Math.floor((Date.parse(selected.expiresAt) - now) / 3600000))
    : 0

  return (
    <div className="flex flex-col gap-3">
      <PageTitle
        title={t('nav.catalog')}
        description={t('catalog.description')}
      />
      <QueryState pending={catalogs.isPending} error={catalogs.error} />
      {selected && (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Card>
              <CardHeader>
                <span className="text-xs font-medium text-muted-foreground">
                  {t(selected.current ? 'catalog.current' : 'common.history')}
                </span>
              </CardHeader>
              <CardContent className="flex flex-col gap-1">
                <strong className="text-lg font-semibold tracking-tight">
                  {selected.catalog.version}
                </strong>
                <p className="font-mono text-xs break-all">
                  <MonoId value={selected.catalog.catalogId} /> /{' '}
                  {t('catalog.schema')} {selected.schemaVersion}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <span className="text-xs font-medium text-muted-foreground">
                  {t('catalog.countdown')}
                </span>
              </CardHeader>
              <CardContent className="flex flex-col gap-1">
                <strong className="text-lg font-semibold tracking-tight">
                  {Date.parse(selected.expiresAt) <= now
                    ? t('common.expired')
                    : t('catalog.remaining', {
                        days: Math.floor(hours / 24),
                        hours: hours % 24,
                      })}
                </strong>
                <span className="text-xs text-muted-foreground">
                  <Time value={selected.expiresAt} />
                </span>
              </CardContent>
            </Card>
          </div>
          {hours <= 336 && (
            <p
              role="note"
              className="rounded-lg bg-secondary px-3 py-2 text-sm text-secondary-foreground"
            >
              {t('catalog.expiryWarning')}
            </p>
          )}
          <Panel title={t('catalog.actions')}>
            <QueryState pending={actions.isPending} error={actions.error} />
            {actions.data && (
              <DataTable<ActionSummary>
                data={actions.data.actions}
                columns={[
                  {
                    accessorKey: 'name',
                    header: t('common.name'),
                    cell: ({ row }) => (
                      <Button
                        variant="link"
                        size="sm"
                        className="h-auto p-0"
                        onClick={() => setAction(row.original.name)}
                      >
                        {row.original.name}
                      </Button>
                    ),
                  },
                  {
                    accessorKey: 'description',
                    header: t('common.description'),
                    cell: ({ row }) => t(row.original.description),
                  },
                  {
                    accessorKey: 'risk',
                    header: t('catalog.risk'),
                    cell: ({ row }) => (
                      <Badge variant="secondary">
                        {t(`risk.${row.original.risk}`)}
                      </Badge>
                    ),
                  },
                ]}
              />
            )}
          </Panel>
        </>
      )}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Panel title={t('common.history')}>
          {catalogs.data && (
            <DataTable<CatalogVersion>
              data={catalogs.data.catalogs}
              columns={[
                {
                  id: 'version',
                  header: t('common.version'),
                  cell: ({ row }) => (
                    <Button
                      variant="link"
                      size="sm"
                      className="h-auto p-0"
                      onClick={() => setVersion(row.original.catalog)}
                    >
                      {row.original.catalog.version}
                    </Button>
                  ),
                },
                {
                  accessorKey: 'createdAt',
                  header: t('common.createdAt'),
                  cell: ({ row }) => <Time value={row.original.createdAt} />,
                },
                {
                  accessorKey: 'gitCommit',
                  header: t('catalog.commit'),
                  cell: ({ row }) => (
                    <MonoId value={row.original.gitCommit} />
                  ),
                },
              ]}
            />
          )}
        </Panel>
        <Panel title={t('catalog.distribution')}>
          <QueryState
            pending={distribution.isPending}
            error={distribution.error}
          />
          {distribution.data && (
            <>
              <DataTable
                data={distribution.data.versions}
                columns={[
                  {
                    id: 'version',
                    header: t('common.version'),
                    cell: ({ row }) => row.original.catalog.version,
                  },
                  { accessorKey: 'hostCount', header: t('common.count') },
                ]}
              />
              <p className="text-xs text-muted-foreground">
                {t('catalog.notLoaded')}: {distribution.data.notLoadedHostCount}
              </p>
            </>
          )}
        </Panel>
      </div>
      {action && selected && (
        <ActionDetail
          action={action}
          catalog={selected.catalog}
          onClose={() => setAction(null)}
        />
      )}
    </div>
  )
}

function ActionDetail({
  action,
  catalog,
  onClose,
}: {
  action: string
  catalog: CatalogVersion['catalog']
  onClose: () => void
}) {
  const { t } = useTranslation()
  const query = useQuery({
    queryKey: ['action', catalog, action],
    queryFn: () => api.getAction({ catalog, action }),
  })
  const definition = query.data
    ? (JSON.parse(fromBase64(query.data.definitionJson)) as ActionDefinition)
    : null

  return (
    <Dialog title={action} onClose={onClose}>
      <QueryState pending={query.isPending} error={query.error} />
      {definition && query.data && (
        <div className="flex min-w-0 flex-col gap-3">
          <p className="text-sm">{t(query.data.action.description)}</p>
          <div>
            <Badge variant="secondary">
              {t(`risk.${query.data.action.risk}`)}
            </Badge>
          </div>
          <h3 className="text-xs font-semibold text-muted-foreground">
            {t('catalog.params')}
          </h3>
          <DataTable
            data={Object.entries(definition.params ?? {}).map(
              ([name, { type, description, ...constraints }]) => ({
                name,
                type,
                description,
                constraints,
              }),
            )}
            columns={[
              { accessorKey: 'name', header: t('common.name') },
              {
                accessorKey: 'description',
                header: t('common.description'),
                cell: ({ row }) => t(row.original.description),
              },
              { accessorKey: 'type', header: t('catalog.paramType') },
              {
                id: 'constraints',
                header: t('catalog.constraints'),
                cell: ({ row }) => JSON.stringify(row.original.constraints),
              },
            ]}
          />
          <h3 className="text-xs font-semibold text-muted-foreground">
            {t('catalog.command')}
          </h3>
          <pre className="overflow-x-auto rounded-lg bg-muted p-3 font-mono text-xs break-all whitespace-pre-wrap">
            {definition.exec
              ? definition.exec
                  .map((arg) =>
                    typeof arg === 'string' ? arg : JSON.stringify(arg),
                  )
                  .join(' ')
              : JSON.stringify(
                  {
                    steps: definition.steps,
                    on_error: definition.on_error,
                    script: definition.script,
                    args: definition.args,
                    builtin: definition.builtin,
                    builtin_config: definition.builtin_config,
                    exec_fallbacks: definition.exec_fallbacks,
                    allow_interpreter: definition.allow_interpreter,
                  },
                  null,
                  2,
                )}
          </pre>
          <dl className="grid grid-cols-[88px_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm">
            <dt className="text-muted-foreground">{t('catalog.runAs')}</dt>
            <dd className="min-w-0 break-words">
              {definition.run_as ?? 'allowops'}
            </dd>
            <dt className="text-muted-foreground">{t('catalog.timeout')}</dt>
            <dd className="min-w-0 break-words">{definition.timeout}</dd>
            <dt className="text-muted-foreground">{t('catalog.maxOutput')}</dt>
            <dd className="min-w-0 break-words">
              {typeof definition.max_output === 'number'
                ? `${definition.max_output} B`
                : definition.max_output}
            </dd>
            <dt className="text-muted-foreground">{t('catalog.redact')}</dt>
            <dd className="min-w-0 break-words">
              {definition.redact
                ? (definition.redact.builtin?.join(', ') ??
                  JSON.stringify(definition.redact))
                : t('catalog.defaultRedact')}
              {definition.redact?.custom && (
                <pre className="mt-2 overflow-x-auto rounded-lg bg-muted p-3 font-mono text-xs break-all whitespace-pre-wrap">
                  {JSON.stringify(definition.redact.custom, null, 2)}
                </pre>
              )}
            </dd>
          </dl>
        </div>
      )}
    </Dialog>
  )
}
