import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { api, type DependencyHealth, type GatewayInstance } from '@/api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DataTable,
  MonoId,
  PageTitle,
  Panel,
  QueryState,
  Status,
  Time,
} from '@/components/console/common'
import { useCommand } from '@/lib/notifications'
import { displayVersion, releaseNotesUrl } from '@/lib/release'

export default function System() {
  const { t } = useTranslation()
  const status = useQuery({
    queryKey: ['systemStatus'],
    queryFn: () => api.getSystemStatus(),
  })
  const instances = useQuery({
    queryKey: ['instances'],
    queryFn: () => api.listGatewayInstances(),
  })
  const versions = useQuery({
    queryKey: ['agentVersions'],
    queryFn: () => api.getAgentVersionDistribution(),
  })
  const refresh = useCommand(async () => {}, 'system.refreshed')
  const instanceVersions = [
    ...new Set(instances.data?.instances.map((i) => i.version) ?? []),
  ].sort()

  return (
    <div className="flex flex-col gap-3">
      <PageTitle
        title={t('nav.system')}
        description={t('system.description')}
        action={
          <Button
            variant="outline"
            size="sm"
            disabled={refresh.isPending}
            onClick={() => refresh.mutate()}
          >
            {t('system.refresh')}
          </Button>
        }
      />
      <QueryState pending={status.isPending} error={status.error} />
      {status.data && (
        <Panel title={t('system.dependencies')}>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <Status value={status.data.status} />
            <span className="text-muted-foreground">
              {t('system.observed')}: <Time value={status.data.observedAt} />
            </span>
          </div>
          <DataTable<DependencyHealth>
            data={status.data.dependencies}
            columns={[
              {
                accessorKey: 'name',
                header: t('common.name'),
                cell: ({ row }) => t(row.original.name),
              },
              {
                accessorKey: 'status',
                header: t('common.status'),
                cell: ({ row }) => <Status value={row.original.status} />,
              },
            ]}
          />
        </Panel>
      )}
      {status.data && (
        <Panel title={t('system.gateway')}>
          <dl className="grid grid-cols-[88px_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm">
            <dt className="text-muted-foreground">
              {t('system.currentVersion')}
            </dt>
            <dd className="min-w-0 break-words">
              {displayVersion(status.data.gatewayVersion)}
            </dd>
            <dt className="text-muted-foreground">{t('system.updateCheck')}</dt>
            <dd className="min-w-0">
              <Badge variant="secondary">
                {t(
                  status.data.updateCheckEnabled
                    ? 'system.updateCheckEnabled'
                    : 'system.updateCheckDisabled',
                )}
              </Badge>
            </dd>
            {status.data.updateCheckEnabled && (
              <>
                <dt className="text-muted-foreground">
                  {t('system.lastChecked')}
                </dt>
                <dd className="min-w-0">
                  <Time value={status.data.updateCheckedAt} />
                </dd>
                <dt className="text-muted-foreground">
                  {t('system.latestVersion')}
                </dt>
                <dd className="min-w-0 break-words">
                  {status.data.gatewayUpdate ? (
                    <a
                      href={releaseNotesUrl(
                        status.data.gatewayUpdate.latestVersion,
                      )}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-medium text-primary underline-offset-4 hover:underline"
                    >
                      {t('system.releaseNotes', {
                        version: displayVersion(
                          status.data.gatewayUpdate.latestVersion,
                        ),
                      })}
                    </a>
                  ) : status.data.updateCheckedAt ? (
                    t('system.upToDate')
                  ) : (
                    t('common.none')
                  )}
                </dd>
              </>
            )}
            <dt className="text-muted-foreground">{t('nav.hosts')}</dt>
            <dd className="min-w-0 break-words">
              {t('system.hostsBelow', {
                count: Number(status.data.hostsBelowGatewayVersion),
              })}
            </dd>
          </dl>
          {status.data.updateCheckEnabled && status.data.updateCheckError && (
            <p className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {t('system.checkError', { error: status.data.updateCheckError })}
            </p>
          )}
        </Panel>
      )}
      <Panel title={t('system.instances')}>
        <QueryState pending={instances.isPending} error={instances.error} />
        {instanceVersions.length > 1 && (
          <p className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {t('system.versionMismatch', {
              versions: instanceVersions.join(t('system.versionSeparator')),
            })}
          </p>
        )}
        {instances.data && (
          <DataTable<GatewayInstance>
            data={instances.data.instances}
            columns={[
              {
                accessorKey: 'instanceId',
                header: t('common.name'),
                cell: ({ row }) => <MonoId value={row.original.instanceId} />,
              },
              { accessorKey: 'version', header: t('common.version') },
              { accessorKey: 'connectedHosts', header: t('system.connected') },
              {
                accessorKey: 'lastSeen',
                header: t('host.lastSeen'),
                cell: ({ row }) => <Time value={row.original.lastSeen} />,
              },
              {
                accessorKey: 'draining',
                header: t('system.draining'),
                cell: ({ row }) => (
                  <Badge variant="secondary">
                    {t(row.original.draining ? 'policy.yes' : 'policy.no')}
                  </Badge>
                ),
              },
            ]}
          />
        )}
      </Panel>
      <Panel title={t('system.distribution')}>
        <QueryState pending={versions.isPending} error={versions.error} />
        {versions.data && (
          <DataTable
            data={versions.data.versions}
            columns={[
              { accessorKey: 'agentVersion', header: t('host.agentVersion') },
              { accessorKey: 'hostCount', header: t('common.count') },
              { accessorKey: 'onlineCount', header: t('host.onlineCount') },
            ]}
          />
        )}
      </Panel>
    </div>
  )
}
