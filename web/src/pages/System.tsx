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
      <Panel title={t('system.instances')}>
        <QueryState pending={instances.isPending} error={instances.error} />
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
