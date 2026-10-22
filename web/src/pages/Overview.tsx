import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { api, type Job } from '@/api'
import {
  DataTable,
  MonoId,
  PageTitle,
  Panel,
  QueryState,
  Status,
  Time,
} from '@/components/console/common'
import { Card, CardContent } from '@/components/ui/card'

export default function Overview() {
  const { t } = useTranslation()
  const health = useQuery({
    queryKey: ['systemStatus'],
    queryFn: () => api.getSystemStatus(),
  })
  const jobs = useQuery({
    queryKey: ['jobs', {}],
    queryFn: () => api.listJobs(),
  })
  const status = health.data
  return (
    <div className="flex flex-col gap-3">
      <PageTitle
        title={t('nav.overview')}
        description={t('overview.description')}
      />
      <QueryState pending={health.isPending} error={health.error} />
      {status && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {[
              ['host.onlineCount', status.onlineHosts],
              ['host.offlineCount', status.offlineHosts],
              ['job.runningCount', status.runningJobs],
              ['job.failedCount', status.failedJobsLast24Hours],
            ].map(([label, count]) => (
              <Card key={label} className="metric">
                <CardContent className="flex flex-col gap-1">
                  <span className="text-xs font-medium text-muted-foreground">
                    {t(label)}
                  </span>
                  <strong className="text-2xl font-semibold tracking-tight tabular-nums">
                    {count}
                  </strong>
                </CardContent>
              </Card>
            ))}
          </div>
          <Panel title={t('overview.attention')}>
            <div className="flex flex-wrap gap-2">
              <Link
                to="/catalog"
                className="rounded-lg bg-secondary px-3 py-1.5 text-xs font-medium text-secondary-foreground hover:no-underline"
              >
                {t('overview.catalogAlert', { count: status.expiringCatalogs })}
              </Link>
              <Link
                to="/service-accounts"
                className="rounded-lg bg-secondary px-3 py-1.5 text-xs font-medium text-secondary-foreground hover:no-underline"
              >
                {t('overview.tokenAlert', {
                  count: status.expiringServiceAccountTokens,
                })}
              </Link>
            </div>
          </Panel>
        </>
      )}
      <Panel title={t('overview.recentJobs')}>
        <QueryState pending={jobs.isPending} error={jobs.error} />
        {jobs.data && (
          <DataTable<Job>
            data={jobs.data.jobs}
            columns={[
              {
                accessorKey: 'jobId',
                header: t('job.id'),
                cell: ({ row }) => (
                  <Link
                    to={`/jobs/${row.original.jobId}`}
                    className="font-medium text-primary underline-offset-4 hover:underline"
                  >
                    <MonoId value={row.original.jobId} />
                  </Link>
                ),
              },
              { accessorKey: 'action', header: t('job.action') },
              {
                accessorKey: 'status',
                header: t('common.status'),
                cell: ({ row }) => <Status value={row.original.status} />,
              },
              { accessorKey: 'totalTasks', header: t('common.count') },
              {
                accessorKey: 'createdAt',
                header: t('common.createdAt'),
                cell: ({ row }) => <Time value={row.original.createdAt} />,
              },
            ]}
          />
        )}
      </Panel>
    </div>
  )
}
