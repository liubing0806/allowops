import { lazy, Suspense, useEffect, useState } from 'react'
import {
  QueryClient,
  QueryClientProvider,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import {
  BrowserRouter,
  Link,
  NavLink,
  Outlet,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  BookOpen,
  ClipboardList,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  ScrollText,
  Server,
  Settings,
  ShieldCheck,
  Users,
} from 'lucide-react'
import { Code } from '@connectrpc/connect'
import { api, ApiError } from '@/api'
import { PageTitle, QueryState } from '@/components/console/common'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { useCommand } from '@/lib/notifications'
import { NotificationProvider } from '@/components/console/NotificationProvider'
import { displayVersion, releaseNotesUrl } from '@/lib/release'
import { applyTheme, useThemeStore } from '@/lib/theme-store'
import { cn } from '@/lib/utils'
const Login = lazy(() => import('@/pages/Login'))
const Overview = lazy(() => import('@/pages/Overview'))
const Hosts = lazy(() => import('@/pages/Hosts'))
const JoinTokens = lazy(() => import('@/pages/JoinTokens'))
const Catalog = lazy(() => import('@/pages/Catalog'))
const Policies = lazy(() => import('@/pages/Policies'))
const ServiceAccounts = lazy(() => import('@/pages/ServiceAccounts'))
const Jobs = lazy(() => import('@/pages/Jobs'))
const Audit = lazy(() => import('@/pages/Audit'))
const UsersPage = lazy(() => import('@/pages/Users'))
const System = lazy(() => import('@/pages/System'))
const HostDetail = lazy(() =>
  import('@/pages/Hosts').then((module) => ({ default: module.HostDetail })),
)
const JobDetail = lazy(() =>
  import('@/pages/Jobs').then((module) => ({ default: module.JobDetail })),
)
const navigation = [
  { path: '/', key: 'nav.overview', icon: LayoutDashboard },
  { path: '/hosts', key: 'nav.hosts', icon: Server },
  { path: '/join-tokens', key: 'nav.joinTokens', icon: KeyRound },
  { path: '/catalog', key: 'nav.catalog', icon: BookOpen },
  { path: '/policies', key: 'nav.policies', icon: ListChecks },
  { path: '/service-accounts', key: 'nav.accounts', icon: ShieldCheck },
  { path: '/jobs', key: 'nav.jobs', icon: ClipboardList },
  { path: '/audit', key: 'nav.audit', icon: ScrollText },
  { path: '/users', key: 'nav.users', icon: Users },
  { path: '/system', key: 'nav.system', icon: Settings },
]
function Layout() {
  const { t, i18n } = useTranslation()
  const location = useLocation()
  const navigate = useNavigate()
  const client = useQueryClient()
  const logout = useCommand(async () => {
    await api.logout()
    client.clear()
    navigate('/login')
  })
  const session = useQuery({
    queryKey: ['session'],
    queryFn: () => api.getCurrentSession(),
    // The update notice comes with the session; a release found later must
    // appear without a reload.
    refetchInterval: 10 * 60 * 1000,
  })
  if (
    session.error instanceof ApiError &&
    session.error.code === Code.Unauthenticated
  )
    return <Navigate to="/login" replace />
  if (!session.data)
    return (
      <div className="mx-auto w-full max-w-5xl p-4">
        <QueryState pending={session.isPending} error={session.error} />
      </div>
    )
  const current =
    navigation.find(
      (item) => item.path !== '/' && location.pathname.startsWith(item.path),
    ) ?? navigation[0]
  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground md:flex-row">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-card focus:px-2 focus:py-1"
      >
        {t('common.skip')}
      </a>
      <aside className="flex w-full shrink-0 flex-col border-b bg-sidebar text-sidebar-foreground md:sticky md:top-0 md:h-screen md:w-52 md:border-r md:border-b-0">
        <div className="flex h-12 items-center gap-2 px-3">
          <Link
            to="/"
            className="flex min-w-0 flex-1 items-center gap-2 rounded-md px-1 py-1 hover:no-underline"
          >
            <span className="grid size-6 shrink-0 place-items-center rounded-md bg-sidebar-primary text-sidebar-primary-foreground">
              <ShieldCheck aria-hidden="true" className="size-4" />
            </span>
            <span className="min-w-0 leading-tight">
              <span className="block truncate text-sm font-semibold">
                {t('app.name')}
              </span>
              <span className="block truncate text-[11px] text-muted-foreground">
                {t('app.subtitle')}
              </span>
              <span className="block truncate text-[11px] text-muted-foreground">
                {displayVersion(session.data.gatewayVersion)}
              </span>
            </span>
          </Link>
          {session.data.gatewayUpdate && (
            <a
              href={releaseNotesUrl(session.data.gatewayUpdate.latestVersion)}
              target="_blank"
              rel="noopener noreferrer"
              aria-label={t('app.updateAvailableLabel', {
                version: session.data.gatewayUpdate.latestVersion,
              })}
              className="shrink-0 self-end mb-1 rounded-full bg-primary/10 px-1.5 py-0.5 text-[10px] leading-none font-medium text-primary hover:bg-primary/15 hover:no-underline"
            >
              {t('app.updateAvailable')}
            </a>
          )}
        </div>
        <Separator />
        <nav aria-label={t('nav.label')} className="flex flex-row flex-wrap gap-0.5 p-2 md:flex-1 md:flex-col md:flex-nowrap md:overflow-y-auto">
          {navigation.map(({ path, key, icon: Icon }) => (
            <NavLink
              key={path}
              to={path}
              end={path === '/'}
              className={({ isActive }) =>
                cn(
                  'flex h-8 shrink-0 items-center gap-2 rounded-lg px-2 text-sm text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground hover:no-underline',
                  isActive &&
                    'bg-sidebar-accent font-medium text-sidebar-accent-foreground',
                )
              }
            >
              <Icon size={16} aria-hidden="true" className="shrink-0" />
              <span className="truncate">{t(key)}</span>
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex min-h-12 flex-wrap items-center justify-between gap-x-3 gap-y-2 border-b bg-background/95 px-4 py-2 backdrop-blur md:h-12 md:flex-nowrap md:py-0">
          <span className="flex min-w-0 items-center gap-1.5 text-sm">
            <span className="hidden text-muted-foreground sm:inline">
              {t('app.name')}
            </span>
            <span aria-hidden="true" className="hidden text-muted-foreground sm:inline">
              /
            </span>
            <b className="truncate font-semibold">{t(current.key)}</b>
          </span>
          <div className="flex flex-wrap items-center gap-1.5">
            <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <span className="hidden md:inline">{t('common.language')}</span>
              <select
                value={i18n.language}
                onChange={(event) =>
                  void i18n.changeLanguage(event.target.value)
                }
                className="h-8 rounded-lg border border-input bg-background px-2 text-xs"
              >
                <option value="zh-CN">{t('common.zh')}</option>
                <option value="en">{t('common.en')}</option>
              </select>
            </label>
            <Link
              className="flex h-8 items-center gap-1.5 rounded-full bg-muted px-2 py-0 text-xs font-medium hover:bg-accent hover:no-underline"
              to="/login"
              aria-label={t('common.currentUser')}
            >
              <span
                aria-hidden="true"
                className="grid size-5 place-items-center rounded-full bg-primary text-[10px] font-semibold text-primary-foreground"
              >
                {session.data?.user.displayName.slice(0, 1).toUpperCase()}
              </span>
              <span className="hidden max-w-28 truncate lg:inline">
                {session.data?.user.displayName}
              </span>
            </Link>
            <Button
              variant="ghost"
              size="sm"
              disabled={logout.isPending}
              onClick={() => logout.mutate()}
            >
              {t('common.logout')}
            </Button>
          </div>
        </header>
        <main id="main-content" className="mx-auto flex w-full max-w-6xl min-w-0 flex-1 flex-col gap-3 p-3 md:p-4">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
function NotFound() {
  const { t } = useTranslation()
  return (
    <>
      <PageTitle title={t('notFound.title')} />
      <Link to="/">{t('notFound.back')}</Link>
    </>
  )
}
export default function App() {
  const { i18n } = useTranslation()
  const preference = useThemeStore((state) => state.preference)
  useEffect(() => {
    applyTheme(preference)
    if (
      typeof window === 'undefined' ||
      typeof window.matchMedia !== 'function' ||
      preference !== 'system'
    )
      return
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const listener = () => applyTheme('system')
    media.addEventListener('change', listener)
    return () => media.removeEventListener('change', listener)
  }, [preference])
  useEffect(() => {
    document.documentElement.lang = i18n.language
  }, [i18n.language])
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: 30000,
            refetchOnWindowFocus: false,
          },
          mutations: { retry: false },
        },
      }),
  )
  return (
    <QueryClientProvider client={client}>
      <NotificationProvider>
        <BrowserRouter>
          <Suspense fallback={<QueryState pending />}>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route element={<Layout />}>
                <Route index element={<Overview />} />
                <Route path="hosts" element={<Hosts />} />
                <Route path="hosts/:hostname" element={<HostDetail />} />
                <Route path="join-tokens" element={<JoinTokens />} />
                <Route path="catalog" element={<Catalog />} />
                <Route path="policies" element={<Policies />} />
                <Route path="service-accounts" element={<ServiceAccounts />} />
                <Route path="jobs" element={<Jobs />} />
                <Route path="jobs/:jobId" element={<JobDetail />} />
                <Route path="audit" element={<Audit />} />
                <Route path="users" element={<UsersPage />} />
                <Route path="system" element={<System />} />
                <Route path="*" element={<NotFound />} />
              </Route>
            </Routes>
          </Suspense>
        </BrowserRouter>
      </NotificationProvider>
    </QueryClientProvider>
  )
}
