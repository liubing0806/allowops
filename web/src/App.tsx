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
  useNavigate,
} from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Check, LogOut, Moon, Search, Sun } from 'lucide-react'
import { Code } from '@connectrpc/connect'
import { api, ApiError } from '@/api'
import { PageTitle, QueryState } from '@/components/console/common'
import { statusTone } from '@/components/console/tone'
import { CommandPalette } from '@/components/console/CommandPalette'
import { navigationGroups } from '@/components/console/navigation'
import { PageHeaderContext } from '@/components/console/page-header'
import { StatusDot } from '@/components/console/StatusDot'
import { Button } from '@/components/ui/button'
import { useCommand } from '@/lib/notifications'
import { NotificationProvider } from '@/components/console/NotificationProvider'
import { displayVersion, releaseNotesUrl } from '@/lib/release'
import {
  applyTheme,
  resolveTheme,
  useThemeStore,
} from '@/lib/theme-store'
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
const JobDetail = lazy(() =>
  import('@/pages/Jobs').then((module) => ({ default: module.JobDetail })),
)
const HostDetail = lazy(() =>
  import('@/pages/Hosts').then((module) => ({ default: module.HostDetail })),
)

function useDarkTheme() {
  const preference = useThemeStore((state) => state.preference)
  const setPreference = useThemeStore((state) => state.setPreference)
  const systemDark =
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: dark)').matches
  const dark = resolveTheme(preference, systemDark) === 'dark'
  return { dark, toggle: () => setPreference(dark ? 'light' : 'dark') }
}

function GatewayHealth() {
  const { t } = useTranslation()
  const status = useQuery({
    queryKey: ['systemStatus'],
    queryFn: () => api.getSystemStatus(),
    refetchInterval: 30000,
  })
  // An unreadable status is shown as unknown, never as healthy.
  const value = status.data?.status
  const tone = value ? statusTone(value) : 'neutral'
  return (
    <span className="flex min-w-0 items-center gap-1.5 text-[11px] text-muted-foreground">
      <StatusDot tone={tone} size={6} />
      <span className="truncate">
        {t('shell.gateway')} ·{' '}
        {value
          ? t(`status.${value}`)
          : status.isPending
            ? t('common.loading')
            : t('shell.gatewayUnknown')}
      </span>
    </span>
  )
}

function Layout() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const client = useQueryClient()
  const theme = useDarkTheme()
  const [slot, setSlot] = useState<HTMLElement | null>(null)
  const [palette, setPalette] = useState(false)
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
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setPalette((open) => !open)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])
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
  const user = session.data.user
  const initials = user.displayName.slice(0, 2).toUpperCase()
  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground md:flex-row">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-card focus:px-2 focus:py-1"
      >
        {t('common.skip')}
      </a>
      <aside className="flex w-full shrink-0 flex-col gap-0.5 border-b bg-sidebar px-2.5 py-3 text-sidebar-foreground md:sticky md:top-0 md:h-screen md:w-[232px] md:border-r md:border-b-0">
        <div className="flex items-start gap-2 pb-3">
          <Link
            to="/"
            className="flex min-w-0 flex-1 items-center gap-2.5 rounded-lg px-2 pt-1.5 hover:no-underline"
          >
            <span className="grid size-6 shrink-0 place-items-center rounded-[7px] bg-sidebar-primary text-sidebar-primary-foreground">
              <Check aria-hidden="true" className="size-3.5" strokeWidth={2.6} />
            </span>
            <span className="flex min-w-0 flex-col leading-tight">
              <span className="truncate text-sm font-semibold">
                {t('app.name')}
              </span>
              <span className="truncate text-[11px] text-muted-foreground">
                {t('app.subtitle')}
              </span>
              <span className="truncate font-mono text-[11px] text-muted-foreground">
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
              className="mt-2 shrink-0 rounded-full bg-accent px-1.5 py-0.5 text-[10px] leading-none font-medium text-accent-foreground hover:no-underline"
            >
              {t('app.updateAvailable')}
            </a>
          )}
        </div>
        <button
          type="button"
          onClick={() => setPalette(true)}
          className="mb-2.5 flex h-[34px] items-center gap-2 rounded-lg border bg-card pr-2 pl-2.5 text-sm text-muted-foreground shadow-[0_1px_2px_rgb(0_0_0/0.04)] hover:text-foreground"
        >
          <Search aria-hidden="true" className="size-3.5" />
          <span className="flex-1 text-left">{t('shell.search')}</span>
          <kbd className="rounded border bg-muted px-1.5 font-mono text-[11px] text-foreground-2">
            ⌘K
          </kbd>
        </button>
        <nav
          aria-label={t('nav.label')}
          className="flex flex-row flex-wrap gap-0.5 md:flex-1 md:flex-col md:flex-nowrap md:overflow-y-auto"
        >
          {navigationGroups.map((group) => (
            <div key={group.key} className="contents md:flex md:flex-col md:gap-0.5">
              <div className="hidden px-2.5 pt-3 pb-1 text-[11px] font-medium text-muted-foreground md:block">
                {t(group.key)}
              </div>
              {group.items.map(({ path, key, icon: Icon }) => (
                <NavLink
                  key={path}
                  to={path}
                  end={path === '/'}
                  className={({ isActive }) =>
                    cn(
                      'flex h-8 shrink-0 items-center gap-2.5 rounded-[7px] px-2.5 text-sm text-foreground-2 hover:bg-muted hover:text-foreground hover:no-underline',
                      isActive &&
                        'bg-sidebar-accent font-medium text-sidebar-accent-foreground shadow-[0_1px_2px_rgb(0_0_0/0.06),0_0_0_0.5px_var(--border)] hover:bg-sidebar-accent',
                    )
                  }
                >
                  <Icon size={15} strokeWidth={1.8} aria-hidden="true" className="shrink-0" />
                  <span className="truncate">{t(key)}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="mt-2 flex items-center gap-2.5 rounded-lg p-2">
          <span
            aria-hidden="true"
            className="grid size-[26px] shrink-0 place-items-center rounded-full bg-accent text-[11px] font-semibold text-accent-foreground"
          >
            {initials}
          </span>
          <span className="flex min-w-0 flex-1 flex-col leading-tight">
            {/* Opening the login page switches identity; the session is replaced on success. */}
            <Link
              to="/login"
              aria-label={t('common.currentUser')}
              title={user.displayName}
              className="truncate font-medium text-foreground hover:underline"
            >
              {user.displayName}
            </Link>
            <GatewayHealth />
          </span>
          <Button
            variant="ghost"
            size="icon-sm"
            disabled={logout.isPending}
            onClick={() => logout.mutate()}
            aria-label={t('common.logout')}
            title={t('common.logout')}
          >
            <LogOut />
          </Button>
        </div>
      </aside>
      <PageHeaderContext.Provider value={{ slot }}>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="z-10 flex min-h-[52px] md:sticky md:top-0 flex-wrap items-center gap-x-3 gap-y-2 border-b bg-background/95 px-5 py-2 backdrop-blur md:flex-nowrap md:py-0">
            <div
              ref={setSlot}
              className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-2 md:flex-nowrap"
            />
            <div className="flex items-center gap-1">
              <label className="flex items-center">
                <span className="sr-only">{t('common.language')}</span>
                <select
                  value={i18n.language}
                  onChange={(event) =>
                    void i18n.changeLanguage(event.target.value)
                  }
                  className="h-8 rounded-lg bg-transparent px-1.5 text-xs text-foreground-2 hover:bg-muted"
                >
                  <option value="zh-CN">{t('common.zh')}</option>
                  <option value="en">{t('common.en')}</option>
                </select>
              </label>
              <Button
                variant="ghost"
                size="icon"
                onClick={theme.toggle}
                aria-label={t(theme.dark ? 'shell.themeToLight' : 'shell.themeToDark')}
                title={t(theme.dark ? 'shell.themeToLight' : 'shell.themeToDark')}
                className="text-foreground-2"
              >
                {theme.dark ? <Sun /> : <Moon />}
              </Button>
            </div>
          </header>
          <main
            id="main-content"
            className="mx-auto flex w-full max-w-[1440px] min-w-0 flex-1 flex-col gap-3.5 p-3 pb-24 md:p-5 md:pb-24"
          >
            <Outlet />
          </main>
        </div>
      </PageHeaderContext.Provider>
      <CommandPalette
        open={palette}
        onOpenChange={setPalette}
        onToggleTheme={theme.toggle}
      />
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
