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
  type LucideIcon,
} from 'lucide-react'

export interface NavItem {
  path: string
  key: string
  icon: LucideIcon
}

// README §3.5: run / govern / manage.
export const navigationGroups: { key: string; items: NavItem[] }[] = [
  {
    key: 'shell.groupRun',
    items: [
      { path: '/', key: 'nav.overview', icon: LayoutDashboard },
      { path: '/hosts', key: 'nav.hosts', icon: Server },
      { path: '/jobs', key: 'nav.jobs', icon: ClipboardList },
      { path: '/audit', key: 'nav.audit', icon: ScrollText },
    ],
  },
  {
    key: 'shell.groupGovern',
    items: [
      { path: '/catalog', key: 'nav.catalog', icon: BookOpen },
      { path: '/policies', key: 'nav.policies', icon: ListChecks },
      { path: '/service-accounts', key: 'nav.accounts', icon: ShieldCheck },
      { path: '/join-tokens', key: 'nav.joinTokens', icon: KeyRound },
    ],
  },
  {
    key: 'shell.groupManage',
    items: [
      { path: '/users', key: 'nav.users', icon: Users },
      { path: '/system', key: 'nav.system', icon: Settings },
    ],
  },
]

export const navigation = navigationGroups.flatMap((group) => group.items)
