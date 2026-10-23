import { defineConfig, type DefaultTheme } from 'vitepress'

// GitHub Pages serves the docs under /allowops/; the allowops.com build sets /docs/.
const base = process.env.ALLOWOPS_DOCS_BASE || '/allowops/'
const github = 'https://github.com/liubing0806/allowops'

const sidebar = (p: string, t: Record<string, string>): DefaultTheme.SidebarItem[] => [
  {
    text: t.start,
    items: [
      { text: t.overview, link: `${p}/` },
      { text: t.concepts, link: `${p}/concepts` },
      { text: t.installation, link: `${p}/installation` },
      { text: t.mcp, link: `${p}/mcp` },
    ],
  },
  {
    text: t.define,
    items: [
      { text: t.catalogs, link: `${p}/catalogs` },
      { text: t.execution, link: `${p}/execution` },
      { text: t.publishing, link: `${p}/publishing` },
      { text: t.policies, link: `${p}/policies` },
      { text: t.identity, link: `${p}/identity` },
    ],
  },
  {
    text: t.operate,
    items: [
      { text: t.cli, link: `${p}/cli` },
      { text: t.audit, link: `${p}/audit` },
      { text: t.operations, link: `${p}/operations` },
      { text: t.security, link: `${p}/security` },
      { text: t.license, link: `${p}/license` },
    ],
  },
]

const en = {
  start: 'Get started', overview: 'Overview', concepts: 'Concepts', installation: 'Installation',
  mcp: 'MCP clients and tools', define: 'Define access', catalogs: 'Action catalogs',
  execution: 'Execution capabilities', publishing: 'Signing and publishing', policies: 'Policies',
  identity: 'Identity', operate: 'Operate', cli: 'CLI reference', audit: 'Audit',
  operations: 'Operations', security: 'Security', license: 'License and participation',
}
const zh = {
  start: '入门', overview: '概览', concepts: '概念', installation: '安装',
  mcp: 'MCP 客户端与工具', define: '定义访问', catalogs: '动作目录',
  execution: '执行能力', publishing: '签名与发布', policies: '策略',
  identity: '身份', operate: '运维', cli: 'CLI 参考', audit: '审计',
  operations: '运维操作', security: '安全', license: '许可与参与',
}

export default defineConfig({
  title: 'allowops',
  base,
  cleanUrls: true,
  srcExclude: ['README.md'],
  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: `${base}favicon.svg` }]],
  locales: {
    root: {
      label: 'English',
      lang: 'en-US',
      description: 'No shell. Only actions you defined.',
      themeConfig: {
        nav: [
          { text: 'Guide', link: '/concepts' },
          { text: 'CLI', link: '/cli' },
          { text: 'Security', link: '/security' },
          { text: 'allowops.com', link: 'https://allowops.com/' },
        ],
        sidebar: sidebar('', en),
      },
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      link: '/zh/',
      description: '不给 shell，只给你定义的动作。',
      themeConfig: {
        nav: [
          { text: '指南', link: '/zh/concepts' },
          { text: 'CLI', link: '/zh/cli' },
          { text: '安全', link: '/zh/security' },
          { text: '官网', link: 'https://allowops.com/zh/' },
        ],
        sidebar: sidebar('/zh', zh),
        outline: { label: '本页目录' },
        docFooter: { prev: '上一页', next: '下一页' },
        darkModeSwitchLabel: '外观',
        lightModeSwitchTitle: '切换到浅色模式',
        darkModeSwitchTitle: '切换到深色模式',
        sidebarMenuLabel: '菜单',
        returnToTopLabel: '回到顶部',
        langMenuLabel: '切换语言',
        notFound: { title: '页面不存在', quote: '这个地址没有对应的文档页面。', linkLabel: '返回文档首页', linkText: '返回文档首页' },
      },
    },
  },
  themeConfig: {
    logo: '/favicon.svg',
    search: {
      provider: 'local',
      options: {
        locales: {
          zh: {
            translations: {
              button: { buttonText: '搜索', buttonAriaLabel: '搜索' },
              modal: {
                noResultsText: '没有结果',
                resetButtonTitle: '清除',
                displayDetails: '显示详情',
                backButtonTitle: '返回',
                footer: { selectText: '选择', navigateText: '切换', closeText: '关闭' },
              },
            },
          },
        },
      },
    },
    socialLinks: [{ icon: 'github', link: github }],
  },
})
