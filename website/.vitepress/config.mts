import { defineConfig } from 'vitepress'

export default defineConfig({
  lang: 'en-US',
  title: 'allowops',
  description: 'No shell. Only actions you defined.',
  base: '/allowops/',
  cleanUrls: true,
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/concepts' },
      { text: 'CLI', link: '/cli' },
      { text: 'Security', link: '/security' },
    ],
    sidebar: [
      {
        text: 'Get started',
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Concepts', link: '/concepts' },
          { text: 'Installation', link: '/installation' },
          { text: 'MCP clients and tools', link: '/mcp' },
        ],
      },
      {
        text: 'Define access',
        items: [
          { text: 'Action catalogs', link: '/catalogs' },
          { text: 'Execution capabilities', link: '/execution' },
          { text: 'Signing and publishing', link: '/publishing' },
          { text: 'Policies', link: '/policies' },
          { text: 'Identity', link: '/identity' },
        ],
      },
      {
        text: 'Operate',
        items: [
          { text: 'CLI reference', link: '/cli' },
          { text: 'Audit', link: '/audit' },
          { text: 'Operations', link: '/operations' },
          { text: 'Security', link: '/security' },
          { text: 'License and participation', link: '/license' },
        ],
      },
    ],
    search: { provider: 'local' },
    socialLinks: [{ icon: 'github', link: 'https://github.com/liubing0806/allowops' }],
  },
})
