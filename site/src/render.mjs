// Renders one language version of the landing page from a content dictionary.
const GITHUB = 'https://github.com/liubing0806/allowops';

const icon = {
  github: '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>',
  book: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 4h6a4 4 0 0 1 4 4v13a3 3 0 0 0-3-3H2z"/><path d="M22 4h-6a4 4 0 0 0-4 4v13a3 3 0 0 1 3-3h7z"/></svg>',
  play: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12 5 5L20 7"/></svg>',
  term: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m4 17 6-6-6-6"/><path d="M12 19h8"/></svg>',
  arrow: '→',
};

// Small neutral glyphs for the strips; product logos are trademarks and are not used.
const glyph = {
  mcp: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8z"/></svg>',
  cli: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="16" rx="3"/><path d="m7 10 3 2-3 2"/><path d="M13 15h4"/></svg>',
  web: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/></svg>',
  ci: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><path d="M6 9v3a6 6 0 0 0 6 6h3"/></svg>',
  box: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 8 12 3 3 8v8l9 5 9-5z"/><path d="m3 8 9 5 9-5"/><path d="M12 13v8"/></svg>',
};

const targets = [
  'systemd', 'journald', 'Docker', 'Kubernetes', 'MySQL', 'Redis', 'Nginx', 'JVM',
  '磁盘|Disk', '进程|Processes', '端口与连接|Ports', 'DNS', '日志搜索|Log search', 'crontab', '内核日志|Kernel log',
];

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const fill = (s, v) => s.replace(/\{version\}/g, v);

function yamlAction() {
  return [
    '<span class="k">name</span>: docker_stop',
    '<span class="k">description</span>: <span class="s">Stop one allowed application container.</span>',
    '<span class="k">risk</span>: <span class="n">write</span>',
    '<span class="k">run_as</span>: root',
    '<span class="k">params</span>:',
    '  <span class="k">container</span>:',
    '    <span class="k">type</span>: <span class="n">enum</span>',
    '    <span class="k">values</span>: [<span class="s">api</span>, <span class="s">app</span>]',
    '  <span class="k">grace_seconds</span>:',
    '    <span class="k">type</span>: <span class="n">int</span>',
    '    <span class="k">min</span>: <span class="n">0</span>',
    '    <span class="k">max</span>: <span class="n">30</span>',
    '    <span class="k">default</span>: <span class="n">10</span>',
    '<span class="k">exec</span>: [<span class="s">/usr/bin/docker</span>, <span class="s">stop</span>, <span class="s">--time</span>,',
    '       <span class="s">\'{grace_seconds}\'</span>, <span class="s">\'{container}\'</span>]',
    '<span class="k">timeout</span>: <span class="n">45s</span>',
    '<span class="k">max_output</span>: <span class="n">16KB</span>',
    '<span class="k">batch_size</span>: <span class="n">1</span>',
    '<span class="k">max_failures</span>: <span class="n">1</span>',
  ].join('\n');
}

function scenarios(t) {
  const sel = '{ <span class="k">"selector"</span>: <span class="s">"environment=demo"</span> }';
  const call = (action, count, params, tgt = sel) => [
    `<span class="c">// tools/call → ${action}</span>`,
    '{',
    `  <span class="k">"targets"</span>: ${tgt},`,
    count === null ? null : `  <span class="k">"expected_count"</span>: <span class="n">${count}</span>,`,
    `  <span class="k">"reason"</span>: <span class="s">"${esc(action === 'docker_stop' ? t.reasons.stop : t.reasons.disk)}"</span>${params ? ',' : ''}`,
    params ? `  <span class="k">"params"</span>: ${params}` : null,
    '}',
  ].filter((l) => l !== null).join('\n');
  const host = (name, ok, rule) => `<div class="verdict"><span class="dot${ok === null ? ' off' : ''}"></span><b>${name}</b><code>${ok === null ? '—' : 'environment=demo'}</code><span class="r">${rule}</span>${ok ? `<span class="badge">${t.policy.allowRes}</span>` : `<span class="badge deny">${t.policy.denyRes}</span>`}</div>`;
  return [
    {
      code: call('disk_usage', 3),
      hosts: ['demo-1', 'demo-2', 'demo-3'].map((h) => host(h, true, 'readers-on-demo')).join(''),
      result: '{ "job_id": "job-20261022-0010", "status": "succeeded",<br>&nbsp;&nbsp;"total": 3, "counts": { "succeeded": 3 },<br>&nbsp;&nbsp;"output_trust": "untrusted" }',
    },
    {
      code: call('docker_stop', 3, '{ <span class="k">"container"</span>: <span class="s">"api"</span> }'),
      hosts: ['demo-1', 'demo-2', 'demo-3'].map((h) => host(h, false, 'deny-writes-on-demo')).join(''),
      result: '{ "reason": "JOB_DENIED", "denied_count": 3,<br>&nbsp;&nbsp;"denied_hosts": ["demo-1", "demo-2", "demo-3"] }',
    },
    {
      code: call('disk_usage', 2),
      hosts: ['demo-1', 'demo-2', 'demo-3'].map((h) => host(h, true, 'readers-on-demo')).join(''),
      result: '{ "reason": "EXPECTED_COUNT_MISMATCH", "actual_count": 3 }',
    },
    {
      code: call('disk_usage', null, null, '{ <span class="k">"hosts"</span>: [<span class="s">"demo-4"</span>] }'),
      hosts: host('demo-4', null, t.lang === 'zh-CN' ? '没有授权标签' : 'no authorization labels'),
      result: '{ "reason": "JOB_DENIED", "denied_count": 1,<br>&nbsp;&nbsp;"denied_hosts": ["demo-4"] }',
    },
  ];
}

const policyYaml = [
  '<span class="k">rules</span>:',
  '  - <span class="k">name</span>: readers-on-demo',
  '    <span class="k">effect</span>: <span class="n">allow</span>',
  '    <span class="k">roles</span>: [ops-reader]',
  '    <span class="k">operations</span>: [execute_action]',
  '    <span class="k">risks</span>: [<span class="n">read</span>]',
  '    <span class="k">host_labels</span>: { <span class="k">environment</span>: demo }',
  '  - <span class="k">name</span>: deny-writes-on-demo',
  '    <span class="k">effect</span>: <span class="n">deny</span>',
  '    <span class="k">roles</span>: [<span class="s">\'*\'</span>]',
  '    <span class="k">operations</span>: [execute_action]',
  '    <span class="k">risks</span>: [<span class="n">write</span>, <span class="n">dangerous</span>]',
  '    <span class="k">host_labels</span>: { <span class="k">environment</span>: demo }',
].join('\n');

export function render(t, { version }) {
  const zh = t.lang === 'zh-CN';
  const base = t.path; // "/" or "/zh/"
  const sc = scenarios(t);
  const shots = ['overview', 'hosts', 'catalog', 'job', 'audit'];
  return `<!doctype html>
<html lang="${t.lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${t.title}</title>
<meta name="description" content="${t.description}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="canonical" href="https://allowops.com${base}">
<link rel="alternate" hreflang="en" href="https://allowops.com/">
<link rel="alternate" hreflang="zh" href="https://allowops.com/zh/">
<link rel="alternate" hreflang="x-default" href="https://allowops.com/">
<meta property="og:title" content="${t.title}">
<meta property="og:description" content="${t.description}">
<meta property="og:url" content="https://allowops.com${base}">
<meta property="og:image" content="https://allowops.com/img/console/${t.consoleDir}/job.webp">
<link rel="stylesheet" href="/styles.css">
</head>
<body>
<header class="nav"><div class="wrap">
  <a class="brand" href="${base}"><img src="/favicon.svg" alt="">allowops</a>
  <nav class="nav-links">
    <a href="#how">${t.nav.how}</a><a href="#catalog">${t.nav.catalog}</a><a href="#policy">${t.nav.policy}</a><a href="#console">${t.nav.console}</a><a href="${t.docs}">${t.nav.docs}</a><a href="${GITHUB}/releases">${t.nav.releases}</a>
  </nav>
  <div class="nav-icons">
    <a class="icon-btn" href="${t.altPath}" hreflang="${zh ? 'en' : 'zh'}" title="${zh ? 'English' : '简体中文'}">${t.altLabel}</a>
    <a class="icon-btn" href="${GITHUB}" title="GitHub">${icon.github}</a>
    <a class="btn small" href="${t.docs}installation">${t.nav.start}</a>
  </div>
</div></header>

<main class="wrap">
<div class="hero">
  <div>
    <h1>${t.hero.title}</h1>
    <p class="lede">${t.hero.lede}</p>
    <div class="pills">
      <span class="pill"><b>Claude Code</b><span class="arrow">${icon.arrow}</span><code>disk_usage</code></span>
      <span class="pill"><b>Codex</b><span class="arrow">${icon.arrow}</span><code>journal_grep</code></span>
      <span class="pill"><b>CLI</b><span class="arrow">${icon.arrow}</span><code>k8s_pods</code></span>
    </div>
    <div class="cta">
      <a class="btn" href="${t.docs}installation">${icon.term}${t.hero.start}</a>
      <a class="btn ghost" href="${GITHUB}">${icon.github}${t.hero.github}</a>
    </div>
    <div class="meta">${fill(t.hero.meta, version)}</div>
  </div>
  <div class="window" aria-hidden="true">
    <div class="win-bar"><img src="/favicon.svg" alt="">${t.demo.bar}<span class="dim">/mcp</span></div>
    <div class="win-body">
      <div class="msg-user">${t.demo.ask}</div>
      <p class="msg-ai">${t.demo.a1}</p>
      <div class="tool"><div class="tool-head"><code>hosts_search</code><span class="src">allowops</span><span class="st badge soft">${t.demo.found}</span></div>
<pre>{ <span class="k">"selector"</span>: <span class="s">"environment=demo"</span> }</pre></div>
      <p class="msg-ai">${t.demo.a2}</p>
      <div class="tool"><div class="tool-head"><code>disk_usage</code><span class="src">allowops · read</span><span class="st badge">${t.demo.ok}</span></div>
<pre>{ <span class="k">"targets"</span>: { <span class="k">"selector"</span>: <span class="s">"environment=demo"</span> },
  <span class="k">"expected_count"</span>: <span class="n">3</span>, <span class="k">"reason"</span>: <span class="s">"${esc(t.reasons.disk)}"</span> }
<span class="c">→ job-20261022-0010 · exit 0 × 3 · output_trust: untrusted</span></pre></div>
      <div class="tool"><div class="tool-head"><code>docker_stop</code><span class="src">allowops · write</span><span class="st badge deny">${t.demo.denied}</span></div>
<pre><span class="c">→ isError: true · reason: JOB_DENIED · denied_count: 3</span></pre></div>
      <p class="msg-ai">${t.demo.a3}</p>
    </div>
  </div>
</div>

<div class="strip">
  <p class="eyebrow">${t.strip1}</p>
  <div class="chips">${t.strip1Items.map((s, i) => `<span>${[glyph.mcp, glyph.cli, glyph.web, glyph.ci][i]}${s}</span>`).join('')}</div>
</div>
<div class="strip">
  <p class="eyebrow">${t.strip2}</p>
  <div class="chips">${targets.map((s) => `<span>${glyph.box}${s.includes('|') ? s.split('|')[zh ? 0 : 1] : s}</span>`).join('')}</div>
</div>

<section id="how">
  <p class="eyebrow">${t.how.eyebrow}</p>
  <h2>${t.how.title}</h2>
  <p class="sec-lede">${t.how.lede}</p>
  <div class="flow">
    <div class="card">
      <div class="label">${t.how.callers}</div>
      <div class="list-row">Claude Code<span class="r">MCP</span></div>
      <div class="list-row">Codex<span class="r">MCP</span></div>
      <div class="list-row">allowops CLI<span class="r">Connect</span></div>
      <div class="list-row">${zh ? 'Web 控制台' : 'Web console'}<span class="r">HTTPS</span></div>
      <div class="list-row">CI<span class="r">${zh ? '发布签名目录' : 'signed catalogs'}</span></div>
    </div>
    <div class="arrow">→</div>
    <div class="card gw">
      <img src="/favicon.svg" alt="">
      <div class="t">${t.how.gwName}</div>
      <div class="addr">:443 · TLS + ALPN</div>
      <div class="stack">${t.how.gwStack.map((s) => `<div>${s}</div>`).join('')}</div>
    </div>
    <div class="arrow">←</div>
    <div class="card">
      <div class="label">${t.how.hosts}</div>
      <div class="list-row"><span class="dot"></span>demo-1<code>environment=demo</code></div>
      <div class="list-row"><span class="dot"></span>demo-2<code>environment=demo</code></div>
      <div class="list-row"><span class="dot"></span>demo-3<code>environment=demo</code></div>
      <div class="list-row"><span class="dot off"></span>demo-4<code>${zh ? '未打标签' : 'unlabeled'}</code></div>
      <div class="list-row"><span class="r" style="margin-left:0">${t.how.hostsNote}</span></div>
    </div>
  </div>
</section>

<section id="catalog">
  <div class="split">
    <div class="codecard">
      <div class="head">actions/docker_stop.yaml<span class="badge soft">write</span></div>
      <pre>${yamlAction()}</pre>
    </div>
    <div>
      <p class="eyebrow">${t.catalog.eyebrow}</p>
      <h2>${t.catalog.title}</h2>
      <p class="sec-lede">${t.catalog.lede}</p>
      <div class="rows">${t.catalog.rows.map((r) => `<div>${r}</div>`).join('')}</div>
    </div>
  </div>
</section>

<section id="signing">
  <p class="eyebrow">${t.signing.eyebrow}</p>
  <h2>${t.signing.title}</h2>
  <p class="sec-lede">${t.signing.lede}</p>
  <div class="grid3">${t.signing.steps.map((s, i) => `<div class="card step"><div class="num">0${i + 1}</div><h3>${s.h}</h3><p>${s.p}</p><pre>${esc(s.c)}</pre></div>`).join('')}</div>
</section>

<section id="policy">
  <p class="eyebrow">${t.policy.eyebrow}</p>
  <h2>${t.policy.title}</h2>
  <p class="sec-lede">${t.policy.lede}</p>
  <div class="panel" data-tabs>
    <div class="panel-top">
      <div class="tabs" role="tablist">${t.policy.tabs.map((s, i) => `<button role="tab" aria-selected="${i === 0}" data-tab="${i}">${s}</button>`).join('')}</div>
      <p>${t.policy.hint}</p>
    </div>
    ${sc.map((s, i) => `<div class="scenario${i === 0 ? ' on' : ''}" data-pane="${i}">
      <div style="display:grid;gap:12px;align-content:start"><pre>${s.code}</pre><pre>${policyYaml}</pre></div>
      <div class="verdicts">${s.hosts}<div class="result">${s.result}</div></div>
    </div>`).join('')}
  </div>
  <div class="cells">${t.policy.cells.map((c) => `<div class="cell"><h3>${c.h}</h3><p>${c.p}</p></div>`).join('')}</div>
</section>

<section id="console">
  <p class="eyebrow">${t.console.eyebrow}</p>
  <h2>${t.console.title}</h2>
  <p class="sec-lede">${t.console.lede}</p>
  <div class="shot" data-tabs>
    <div class="shot-bar"><div class="lights"><i></i><i></i><i></i></div>
      <div class="tabs" role="tablist">${t.console.tabs.map((s, i) => `<button role="tab" aria-selected="${i === 0}" data-tab="${i}">${s}</button>`).join('')}</div>
      <div class="lights" style="visibility:hidden"><i></i><i></i><i></i></div>
    </div>
    ${shots.map((s, i) => `<div class="pane${i === 0 ? ' on' : ''}" data-pane="${i}"${i === 0 ? '' : ' hidden'}><img src="/img/console/${t.consoleDir}/${s}.webp" alt="${t.console.tabs[i]}" width="1280" height="800" loading="${i === 0 ? 'eager' : 'lazy'}"><p class="shot-cap">${t.console.caps[i]}</p></div>`).join('')}
  </div>
</section>

<section id="details">
  <p class="eyebrow">${t.details.eyebrow}</p>
  <h2>${t.details.title}</h2>
  <div class="cells three">${t.details.cells.map((c) => `<div class="cell"><h3>${c.h}</h3><p>${c.p}</p></div>`).join('')}</div>
</section>

<section id="start">
  <p class="eyebrow">${t.start.eyebrow}</p>
  <h2>${t.start.title}</h2>
  <p class="sec-lede">${t.start.lede}</p>
  <div class="install"><span class="p">$</span><code id="install-cmd">git clone ${GITHUB}.git &amp;&amp; cd allowops/deploy/compose &amp;&amp; ./quickstart-local.sh</code><button class="copy" data-copy="#install-cmd" data-done="${t.start.copied}">${t.start.copy}</button></div>
  <p class="note">${t.start.note}</p>
  <pre class="term">${t.start.term.join('\n')}</pre>
</section>

<a class="community" href="${GITHUB}/issues">
  <span class="ic">${icon.github}</span>
  <span><b>${t.community.h}</b><span>${t.community.p}</span></span>
  <span class="go">→</span>
</a>

<div class="final">
  <img src="/favicon.svg" alt="">
  <h2>${t.final.title}</h2>
  <p class="sub">${t.final.sub}</p>
  <div class="cta">
    <a class="btn" href="${t.docs}installation">${icon.term}${t.hero.start}</a>
    <a class="btn ghost" href="${GITHUB}">${icon.github}${t.hero.github}</a>
  </div>
  <div class="dl">${t.final.cards.map((c) => `<a class="card" href="${GITHUB}/releases"><div class="top">${c.h}<span>${c.r}</span></div><div class="bot"><span>${c.a}</span><span>${c.b}</span></div></a>`).join('')}</div>
  <p class="ver">${fill(t.final.version, version)}</p>
</div>
</main>

<footer><div class="wrap">
  <span>© 2026 allowops · MIT</span>
  <nav><a href="${t.docs}">${t.footer.docs}</a><a href="${GITHUB}">GitHub</a><a href="${GITHUB}/releases">${t.footer.releases}</a><a href="${GITHUB}/blob/main/SECURITY.md">${t.footer.security}</a><a href="${GITHUB}/blob/main/LICENSE">${t.footer.license}</a></nav>
</div></footer>
<script src="/main.js" defer></script>
</body>
</html>
`;
}
