// Builds the static site into dist/: the landing page in each language, assets,
// and (with --docs) the VitePress documentation under /docs/.
import { cpSync, mkdirSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { render } from './src/render.mjs';

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, 'dist');
const version = process.env.ALLOWOPS_SITE_VERSION || 'v0.1.0';
const langs = process.env.ALLOWOPS_SITE_LANGS?.split(',') || ['zh', 'en'];

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });
cpSync(join(root, 'public'), dist, { recursive: true });
cpSync(join(root, 'src/styles.css'), join(dist, 'styles.css'));
cpSync(join(root, 'src/main.js'), join(dist, 'main.js'));

for (const lang of langs) {
  const file = join(root, 'src/content', `${lang}.mjs`);
  if (!existsSync(file)) continue;
  const t = (await import(file)).default;
  const out = join(dist, t.path, 'index.html');
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, render(t, { version }));
  console.log('page', t.path);
}

if (process.argv.includes('--docs')) {
  const docs = join(root, '../website');
  execFileSync('pnpm', ['exec', 'vitepress', 'build', '.', '--base', '/docs/', '--outDir', join(dist, 'docs')], { cwd: docs, stdio: 'inherit' });
}
