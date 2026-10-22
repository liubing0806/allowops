import { fileURLToPath, URL } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    {
      name: 'exclude-test-fixtures',
      generateBundle(_options, bundle) {
        for (const chunk of Object.values(bundle)) {
          if (
            chunk.type === 'chunk' &&
            Object.keys(chunk.modules).some(
              (id) =>
                id.includes('/src/test/') || /\.test\.[cm]?[jt]sx?$/.test(id),
            )
          ) {
            this.error('Production console references a test module')
          }
        }
      },
    },
  ],
  build: {
    outDir: '../internal/gateway/console/dist',
    emptyOutDir: true,
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
  },
})
