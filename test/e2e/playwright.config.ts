import { defineConfig, devices } from '@playwright/test'

if (!process.env.ALLOWOPS_E2E_URL || !process.env.ALLOWOPS_E2E_ARTIFACTS) {
  throw new Error('Run make e2e to start the isolated local environment')
}

export default defineConfig({
  testDir: '.',
  testMatch: '*.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  outputDir: `${process.env.ALLOWOPS_E2E_ARTIFACTS}/results`,
  reporter: [
    ['list'],
    ['html', { outputFolder: `${process.env.ALLOWOPS_E2E_ARTIFACTS}/report`, open: 'never' }],
  ],
  use: {
    ...devices['Desktop Chrome'],
    viewport: { width: 1440, height: 1000 },
    baseURL: process.env.ALLOWOPS_E2E_URL,
    // The runner checks the generated CA with the gateway health CLI.
    ignoreHTTPSErrors: true,
    // Network traces and storage-state files would contain local credentials.
    trace: 'off',
    video: 'off',
    screenshot: 'off',
  },
})
