import { defineConfig } from '@playwright/test'

const port = Number(process.env.NOCTIS_BUILD_TEST_PORT || 4173)
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid NOCTIS_BUILD_TEST_PORT')
const origin = `http://127.0.0.1:${port}`

export default defineConfig({
  testDir: './tests',
  testMatch: ['offline-assets.spec.js', 'landing.spec.js', 'premium.spec.js', 'v2-real.spec.js'],
  workers: 2,
  use: { baseURL: origin },
  webServer: {
    command: `npm run preview -- --host 127.0.0.1 --port ${port} --strictPort`,
    url: origin,
    reuseExistingServer: false,
  },
})
