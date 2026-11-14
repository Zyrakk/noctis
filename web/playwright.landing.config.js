import { defineConfig } from '@playwright/test'
import base from './playwright.config.js'
export default defineConfig({
  ...base,
  testMatch: ['landing.spec.js', 'premium.spec.js', 'v2-panel.spec.js', 'v2-product.spec.js', 'v2-p7.spec.js'],
  workers: 2,
})
