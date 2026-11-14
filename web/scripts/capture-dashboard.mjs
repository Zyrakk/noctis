// Run with the local Vite server active: node scripts/capture-dashboard.mjs
// This renders the actual private UI against explicit synthetic fixtures.
import { chromium } from '@playwright/test'
import { panelFixture } from '../tests/panel-fixture.js'
import { readFile, writeFile } from 'node:fs/promises'
const origin = new URL(process.argv[2] || 'http://127.0.0.1:5173')
if (origin.hostname !== '127.0.0.1' || origin.protocol !== 'http:') throw new Error('Only a local synthetic preview is allowed')
const browser = await chromium.launch()
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 960 }, deviceScaleFactor: 1 })
  await panelFixture(page, { changes: true })
  await page.goto(new URL('/v2/today', origin).href)
  await page.getByText('Offer reported by one source', { exact: true }).waitFor()
  await page.evaluate(() => document.fonts.ready)
  const screenshot = await page.screenshot()
  const document = new URL('../index.html', import.meta.url)
  const html = await readFile(document, 'utf8')
  const marker = /(<img data-dashboard-capture src=")[^"]+/
  if (!marker.test(html)) throw new Error('Dashboard capture marker missing from landing')
  await writeFile(document, html.replace(marker, '$1data:image/png;base64,' + screenshot.toString('base64')))
  console.log('Embedded actual dashboard capture with synthetic data into index.html')
} finally { await browser.close() }
