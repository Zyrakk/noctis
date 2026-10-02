import { test, expect } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'

const routes = [
  '/presentation',
  '/presentation/brief',
  '/presentation/correlation',
  '/presentation/architecture',
  '/presentation/lessons',
]

const screenshotDir = path.resolve(process.cwd(), '../docs/presentation/screenshots')

test.beforeAll(() => {
  fs.mkdirSync(screenshotDir, { recursive: true })
})

test('all presentation routes render at recording viewport', async ({ page }) => {
  const pageErrors = []
  page.on('pageerror', error => pageErrors.push(error.message))
  for (const route of routes) {
    await page.goto(route, { waitUntil: 'networkidle' })
    await expect(page.locator('.pres-shell')).toBeVisible()
    await expect(page.getByText('SYNTHETIC DEMO DATA · PRESENTATION SAFE')).toBeVisible()
    await expect(page.locator('body')).toHaveCSS('overflow-x', 'hidden')
    await expect(page.locator('.skeleton')).toHaveCount(0)
    await expect(page.locator('.pres-title')).toHaveCSS('font-size', /.+/)

    const overflow = await page.evaluate(() => ({
      body: document.body.scrollWidth - window.innerWidth,
      document: document.documentElement.scrollWidth - window.innerWidth,
    }))
    expect(overflow.body).toBeLessThanOrEqual(1)
    expect(overflow.document).toBeLessThanOrEqual(1)

    await page.screenshot({ path: path.join(screenshotDir, `${route.split('/').filter(Boolean).pop() || 'overview'}.png`), fullPage: true })
  }
  expect(pageErrors).toEqual([])
})

test('recommended navigation path has no dead links', async ({ page }) => {
  await page.goto('/presentation', { waitUntil: 'networkidle' })
  for (const route of routes.slice(1)) {
    const label = route.split('/').pop().replace('-', ' ')
    await page.getByRole('button', { name: new RegExp(label, 'i') }).first().click()
    await expect(page).toHaveURL(new RegExp(`${route}$`))
    await expect(page.locator('.pres-title')).toBeVisible()
  }
})

test('keyboard path and key demo actions work', async ({ page }) => {
  await page.goto('/presentation', { waitUntil: 'networkidle' })
  await page.keyboard.press('ArrowRight')
  await expect(page).toHaveURL(/\/presentation\/brief$/)
  await page.getByRole('button', { name: /Trace the correlation path/i }).click()
  await expect(page).toHaveURL(/\/presentation\/correlation$/)
  await page.getByRole('button', { name: /Show the real pipeline/i }).click()
  await expect(page).toHaveURL(/\/presentation\/architecture$/)
})

test('mobile layout remains readable', async ({ browser }) => {
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } })
  for (const route of routes) {
    await page.goto(route, { waitUntil: 'networkidle' })
    await expect(page.locator('.pres-shell')).toBeVisible()
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
    expect(overflow).toBeLessThanOrEqual(1)
  }
  await page.close()
})
