import { test, expect } from '@playwright/test'

test('compiled app renders with third-party requests blocked', async ({ page, baseURL }) => {
  const external = []
  const failures = []
  page.on('pageerror', error => failures.push(error.message))
  await page.route('**/*', route => {
    const url = new URL(route.request().url())
    if (url.origin !== baseURL && !['data:', 'blob:'].includes(url.protocol)) {
      external.push(url.href)
      return route.abort()
    }
    return route.continue()
  })
  for (const path of ['/login', '/v2/login', '/presentation']) {
    await page.goto(path, { waitUntil: 'networkidle' })
    await expect(page.locator('#root')).not.toBeEmpty()
    await page.evaluate(() => document.fonts.ready)
    expect(await page.evaluate(() => document.fonts.check('400 16px "Fira Sans"'))).toBe(true)
    await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(10, 10, 15)')
    if (path.endsWith('/login')) {
      await expect(page.locator('input[type="password"]')).toBeVisible()
      expect(await page.locator('input[type="password"]').evaluate(element => getComputedStyle(element).borderRadius)).not.toBe('0px')
    }
    if (path === '/presentation') await expect(page.locator('.pres-shell')).toBeVisible()
  }
  expect(external).toEqual([])
  expect(failures).toEqual([])
})
