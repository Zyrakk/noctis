import { test, expect } from '@playwright/test'

for (const width of [320, 353, 390, 552, 768, 1160, 1280, 1920]) {
  test(`landing at ${width}px: independent, readable and navigable`, async ({ page }) => {
    await page.setViewportSize({ width, height: 800 })
    const privateRequests = [], errors = []
    page.on('request', r => { if (new URL(r.url()).pathname.startsWith('/api/')) privateRequests.push(r.url()) })
    page.on('pageerror', e => errors.push(e.message))
    await page.goto('/', { waitUntil: 'domcontentloaded' })
    await expect(page.locator('html')).toHaveAttribute('lang', 'en')
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('From noiseto evidence.')
    await expect(page.locator('html')).not.toHaveClass(/anim/, { timeout: 5000 })
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
    await expect(page.locator('h1 .ln')).toHaveCount(2)
    expect(await page.locator('.left-panel').evaluate(panel => {
      const style = getComputedStyle(panel)
      const available = panel.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight)
      return [...panel.querySelectorAll('.ln-i')].every(line => {
        const range = document.createRange(); range.selectNodeContents(line)
        return range.getBoundingClientRect().width <= available + 1
      })
    })).toBe(true)
    if (width >= 1024) await expect(page.locator('.right-panel')).toBeVisible()
    else await expect(page.locator('.right-panel')).toBeHidden()
    for (const brand of await page.getByRole('link', { name: 'Noctis, home' }).all()) await expect(brand).toHaveAttribute('href', '/')
    expect(await page.locator('.dashboard-frame img').evaluate(el => el.complete && el.naturalWidth === 1440)).toBe(true)
    const before = await page.locator('.dashboard-frame').evaluate(el => getComputedStyle(el).transform)
    await page.locator('.dashboard-frame').evaluate(frame => scrollTo(0, scrollY + frame.getBoundingClientRect().top - innerHeight * .3))
    await expect.poll(() => page.locator('.dashboard-frame').evaluate(el => getComputedStyle(el).transform)).not.toBe(before)
    {
      await page.evaluate(() => scrollTo(0, 0))
      const burger = page.locator('#burger')
      await burger.click()
      await expect(burger).toHaveAttribute('aria-expanded', 'true')
      await expect(page.getByRole('navigation', { name: 'Noctis menu' })).toBeVisible()
      await page.keyboard.press('Escape')
      await expect(burger).toBeFocused()
      await expect(burger).toHaveAttribute('aria-expanded', 'false')
    }
    expect(await page.locator('script[src*="src/main"], script[src*="assets/app"]').count()).toBe(0)
    expect(privateRequests).toEqual([])
    expect(errors).toEqual([])
  })
}
test('reduced motion holds the first frame and still permits scrolling', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.goto('/', { waitUntil: 'domcontentloaded' })
  await expect(page.locator('html')).not.toHaveClass(/anim/)
  expect(await page.locator('video').evaluateAll(videos => videos.every(v => v.paused && v.currentTime === 0))).toBe(true)
  await expect(page.locator('.dashboard-frame')).toHaveCSS('transform', 'none')
  await expect(page.locator('#motionToggle')).toBeHidden()
  await page.getByRole('link', { name: 'Explore Noctis', exact: true }).click()
  await expect(page.locator('.dashboard-frame img')).toBeInViewport()
})
test('private login remains a separate document', async ({ page }) => {
  await page.route('**/api/v2/auth/session', r => r.fulfill({ status: 401, json: { error: { message: 'Sin sesión' } } }))
  await page.goto('/v2/login')
  await expect(page.getByLabel('Username', { exact: true })).toBeVisible()
  await expect(page.getByLabel('Password', { exact: true })).toBeVisible()
  await expect(page.locator('video')).toHaveCount(0)
})
test('blocked external resources keep the content and real dashboard available', async ({ page, baseURL }) => {
  await page.route('**/*', route => {
    const url = new URL(route.request().url())
    return url.origin !== baseURL && !['data:', 'blob:'].includes(url.protocol) ? route.abort() : route.continue()
  })
  await page.goto('/', { waitUntil: 'domcontentloaded' })
  await expect(page.locator('html')).not.toHaveClass(/anim/, { timeout: 5000 })
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  expect(await page.locator('.dashboard-frame img').evaluate(el => el.complete && el.naturalWidth > 0)).toBe(true)
})
