import {test,expect} from '@playwright/test'
import {panelFixture,evidence} from './panel-fixture.js'
import fs from 'node:fs/promises'
import path from 'node:path'
const out=process.env.NOCTIS_PANEL_ARTIFACTS||path.resolve('test-results/panel-captures')
const review=path.resolve('../.impeccable/review')
async function noOverflow(page){expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true)}
for(const [size,width,height] of [['desktop',1440,1000],['mobile',390,844]]) {
  test(`${size}: composition, focus, fourteen functions and evidence`,async({page})=>{
    const errors=[];page.on('pageerror',e=>errors.push(e.message))
    await page.setViewportSize({width,height});await panelFixture(page)
    await fs.mkdir(out,{recursive:true});await fs.mkdir(review,{recursive:true})
    await page.goto('/v2/today');await expect(page.getByText('No material changes',{exact:true})).toBeVisible()
    await page.evaluate(()=>document.fonts.ready);await noOverflow(page)
    await page.keyboard.press('Tab');await expect(page.getByRole('button',{name:'Sign out',exact:true})).toBeFocused()
    expect(await page.getByRole('button',{name:'Sign out',exact:true}).evaluate(el=>getComputedStyle(el).outlineWidth)).toBe('3px')
    await page.getByRole('heading',{name:'Today',exact:true}).click()
    await page.screenshot({path:`${out}/after-${size}.png`,fullPage:true});await page.screenshot({path:`${review}/${size}.png`,fullPage:true})
    await expect(page.locator('time')).toHaveAttribute('datetime','2026-10-20T12:00:00Z')
    for(const [route,heading] of [['sources','Sources'],['system','System']]){
      await page.getByRole('link',{name:heading,exact:true}).click();await expect(page.getByRole('heading',{name:heading,exact:true})).toBeVisible()
      if(route==='system'){
        await expect(page.locator('.v2-ai-function')).toHaveCount(14)
        await expect(page.getByRole('navigation',{name:'Intelligence functions'}).getByRole('link')).toHaveCount(14)
        await expect(page.getByRole('button',{name:'Validate without inference'})).toBeVisible()
      }
      await noOverflow(page);await page.screenshot({path:`${out}/after-${size}-${route}.png`,fullPage:false})
      if(route==='system'){
        await page.locator('.v2-ai-function-directory').scrollIntoViewIfNeeded();await page.screenshot({path:`${out}/after-${size}-ai-index.png`})
        expect(await page.getByRole('navigation',{name:'Intelligence functions'}).evaluate(el=>getComputedStyle(el).display)).toBe('grid')
        await page.getByRole('link',{name:/case.summarize/}).click();await expect(page.locator('[id="ai-case.summarize"]')).toBeInViewport();await expect(page.locator('[id="ai-case.summarize"]')).toBeFocused();await noOverflow(page)
        if(size==='mobile'){
          for(const name of ['Save configuration','Validate without inference','Reload configuration'])await expect(page.getByRole('button',{name,exact:true})).toBeInViewport({ratio:1})
          const model=page.locator('[id="ai-case.summarize"]').getByLabel('Model ID');await model.fill('modelo-editado')
          expect(await model.evaluate(el=>{const r=el.getBoundingClientRect();return document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)===el})).toBe(true)
          await expect(page.getByRole('button',{name:'Save configuration',exact:true})).toBeInViewport({ratio:1})
        }
        await page.screenshot({path:`${out}/after-${size}-ai-editor.png`})
      }
    }
    await page.goto(`/v2/cases?evidence=${encodeURIComponent(JSON.stringify(evidence))}`)
    await expect(page.getByRole('dialog')).toBeVisible();await expect(page.locator('mark')).toHaveText('Evidence')
    await noOverflow(page);await page.screenshot({path:`${out}/after-${size}-evidence.png`})
    await page.keyboard.press('Escape');await expect(page.getByRole('dialog')).toHaveCount(0)
    expect(errors).toEqual([])
  })
  test(`${size}: login preserves /v2/ destination`,async({page})=>{
    await page.setViewportSize({width,height});await panelFixture(page,{authenticated:false});await page.goto('/v2/')
    await page.getByLabel('Username',{exact:true}).fill('fixture');await page.getByLabel('Password',{exact:true}).fill('fixture-password')
    await noOverflow(page);await page.screenshot({path:`${out}/after-${size}-login.png`,fullPage:true})
    await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('heading',{name:'Today',exact:true})).toBeVisible()
    await expect(page.getByRole('navigation',{name:'Main'}).getByRole('link',{name:'Today',exact:true})).toHaveAttribute('aria-current','page')
  })
}
test('settings retain CAS/CSRF and clear a replaced credential after save',async({page})=>{
  const {writes}=await panelFixture(page);await page.goto('/v2/system')
  const connection=page.getByRole('group',{name:'Connection fixture-local',exact:true})
  await connection.getByLabel('Credential action').selectOption('set');await connection.getByLabel('API key',{exact:true}).fill('synthetic-secret-no-provider')
  await page.getByRole('button',{name:'Save configuration'}).click()
  await expect(page.getByText('Configuration saved. Credentials cleared from the form. No inference was run.')).toBeVisible()
  await expect(connection.getByLabel('API key',{exact:true})).toHaveCount(0)
  expect(writes).toHaveLength(1);expect(writes[0].headers['if-match']).toBe('"fixture-1"');expect(writes[0].headers['x-csrf-token']).toBe('fixture-csrf')
  expect(writes[0].payload.connections[0].api_key).toBe('synthetic-secret-no-provider')
  expect(await page.evaluate(()=>JSON.stringify({...localStorage,...sessionStorage}))).not.toContain('synthetic-secret')
})
for(const [size,width,height] of [['desktop',1440,1000],['mobile',390,844]])test(`${size}: public evidence citation and keyboard focus retain contrast`,async({page})=>{
  await page.setViewportSize({width,height});await page.goto('/demo?story=B&step=2')
  await page.getByRole('button',{name:'Case file',exact:true}).click()
  const citation=page.getByRole('button',{name:'Open synthetic evidence 1',exact:true});await citation.focus()
  await expect(citation).toBeFocused();await noOverflow(page)
  const colors=await citation.evaluate(el=>{const s=getComputedStyle(el);return {text:s.color,background:s.backgroundColor,focus:s.outlineColor,width:s.outlineWidth}})
  const luminance=rgb=>rgb.match(/[\d.]+/g).slice(0,3).map(v=>Number(v)/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0)
  const ratio=(a,b)=>{const [high,low]=[luminance(a),luminance(b)].sort((a,b)=>b-a);return (high+.05)/(low+.05)}
  expect(ratio(colors.text,colors.background)).toBeGreaterThanOrEqual(4.5);expect(ratio(colors.focus,colors.background)).toBeGreaterThanOrEqual(3);expect(colors.width).toBe('3px')
  await page.screenshot({path:`${out}/after-${size}-public-citation-focus.png`,fullPage:true})
})
test('rendered body, secondary text and primary action meet WCAG contrast',async({page})=>{
  await panelFixture(page);await page.goto('/v2/today');await expect(page.getByText('No material changes',{exact:true})).toBeVisible()
  const pairs=await page.evaluate(()=>['.v2-page-intro h1','.v2-brief .v2-muted','.v2-sidebar small','.v2-brief button','.v2-main-nav [aria-current]'].map(selector=>{
    const element=document.querySelector(selector);let ancestor=element,background
    while(ancestor){background=getComputedStyle(ancestor).backgroundColor;if(background!=='rgba(0, 0, 0, 0)')break;ancestor=ancestor.parentElement}
    return [getComputedStyle(element).color,background]
  }))
  const luminance=rgb=>rgb.match(/[\d.]+/g).slice(0,3).map(v=>Number(v)/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0)
  for(const [foreground,background] of pairs){
    const values=[luminance(foreground),luminance(background)].sort((a,b)=>b-a);expect((values[0]+.05)/(values[1]+.05)).toBeGreaterThanOrEqual(4.5)
  }
})
