import {test,expect} from '@playwright/test'
import fs from 'node:fs'
const artifact=process.env.NOCTIS_AI_VALIDATION_UI_JOB_PATH
const meta={generated_at:'2026-10-20T12:00:00Z',coverage:'SYNTHETIC offline',degraded:false}
for(const outcome of ['valid','invalid','unknown-reason'])test(`contexto CVE sin documentos: ${outcome}`,async({page})=>{
 test.skip(!artifact,'Requires synthetic JobViews published by PG16/HTTPS fake integration')
 const records=JSON.parse(fs.readFileSync(artifact,'utf8')),job=outcome==='valid'?records.valid:{...records.invalid,...(outcome==='unknown-reason'?{validation_reason:'__proto__'}:{})}
 const errors=[];page.on('pageerror',e=>errors.push(e.message))
 let submits=0
 await page.route('**/api/v2/**',async route=>{
  const req=route.request(),url=new URL(req.url()),send=data=>route.fulfill({json:{data,meta}})
  if(url.pathname.endsWith('/auth/session'))return send({user:{username:'synthetic'},permissions:['read'],csrf:'synthetic-csrf'})
  if(url.pathname.includes('/vulnerabilities/'))return send([{cve:records.cve,snapshot_id:'synthetic-snapshot',status:'unknown',body:{synthetic:true},refs:[]}])
  if(url.pathname.endsWith('/ai/jobs')&&req.method()==='POST'){
   submits++;expect(req.postDataJSON()).toMatchObject({function_id:'vulnerability.context',input:{kind:'vulnerability',id:records.cve}});return send(job)
  }
  throw new Error('Unexpected offline UI request')
 })
 await page.goto(`/v2/explore?view=feeds&cve=${encodeURIComponent(records.cve)}`)
 await page.getByRole('button',{name:'Contextualizar CVE con IA'}).click()
 if(outcome==='valid'){
  await expect(page.getByText(records.valid.result.text,{exact:true})).toBeVisible()
  await expect(page.getByText('Aplicabilidad y exposición local: unknown; el texto no modifica hechos del feed.',{exact:true})).toBeVisible()
  await expect(page.getByRole('button',{name:/Abrir evidencia/})).toHaveCount(0)
 }else{
  await expect(page.getByRole('alert').filter({hasText:'result_validation_failed'})).toBeVisible()
  if(outcome==='invalid')await expect(page.getByText('Una afirmación carece de campos o citas válidos.',{exact:true})).toBeVisible()
  else await expect(page.getByText('Una afirmación carece de campos o citas válidos.',{exact:true})).toHaveCount(0)
  await expect(page.getByText(records.valid.result.text,{exact:true})).toHaveCount(0)
 }
 expect(await page.locator('body').innerText()).not.toContain('SECRET-DECOY')
 expect(submits).toBe(1);expect(errors).toEqual([])
})
