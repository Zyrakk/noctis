const {test,expect}=require('../../../web/node_modules/@playwright/test')
const fs=require('node:fs')
const base=process.env.NOCTIS_V2_E2E_URL,control=process.env.NOCTIS_V2_REAL_AI_CONTROL
test('opt-in synthetic real AI: panel save/validation first, sequential guarded consumers',async({page,request})=>{
	page.setDefaultTimeout(30000)
 test.skip(!base||!control,'Requires explicit isolated real AI harness')
 if(process.env.NOCTIS_V2_REAL_AI_RESUME==='true'){
  test.setTimeout(1500000)
  await expect(async()=>{await page.goto(base+'/v2/login')}).toPass({timeout:15000})
  await page.getByLabel('Usuario',{exact:true}).fill(process.env.NOCTIS_V2_E2E_USERNAME);await page.getByLabel('Contraseña').fill(process.env.NOCTIS_V2_E2E_PASSWORD);await page.getByRole('button',{name:'Entrar'}).click()
  await page.getByRole('link',{name:'Sistema',exact:true}).click();await expect(page.getByRole('heading',{name:'IA por función'})).toBeVisible()
  if(process.env.NOCTIS_V2_REAL_AI_WIRE==='true')expect((await request.post(control+'/resume-suite',{headers:{'X-Harness-Token':process.env.NOCTIS_V2_REAL_AI_TOKEN},timeout:1400000})).status()).toBe(204)
  return
 }
 const config=JSON.parse(fs.readFileSync(process.env.NOCTIS_V2_REAL_AI_CONFIG,'utf8'))
 const controlPost=path=>request.post(control+path,{headers:{'X-Harness-Token':process.env.NOCTIS_V2_REAL_AI_TOKEN},timeout:500000})
 await page.goto(base+'/v2/login');await page.getByLabel('Usuario',{exact:true}).fill(process.env.NOCTIS_V2_E2E_USERNAME);await page.getByLabel('Contraseña').fill(process.env.NOCTIS_V2_E2E_PASSWORD);await page.getByRole('button',{name:'Entrar'}).click()
 await page.getByRole('link',{name:'Sistema',exact:true}).click();await expect(page.getByRole('heading',{name:'IA por función'})).toBeVisible()
 const global=page.locator('.v2-ai fieldset').filter({has:page.locator('legend').filter({hasText:'Límites globales'})})
 for(const k of ['daily_cap_units','monthly_cap_units'])await global.getByLabel(k,{exact:true}).fill('5000000000')
 await global.getByLabel('max_concurrent',{exact:true}).fill('1')
 await page.getByRole('button',{name:'Añadir conexión'}).click()
 const connection=page.locator('.v2-ai fieldset').filter({has:page.locator('legend').filter({hasText:/^Conexión /})}).last()
 await connection.getByLabel('Adaptador').selectOption(config.adapter);await connection.getByLabel('Proveedor',{exact:true}).fill(config.provider);await connection.getByLabel('URL completa del endpoint').fill(config.endpoint);await connection.getByLabel('Clases autorizadas').fill('private-approved');await connection.getByLabel('Acción de credencial').selectOption('set')
 // Never use fill(key): its error message may include the attempted value.
 // No trace/video/screenshot, and assertions involving secrets return booleans.
 const key=fs.readFileSync(config.api_key_file,'utf8').trim()
 if(!key||key.length>8192||/[\r\n]/.test(key))throw new Error('Credential file format invalid')
 await connection.getByLabel('API key',{exact:true}).evaluate((element,value)=>{const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;setter.call(element,value);element.dispatchEvent(new Event('input',{bubbles:true}))},key)
 const functions=['semantic.classify','semantic.relevance','semantic.claims','semantic.entities_relations','semantic.observable_roles','identity.disambiguate','vulnerability.context','case.analyze','case.summarize','brief.compose','query.plan','query.explain','evidence.translate','source.triage']
 for(const fn of functions){
  const row=page.locator('.v2-ai fieldset').filter({has:page.locator('legend').filter({hasText:fn})})
  await row.getByLabel('Habilitada',{exact:false}).check();await row.getByRole('combobox',{name:'Conexión',exact:true}).selectOption({label:`${config.provider} · ${config.endpoint}`});await row.getByLabel('ID de modelo').fill(config.model);await row.getByLabel('Ruta admite JSON estructurado').check()
  for(const [k,v]of Object.entries(config.limits))await row.getByLabel(k,{exact:true}).fill(String(v))
  for(const k of ['daily_cap_units','monthly_cap_units'])await row.getByLabel(k,{exact:true}).fill('5000000000')
  await row.getByLabel('max_concurrent',{exact:true}).fill('1');await row.getByLabel('Versión de tarifa').fill(config.price.version)
  for(const k of ['input_units_per_token','output_units_per_token'])await row.getByLabel(k,{exact:true}).fill(String(config.price[k]))
 }
 await page.getByRole('button',{name:'Validar sin inferencia'}).click();await expect(page.getByText('Estructura válida.',{exact:false})).toBeVisible();expect((await controlPost('/zero-calls')).status()).toBe(204)
 await page.getByRole('button',{name:'Guardar configuración'}).click();await expect(page.getByText('Configuración guardada.',{exact:false})).toBeVisible();expect((await controlPost('/zero-calls')).status()).toBe(204)
 const saved=await(await page.request.get(base+'/api/v2/ai/config')).text()
 expect(saved.includes(key)).toBe(false);expect(await page.evaluate(value=>JSON.stringify({...localStorage,...sessionStorage}).includes(value),key)).toBe(false)
 await expect(page.getByLabel('API key',{exact:true})).toHaveCount(0)
 if(process.env.NOCTIS_V2_REAL_AI_WIRE!=='true')return
 await page.goto(base+'/v2/cases/'+process.env.NOCTIS_V2_REAL_AI_CASE)
 await page.getByRole('button',{name:'Abrir evidencia 1'}).first().click()
 await page.getByRole('button',{name:'Traducir evidencia al español'}).click()
 await expect(page.getByText('Estado IA: queued',{exact:false})).toBeVisible()
 expect((await controlPost('/translation-once')).status()).toBe(204)
 await expect(page.getByText('Traducción generada · no es el original')).toBeVisible({timeout:15000})
 expect((await controlPost('/suite')).status()).toBe(204)
})
