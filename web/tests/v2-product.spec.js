import { test, expect } from '@playwright/test'
const meta={generated_at:'2026-10-18T12:00:00Z',coverage:'parcial',degraded:false}
const ref={observation_id:'9007199254740993',revision:'2',hash:'digest',representation:'original',start:7,end:12}
test.beforeEach(async({page})=>{const errors=[];page.on('pageerror',error=>errors.push(error.message));page.__errors=errors})
test.afterEach(async({page})=>{expect(page.__errors).toEqual([])})
async function fixture(page,{authenticated=true,failed=false}={}) {
  let logged=authenticated
  const requests=[]
  await page.route('**/api/v2/**',async route=>{
    const request=route.request(),url=new URL(request.url());requests.push({url,request})
    const send=(data,status=200)=>route.fulfill({status,json:{data,meta}})
    if(url.pathname.endsWith('/auth/session')) return logged?send({user:{username:'operador'},permissions:['read'],csrf:'csrf-fixture'}):route.fulfill({status:401,json:{error:{code:'unauthorized',message:'Sin sesión'}}})
    if(url.pathname.endsWith('/auth/login')) { expect(request.postDataJSON()).toEqual({username:'operador',password:'fixture-password'});logged=true;return send({user:{username:'operador'},permissions:['read'],csrf:'csrf-fixture'}) }
    if(url.pathname.endsWith('/auth/logout')) {expect(request.headers()['x-csrf-token']).toBe('csrf-fixture');logged=false;return send(null)}
    if(failed) return route.fulfill({status:503,json:{error:{code:'unavailable',message:'Base de datos no disponible',request_id:'fixture'}}})
    if(url.pathname.endsWith('/today')) return route.fulfill({json:{data:{changes:[],brief:null},meta:{...meta,degraded:true}}})
    if(url.pathname.endsWith('/cases')) return send([{id:'9007199254740995',title:'Oferta reportada',revision:'2',status:'reportada',summary:'Cuatro copias no confirman la afirmación.',citations:[ref]}])
    if(url.pathname.includes('/cases/')) return send({id:'9007199254740995',title:'Oferta reportada',revision:'2',status:'reportada',summary:'Afirmación sin verificar',citations:[ref],timeline:[{id:'1',title:'Original',text:'Texto conservado',kind:'original',created_at:'2026-10-18',citations:[ref]}]})
    if(url.pathname.includes('/evidence/')) return send({text:'Antes: café 🙂 <script>alert(1)</script>',hash:'digest',representation:'original',source:'Fuente sintética',revision:'2'})
    if(url.pathname.endsWith('/sources')||url.pathname.endsWith('/telegram/candidates')) return send([])
    if(url.pathname.endsWith('/claims')||url.pathname.endsWith('/source-imports')) return send([])
    if(['/questions','/discovery','/coverage'].some(path=>url.pathname.endsWith(path))) return send([])
    if(url.pathname.endsWith('/runtime-control')) return send({revision:1,paused:false})
    if(url.pathname.endsWith('/system')) return send({status:'degraded',backlog:null,errors:[]})
    if(url.pathname.endsWith('/ai/config')) return send({revision:1,functions:[],connections:[],bindings:[],daily_cap_units:0,monthly_cap_units:0,max_concurrent:0,credential_available:false})
    throw new Error(`Unexpected URL ${url}`)
  })
  return requests
}
test('acceso por cookie, logout CSRF y ausencia de tokens en storage',async({page})=>{
  await fixture(page,{authenticated:false});await page.goto('/v2/login')
  await page.getByLabel('Usuario',{exact:true}).fill('operador');await page.getByLabel('Contraseña').fill('fixture-password');await page.getByRole('button',{name:'Entrar'}).click()
  await expect(page.getByRole('heading',{name:'Hoy',exact:true})).toBeVisible()
  expect(await page.evaluate(()=>({...localStorage}))).toEqual({});expect(await page.evaluate(()=>({...sessionStorage}))).toEqual({})
  await page.getByRole('button',{name:'Salir'}).click();await expect(page.getByRole('heading',{name:'Noctis · Acceso privado'})).toBeVisible()
})
test('ruta profunda, cita UTF8 y texto hostil, selección recuperable con atrás',async({page})=>{
  await fixture(page);await page.goto('/v2/cases/9007199254740995')
  await page.getByRole('button',{name:'Abrir evidencia 1'}).first().click()
  await expect(page.locator('mark')).toHaveText('café');await expect(page.locator('.v2-evidence pre')).toContainText('<script>alert(1)</script>')
  expect(await page.locator('.v2-evidence script').count()).toBe(0)
  await page.reload();await expect(page.locator('mark')).toHaveText('café')
  await page.getByRole('button',{name:'Cerrar evidencia'}).click();await expect(page.locator('.v2-evidence')).toHaveCount(0)
  await page.goBack();await expect(page.locator('mark')).toHaveText('café')
})
test('filtro URL, vacío real y cobertura degradada diferenciados',async({page})=>{
  const requests=await fixture(page);await page.goto('/v2/cases?q=inicial')
  await expect(page.getByLabel('Buscar',{exact:true})).toHaveValue('inicial');await page.getByLabel('Buscar',{exact:true}).fill('cambio');await page.getByRole('button',{name:'Buscar',exact:true}).click()
  await expect(page).toHaveURL(/q=cambio/);await page.reload();await expect(page.getByLabel('Buscar',{exact:true})).toHaveValue('cambio')
  expect(requests.some(r=>r.url.searchParams.get('q')==='cambio')).toBeTruthy()
  await page.getByRole('link',{name:'Hoy',exact:true}).click();await expect(page.getByText(/Servicio degradado/)).toBeVisible();await expect(page.getByText(/No se observaron cambios materiales/)).toBeVisible()
  await page.getByRole('link',{name:'Fuentes',exact:true}).click();await expect(page.getByText('No hay fuentes configuradas.')).toBeVisible()
})
test('fallo no se muestra como vacío y sistema IA sin selectores ficticios',async({page})=>{
  await fixture(page,{failed:true});await page.goto('/v2/today');await expect(page.getByRole('alert')).toContainText('Base de datos no disponible');await expect(page.getByText(/No se observaron/)).toHaveCount(0)
})
test('móvil y teclado muestran Sistema y configuración sin cifras inventadas',async({page})=>{
  await page.setViewportSize({width:390,height:844});await fixture(page);await page.goto('/v2/system')
  await expect(page.getByText('Trabajos pendientes: desconocido')).toBeVisible();await expect(page.getByText(/Falta montar la clave maestra/)).toBeVisible();await expect(page.getByRole('button',{name:'Validar sin inferencia'})).toBeVisible()
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBeTruthy()
  await page.keyboard.press('Tab');await expect(page.getByRole('button',{name:'Salir'})).toBeFocused()
})
test('presentación pública no solicita API v2 ni monta sesión privada',async({page})=>{
  const requests=[],errors=[];page.on('pageerror',error=>errors.push(error.message));page.on('request',request=>{if(new URL(request.url()).pathname.startsWith('/api/v2')) requests.push(request.url())})
  await page.addInitScript(()=>{Storage.prototype.getItem=()=>{throw new Error('La demo no debe leer credenciales del navegador')}})
  await page.route('**/api/v2/**',route=>route.abort());await page.goto('/presentation/demo');await expect(page.locator('.v2')).toHaveCount(0);await expect(page.locator('body')).toContainText(/synthetic demo data/i);expect(requests).toEqual([]);expect(errors).toEqual([])
})
test('carga permanece explícita y cita con offset inválido falla sin inventar texto',async({page})=>{
  await fixture(page)
  let release
  const blocked=new Promise(resolve=>{release=resolve})
  await page.route('**/api/v2/today',async route=>{await blocked;await route.fulfill({json:{data:{changes:[],brief:null},meta}})})
  await page.goto('/v2/today');await expect(page.getByRole('status')).toHaveText('Cargando datos…');await expect(page.getByText(/No se observaron/)).toHaveCount(0)
  release();await expect(page.getByText(/No se observaron/)).toBeVisible()
  const invalid={...ref,start:11}
  await page.goto(`/v2/cases/9007199254740995?evidence=${encodeURIComponent(JSON.stringify(invalid))}`)
  await expect(page.locator('.v2-evidence [role=alert]')).toBeVisible();await expect(page.locator('mark')).toHaveCount(0)
})
test('referencias URL malformadas no solicitan evidencia',async({page})=>{
  const requests=await fixture(page)
  for(const reference of [true,{},null,{...ref,observation_id:42},{...ref,revision:null},{...ref,hash:{}},{...ref,representation:''},{...ref,start:Number.MAX_SAFE_INTEGER+1},{...ref,start:-1},{...ref,end:0}]) {
    await page.goto(`/v2/cases?evidence=${encodeURIComponent(JSON.stringify(reference))}`)
    await expect(page.getByText('Selección de evidencia no válida.')).toBeVisible()
  }
  expect(requests.filter(r=>r.url.pathname.includes('/evidence/'))).toEqual([])
})
test('revisión o texto incompatibles fallan y ruta inválida no rompe React',async({page})=>{
  await fixture(page)
  for(const data of [{text:'contenido',hash:'digest',representation:'original',revision:'3'},{text:null,hash:'digest',representation:'original',revision:'2'}]) {
    await page.route('**/api/v2/evidence/**',route=>route.fulfill({json:{data,meta}}))
    await page.goto(`/v2/cases?evidence=${encodeURIComponent(JSON.stringify(ref))}`)
    await expect(page.locator('.v2-evidence [role=alert]')).toContainText('no coincide');await expect(page.locator('mark')).toHaveCount(0)
  }
  await page.evaluate(()=>{history.pushState({},'','/v2/cases/%E0%A4%A');dispatchEvent(new PopStateEvent('popstate'))});await expect(page.getByText('Ruta no válida.')).toBeVisible()
})
test('login conserva ruta y query internos y 401 invalida sesión, 403 la conserva',async({page})=>{
  await fixture(page,{authenticated:false});await page.goto('/v2/cases/9007199254740995?q=conservar')
  await page.getByLabel('Usuario',{exact:true}).fill('operador');await page.getByLabel('Contraseña').fill('fixture-password');await page.getByRole('button',{name:'Entrar'}).click()
  await expect(page).toHaveURL(/\/v2\/cases\/9007199254740995\?q=conservar$/)
  await page.route(url=>url.pathname==='/api/v2/sources',route=>route.fulfill({status:403,json:{error:{message:'Prohibido'}}}))
  await page.getByRole('link',{name:'Fuentes',exact:true}).click();await expect(page.getByRole('alert')).toContainText('Prohibido');await expect(page.getByRole('button',{name:'Salir'})).toBeVisible()
  await page.route('**/api/v2/system',route=>route.fulfill({status:401,json:{error:{message:'Expirada'}}}))
  await page.getByRole('link',{name:'Sistema',exact:true}).click();await expect(page.getByRole('heading',{name:'Noctis · Acceso privado'})).toBeVisible()
})
test('lector móvil modal contiene foco y devuelve al invocador',async({page})=>{
  await page.setViewportSize({width:390,height:844});await fixture(page);await page.goto('/v2/cases')
  const opener=page.getByRole('button',{name:'Abrir evidencia 1'});await opener.click()
  await expect(page.getByRole('dialog')).toBeVisible();await expect(page.getByRole('button',{name:'Cerrar evidencia'})).toBeFocused()
  await page.keyboard.press('Tab');await expect(page.getByRole('button',{name:'Traducir evidencia al español'})).toBeFocused()
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy()
  await page.keyboard.press('Escape');await expect(page.getByRole('dialog')).toHaveCount(0);await expect(opener).toBeFocused()
  await page.screenshot({path:'/tmp/noctis-v2-mobile.png',fullPage:true})
})
