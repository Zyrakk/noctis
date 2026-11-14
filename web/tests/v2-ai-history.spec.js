import {test,expect} from '@playwright/test'

const a='00000000-0000-4000-8000-000000000001',b='00000000-0000-4000-8000-000000000002'
const job=(id,state='running',extra={})=>({id,function_id:'brief.compose',state,terminal:['succeeded','failed','cancelled','dependency_blocked','budget_blocked'].includes(state),refs:[],limitations:[],...extra})
const summary=j=>({id:j.id,function_id:j.function_id,created_at:'2026-11-14T12:00:00Z',state:j.state})
async function fixture(page,options={}){
 const state={jobs:options.jobs||[],submits:0,cancels:0,queries:0,reads:[],lists:[],errors:[]}
 page.on('pageerror',e=>state.errors.push(e.message))
 await page.addInitScript(()=>{Storage.prototype.setItem=()=>{throw new Error('AI history must not persist browser results')}})
 await page.route('**/api/v2/**',async route=>{
  const request=route.request(),url=new URL(request.url()),path=url.pathname,send=data=>route.fulfill({json:{data}})
  if(path.endsWith('/auth/session'))return send({user:{username:'synthetic'},csrf:'synthetic-csrf',permissions:['read']})
  if(path.endsWith('/auth/logout'))return send({logged_out:true})
  if(path.endsWith('/today'))return send({changes:[],brief:null})
  if(path.endsWith('/query')){state.queries++;return send({rows:[]})}
  if(path.endsWith('/ai/jobs')){
   if(request.method()==='POST'){
    state.submits++;state.jobs=[job(a)];if(options.lostResponse)return route.abort('failed');return send(state.jobs[0])
   }
   state.lists.push(url.searchParams.get('cursor')||'')
   if(options.list)return options.list(route,url,state)
   return send({jobs:state.jobs.map(summary)})
  }
  const match=path.match(/\/ai\/jobs\/([^/]+)(\/cancel)?$/)
  if(match){
   const id=match[1]
   if(match[2]){state.cancels++;state.jobs=state.jobs.map(j=>j.id===id?job(id,'cancelled'):j);return send(state.jobs.find(j=>j.id===id))}
   state.reads.push(id)
   if(options.detail)return options.detail(route,id,state)
   return send(state.jobs.find(j=>j.id===id))
  }
  // History remains available even if unrelated system settings are unavailable.
  return route.fulfill({status:503,json:{error:{message:'Synthetic settings unavailable'}}})
 })
 return state
}

test('crear, navegar, recargar y cancelar el mismo ID sin nuevas inferencias',async({page})=>{
 const state=await fixture(page)
 await page.goto('/v2/today')
 await page.getByRole('button',{name:'Compose brief with AI'}).click()
 await expect(page.getByRole('status').filter({hasText:`Job ${a}`})).toBeVisible()
 await page.getByRole('link',{name:'Open AI jobs history'}).click()
 await expect(page).toHaveURL(new RegExp(`job=${a}`))
 await page.reload()
 const detail=page.getByRole('region',{name:'Selected AI job'})
 await expect(detail).toContainText(`Job ${a}`)
 await expect(detail).toContainText('A call already sent may continue and still incur its cost.')
 await detail.getByRole('button',{name:'Cancel job'}).click()
 await expect(detail).toContainText('AI status: cancelled')
 const reads=state.reads.length
 await page.waitForTimeout(1750)
 expect(state.reads).toHaveLength(reads)
 expect(state.submits).toBe(1);expect(state.cancels).toBe(1);expect(state.queries).toBe(0);expect(state.errors).toEqual([])
})

test('respuesta POST perdida se recupera desde historial sin reenviar POST',async({page})=>{
 const state=await fixture(page,{lostResponse:true})
 await page.goto('/v2/today');await page.getByRole('button',{name:'Compose brief with AI'}).click()
 await expect(page.getByText('The response may have been lost after saving the job. Check AI jobs history before submitting again.')).toBeVisible()
 await page.getByRole('link',{name:'Open AI jobs history'}).click()
 await page.getByRole('link',{name:`brief.compose · ${a}`}).click()
 await expect(page.getByRole('region',{name:'Selected AI job'})).toContainText(`Job ${a}`)
 expect(state.submits).toBe(1);expect(state.queries).toBe(0);expect(state.errors).toEqual([])
})

for(const terminal of ['dependency_blocked','budget_blocked','succeeded'])test(`terminal ${terminal}: abrir no ejecuta planes ni vuelve a sondear`,async({page})=>{
 const result=terminal==='succeeded'?{text:'Synthetic plan for review',plan:{version:'1',entity:'cases',text:'synthetic'}}:undefined
 const state=await fixture(page,{jobs:[job(a,terminal,{result,safe_error:terminal==='dependency_blocked'?'result_requires_revalidation':undefined})]})
 await page.goto(`/v2/system?job=${a}`)
 const detail=page.getByRole('region',{name:'Selected AI job'})
 await expect(detail).toContainText(`AI status: ${terminal}`)
 await expect(detail.getByRole('button',{name:'Cancel job'})).toHaveCount(0)
 await expect(detail.getByRole('button',{name:'Run this typed plan'})).toHaveCount(0)
 await page.waitForTimeout(1750)
 expect(state.reads).toEqual([a]);expect(state.submits).toBe(0);expect(state.queries).toBe(0);expect(state.errors).toEqual([])
})

test('selección y logout invalidan respuestas pendientes y resultados visibles',async({page})=>{
 let release,started
 const pending=new Promise(resolve=>{release=resolve}),entered=new Promise(resolve=>{started=resolve})
 const state=await fixture(page,{jobs:[job(a),job(b,'succeeded',{result:{text:'CURRENT B'}})],detail:async(route,id,state)=>{
  if(id===a){started();await pending;return route.fulfill({json:{data:job(a,'succeeded',{result:{text:'STALE A'}})}}).catch(()=>{})}
  return route.fulfill({json:{data:state.jobs.find(j=>j.id===id)}})
 }})
 await page.goto(`/v2/system?job=${a}`);await entered
 await page.getByRole('link',{name:`brief.compose · ${b}`}).click()
 await expect(page.getByText('CURRENT B',{exact:true})).toBeVisible();release()
 await expect(page.getByText('STALE A',{exact:true})).toHaveCount(0)
 await page.getByRole('button',{name:'Sign out'}).click()
 await expect(page.getByText('CURRENT B',{exact:true})).toHaveCount(0)
 await expect(page.getByRole('region',{name:'AI jobs',exact:true})).toHaveCount(0)
 expect(state.submits).toBe(0);expect(state.errors).toEqual([])
})

test('paginación, refresco, vacío y errores de listado/detalle visibles',async({page})=>{
 let failed=true
 const state=await fixture(page,{list:(route,url)=>{
  if(failed)return route.fulfill({status:503,json:{error:{message:'History unavailable'}}})
  return route.fulfill({json:{data:url.searchParams.has('cursor')?{jobs:[]}:{jobs:[summary(job(a,'failed'))],next_cursor:'synthetic-next'}}})
 },detail:route=>route.fulfill({status:404,json:{error:{message:'Job unavailable'}}})})
 await page.goto(`/v2/system?job=${a}`)
 await expect(page.getByRole('alert').filter({hasText:'Could not load AI jobs: History unavailable'})).toBeVisible()
 await expect(page.getByRole('alert').filter({hasText:'Could not update AI job: Job unavailable'})).toBeVisible()
 failed=false;await page.getByRole('button',{name:'Refresh AI jobs'}).click()
 await page.getByRole('button',{name:'Older AI jobs'}).click()
 await expect(page.getByText('No AI jobs found.')).toBeVisible()
 await expect(page).toHaveURL(/ai_cursor=synthetic-next/)
 await page.reload();await expect(page.getByText('No AI jobs found.')).toBeVisible()
 await page.getByRole('button',{name:'Refresh AI jobs'}).click()
 await expect(page.getByRole('link',{name:`brief.compose · ${a}`})).toBeVisible()
 expect(state.lists).toEqual(['','','synthetic-next','synthetic-next',''])
 expect(state.submits).toBe(0);expect(state.errors).toEqual([])
})
