import {test,expect} from '@playwright/test'

const sourceA='11111111-1111-4111-8111-111111111111',sourceB='22222222-2222-4222-8222-222222222222'
async function fixture(page,handlers={}){
 const writes=[],errors=[]
 page.on('pageerror',e=>errors.push(e.message))
 await page.route('**/api/v2/**',async route=>{
  const req=route.request(),url=new URL(req.url()),path=url.pathname.slice('/api/v2'.length)
  const send=data=>route.fulfill({json:{data,meta:{}}}),fail=(code,status=409)=>route.fulfill({status,json:{error:{code,current_revision:0}}})
  if(req.method()==='POST')writes.push({path,...req.postDataJSON()})
  if(handlers[path])return handlers[path]({req,url,send,fail,writes})
  if(path==='/auth/session')return send({user:{username:'operator'},csrf:'fixture-csrf'})
  if(path==='/system')return send({status:'ok',errors:[]})
  if(path==='/ai/jobs'&&req.method()==='GET')return send({jobs:[]})
  if(path==='/runtime-control')return send({revision:1,paused:false})
  if(path==='/ai/config')return send({revision:1,functions:[],connections:[],bindings:[],credential_available:false})
  if(path==='/today')return send({changes:[]})
  return send([])
 })
 return {writes,errors}
}

test('source saves use server revisions, reconcile rows and preserve other drafts',async({page})=>{
 let sources=[{id:sourceA,name:'Source A',policy_version:'p1',policy_revision:7,enabled:true,status:'active'},{id:sourceB,name:'Source B',policy_version:'p1',policy_revision:1,enabled:true,status:'active'}]
 const {writes,errors}=await fixture(page,{
  '/sources':({send})=>send(sources),
  [`/sources/${sourceA}/policy`]:({req,send})=>{const body=req.postDataJSON();sources=sources.map(s=>s.id===sourceA?{...s,...body,policy_revision:s.policy_revision+3,status:body.enabled?'active':'paused'}:s);return send(sources[0])},
 })
 await page.goto('/v2/sources')
 const a=page.locator('li').filter({has:page.getByText('Source A',{exact:true})}),b=page.locator('li').filter({has:page.getByText('Source B',{exact:true})})
 await a.locator('summary').click();await b.locator('summary').click()
 await b.getByLabel('PIR policy version').fill('preserved-other-draft')
 await a.getByLabel('Collection authorized and active').uncheck();await a.getByRole('button',{name:'Save source policy',exact:true}).click()
 await expect(a.getByText(/Confirmed source revision 10/)).toBeVisible();await expect(a.getByText(/Status: paused/)).toBeVisible()
 await expect(b.getByLabel('PIR policy version')).toHaveValue('preserved-other-draft')
 await a.getByLabel('Collection authorized and active').check();await a.getByRole('button',{name:'Save source policy',exact:true}).click()
 await expect(a.getByText(/Confirmed source revision 13/)).toBeVisible();await expect(a.getByText(/Status: active/)).toBeVisible()
 expect(writes.map(w=>w.expected_revision)).toEqual([7,10]);expect(errors).toEqual([])
})

test('source CAS reload reads only, preserves conflict on failure and never adopts error revision',async({page})=>{
 let read=0,unavailable=false
 const {writes}=await fixture(page,{
  '/sources':({send,fail})=>unavailable?fail('read_unavailable',503):send([{id:sourceA,name:'Source A',policy_version:read++?'server-policy':'p1',policy_revision:read===1?2:9,enabled:true,status:'active'}]),
  [`/sources/${sourceA}/policy`]:({fail})=>fail('stale_revision'),
 })
 await page.goto('/v2/sources');await page.getByText('Source policy and pause',{exact:true}).click();await page.getByLabel('PIR policy version').fill('operator-draft')
 await page.getByRole('button',{name:'Save source policy',exact:true}).click();await expect(page.getByText(/Revision conflict/)).toBeVisible()
 unavailable=true;await page.getByRole('button',{name:'Reload current source',exact:true}).click();await expect(page.getByText('read_unavailable')).toBeVisible();await expect(page.getByText(/Revision conflict/)).toBeVisible()
 unavailable=false;await page.getByRole('button',{name:'Reload current source',exact:true}).click();await expect(page.getByText(/Confirmed source revision 9/)).toBeVisible();await expect(page.getByLabel('PIR policy version')).toHaveValue('operator-draft');expect(writes).toHaveLength(1)
 await page.getByRole('button',{name:'Save source policy',exact:true}).click();await expect(page.getByText(/Revision conflict/)).toBeVisible();expect(writes.map(w=>w.expected_revision)).toEqual([2,9])
})

test('source non-CAS conflicts retain cause and confirmed save survives a failed refresh',async({page})=>{
 let failure='current_channel_baseline_required',saved=false
 const {writes}=await fixture(page,{
  '/sources':({send,fail})=>saved?fail('refresh_unavailable',503):send([{id:sourceA,name:'Source A',policy_version:'p1',policy_revision:4,enabled:false,status:'paused'}]),
  [`/sources/${sourceA}/policy`]:({send,fail})=>{if(failure)return fail(failure);saved=true;return send({policy_revision:8,policy_version:'p1',enabled:true})},
 })
 await page.goto('/v2/sources');await page.getByText('Source policy and pause',{exact:true}).click();await page.getByLabel('Collection authorized and active').check()
 for(const code of ['current_channel_baseline_required','inventory_identity_changed','request_id_conflict']){failure=code;await page.getByRole('button',{name:'Save source policy',exact:true}).click();await expect(page.getByText(code,{exact:true})).toBeVisible();await expect(page.getByText(/Revision conflict/)).toHaveCount(0)}
 failure='';await page.getByRole('button',{name:'Save source policy',exact:true}).click();await expect(page.getByText(/Save confirmed. Source view pending refresh/)).toBeVisible();await expect(page.getByText(/Confirmed source revision 8/)).toBeVisible();expect(writes).toHaveLength(4)
})

test('runtime preserves pause intention and recognizes an already satisfied action without writing',async({page})=>{
 let current={revision:1,paused:false},readFailure=false
 const {writes}=await fixture(page,{'/runtime-control':({req,send,fail})=>req.method()==='POST'?fail('stale_revision'):readFailure?fail('read_unavailable',503):send(current)})
 await page.goto('/v2/system');const control=page.getByRole('region',{name:'Processing control'})
 await control.getByRole('button',{name:'Pause processing',exact:true}).click();await expect(control.getByText(/Requested action: pause/)).toBeVisible()
 readFailure=true;await control.getByRole('button',{name:'Reload processing control'}).click();await expect(control.getByText(/Revision conflict/)).toBeVisible()
 readFailure=false;current={revision:5,paused:false};await control.getByRole('button',{name:'Reload processing control'}).click();await expect(control.getByText(/Confirmed control revision 5/)).toBeVisible();expect(writes).toHaveLength(1)
 await control.getByRole('button',{name:'Pause processing',exact:true}).click();await expect(control.getByText(/Revision conflict/)).toBeVisible();expect(writes.map(w=>w.action)).toEqual(['pause','pause']);expect(writes.map(w=>w.expected_revision)).toEqual([1,5])
 current={revision:6,paused:true};await control.getByRole('button',{name:'Reload processing control'}).click();await expect(control.getByText(/already satisfies your requested action/)).toBeVisible();await expect(control.getByRole('button',{name:'Pause processing',exact:true})).toBeDisabled();expect(writes).toHaveLength(2)
})

test('retention reload preserves draft, invalidates preview and run, and keeps run conflicts distinct',async({page})=>{
 let revision=2,failRead=false,failPolicy=true
 const {writes}=await fixture(page,{'/retention':({req,send,fail})=>{
  if(req.method()==='GET')return failRead?fail('read_unavailable',503):send({present:true,revision,retain_seconds:500})
  const b=req.postDataJSON()
  if(b.action==='policy')return failPolicy?fail('stale_revision'):send({revision:++revision})
  if(b.dry_run)return send({policy_revision:revision,eligible:3})
  if(b.action==='batch')return fail('retention_policy_changed_or_run_unavailable')
  return send({run_id:'synthetic-run'})
 }})
 await page.goto('/v2/system');await page.getByText('Retention by source and class',{exact:true}).click();await page.getByLabel('Source UUID',{exact:true}).fill(sourceA)
 await expect(page.getByText(/Confirmed retention revision 2/)).toBeVisible();await page.getByLabel('Retention in seconds',{exact:true}).fill('900')
 await page.getByRole('button',{name:'Preview without purging'}).click();await expect(page.getByText(/Preview: 3 eligible/)).toBeVisible()
 await page.getByRole('button',{name:'Create purge run',exact:true}).click();await expect(page.getByLabel('Resumable run UUID')).toHaveValue('synthetic-run')
 await page.getByRole('button',{name:'Purge next batch of 100'}).click();await expect(page.getByText('retention_policy_changed_or_run_unavailable',{exact:true})).toBeVisible();await expect(page.getByText(/Revision conflict/)).toHaveCount(0)
 await page.getByRole('button',{name:'Save retention policy',exact:true}).click();await expect(page.getByText(/Revision conflict/)).toBeVisible();await expect(page.getByLabel('Resumable run UUID')).toHaveValue('');await expect(page.getByText(/Preview: 3/)).toHaveCount(0)
 failRead=true;await page.getByRole('button',{name:'Reload current retention policy'}).click();await expect(page.getByText('read_unavailable')).toBeVisible();await expect(page.getByText(/Revision conflict/)).toBeVisible()
 failRead=false;revision=5;await page.getByRole('button',{name:'Reload current retention policy'}).click();await expect(page.getByText(/Confirmed retention revision 5/)).toBeVisible();await expect(page.getByLabel('Retention in seconds',{exact:true})).toHaveValue('900');expect(writes).toHaveLength(4)
 await page.getByRole('button',{name:'Save retention policy',exact:true}).click();await expect(page.getByText(/Revision conflict/)).toBeVisible();expect(writes.at(-1).expected_revision).toBe(5)
 failPolicy=false;await page.getByRole('button',{name:'Reload current retention policy'}).click();await expect(page.getByRole('button',{name:'Save retention policy',exact:true})).toBeEnabled();await page.getByRole('button',{name:'Save retention policy',exact:true}).click();await expect(page.getByText(/Confirmed retention revision 6/)).toBeVisible()
 await page.getByRole('button',{name:'Preview without purging'}).click();await expect(page.getByText(/Preview: 3 eligible/)).toBeVisible();await page.getByRole('button',{name:'Create purge run',exact:true}).click();await expect(page.getByLabel('Resumable run UUID')).toHaveValue('synthetic-run')
 revision=7;await page.getByRole('button',{name:'Reload current retention policy'}).click();await expect(page.getByText(/Confirmed retention revision 7/)).toBeVisible();await expect(page.getByLabel('Resumable run UUID')).toHaveValue('');await expect(page.getByText(/Preview: 3 eligible/)).toHaveCount(0)
 revision=8;await page.getByRole('button',{name:'Preview without purging'}).click();await expect(page.getByText(/The preview found a changed policy/)).toBeVisible();await expect(page.getByText(/Confirmed retention revision 7/)).toBeVisible();await expect(page.getByRole('button',{name:'Create purge run',exact:true})).toBeDisabled()
})

test('retention A-B-A contexts reject late reads and mutations and prevent duplicate sends',async({page})=>{
 let releaseRead,releaseMutation,holdRead=true,holdMutation=false,readFinished=false,mutationFinished=false
 const readBlocked=new Promise(resolve=>releaseRead=resolve),mutationBlocked=new Promise(resolve=>releaseMutation=resolve)
 const {writes}=await fixture(page,{'/retention':async({req,url,send})=>{
  if(req.method()==='GET'){
   if(url.searchParams.get('source_id')===sourceA&&holdRead){holdRead=false;await readBlocked;await send({present:true,revision:99,retain_seconds:99});readFinished=true;return}
   return send({present:true,revision:2,retain_seconds:200})
  }
  if(holdMutation){await mutationBlocked;await send({run_id:'obsolete-run'});mutationFinished=true;return}
  return send({policy_revision:2,eligible:10})
 }})
 await page.goto('/v2/system');await page.getByText('Retention by source and class',{exact:true}).click()
 await page.getByLabel('Source UUID',{exact:true}).fill(sourceA);await expect.poll(()=>holdRead).toBe(false)
 await page.getByLabel('Source UUID',{exact:true}).fill(sourceB);await expect(page.getByText(/Confirmed retention revision 2/)).toBeVisible()
 await page.getByLabel('Source UUID',{exact:true}).fill(sourceA);await expect(page.getByText(/Confirmed retention revision 2/)).toBeVisible();releaseRead();await expect.poll(()=>readFinished).toBe(true);await expect(page.getByText(/Confirmed retention revision 99/)).toHaveCount(0)
 await page.getByRole('button',{name:'Preview without purging'}).click();await expect(page.getByText(/Preview: 10 eligible/)).toBeVisible()
 holdMutation=true;await page.getByRole('button',{name:'Create purge run',exact:true}).evaluate(el=>{el.click();el.click()});await expect.poll(()=>writes.length).toBe(2)
 await expect(page.getByRole('button',{name:'Create purge run',exact:true})).toBeDisabled()
 await page.getByLabel('Data class',{exact:true}).fill('public');await expect(page.getByText(/Confirmed retention revision 2/)).toBeVisible();await page.getByLabel('Data class',{exact:true}).fill('private');await expect(page.getByText(/Confirmed retention revision 2/)).toBeVisible();releaseMutation()
 await expect.poll(()=>mutationFinished).toBe(true);await page.evaluate(()=>new Promise(requestAnimationFrame));await expect(page.getByLabel('Resumable run UUID')).toHaveValue('');await expect(page.getByText(/Preview: 10 eligible/)).toHaveCount(0);expect(writes).toHaveLength(2)
})

test('source and control editors reject concurrent sends while a mutation is pending',async({page})=>{
 let releaseSource,releaseControl
 const sourceBlocked=new Promise(resolve=>releaseSource=resolve),controlBlocked=new Promise(resolve=>releaseControl=resolve)
 const {writes}=await fixture(page,{
  '/sources':({send})=>send([{id:sourceA,name:'Source A',policy_version:'p1',policy_revision:1,enabled:true,status:'active'}]),
  [`/sources/${sourceA}/policy`]:async({send})=>{await sourceBlocked;return send({policy_revision:2,policy_version:'p1',enabled:false})},
  '/runtime-control':async({req,send})=>{if(req.method()==='GET')return send({revision:1,paused:false});await controlBlocked;return send({revision:2,paused:true})},
 })
 await page.goto('/v2/sources');await page.getByText('Source policy and pause',{exact:true}).click()
 await page.getByRole('button',{name:'Save source policy',exact:true}).evaluate(el=>{el.click();el.click()});await expect.poll(()=>writes.length).toBe(1);await expect(page.getByRole('button',{name:'Save source policy',exact:true})).toBeDisabled()
 releaseSource();await expect(page.getByRole('button',{name:'Save source policy',exact:true})).toBeEnabled()
 await page.goto('/v2/system');await expect(page.getByRole('button',{name:'Pause processing',exact:true})).toBeEnabled();await page.getByRole('button',{name:'Pause processing',exact:true}).evaluate(el=>{el.click();el.click()});await expect.poll(()=>writes.length).toBe(2);await expect(page.getByRole('button',{name:'Pause processing',exact:true})).toBeDisabled()
 releaseControl();await expect(page.getByRole('button',{name:'Resume processing',exact:true})).toBeEnabled();expect(writes).toHaveLength(2)
})
