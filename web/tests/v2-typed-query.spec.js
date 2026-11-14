import {test,expect} from '@playwright/test'

const meta={generated_at:'2026-11-14T00:00:00Z',coverage:'synthetic',degraded:false}
const cursor='00000000-0000-0000-0000-000000000003',nextCursor='00000000-0000-0000-0000-000000000010'
const reviewed={version:'1',operation:'search',entity:'observations',mode:'fulltext',text:'  exact café + text  ',filters:{source_id:'00000000-0000-0000-0000-000000000001',case_id:'00000000-0000-0000-0000-000000000002',kind:' original '},limit:7,cursor}

async function fixture(page,proposed=reviewed){
 const plans=[],errors=[]
 page.on('pageerror',error=>errors.push(error.message))
 await page.route('**/api/v2/**',route=>{
  const request=route.request(),path=new URL(request.url()).pathname
  const send=(data,status=200)=>route.fulfill({status,json:{data,meta}})
  if(path.endsWith('/auth/session'))return send({user:{username:'fixture'},permissions:['read'],csrf:'synthetic'})
  if(path.endsWith('/query')){
   const {plan}=request.postDataJSON();plans.push(plan)
   if(plan.cursor==='invalid')return route.fulfill({status:400,json:{error:{message:'Invalid query cursor'}}})
   return send({id:'synthetic-result',plan,rows:[],next_cursor:nextCursor})
  }
  if(path.endsWith('/ai/jobs')){
   expect(request.postDataJSON().function_id).toBe('query.plan')
   return send({id:'synthetic-job',state:'succeeded',terminal:true,result:{text:'Review this synthetic plan',plan:proposed}})
  }
  throw new Error(`Unexpected API request: ${path}`)
 })
 return {plans,errors}
}

async function lastPlan(plans,want){await expect.poll(()=>plans.at(-1)).toEqual(want)}
async function acceptPlan(page){
 await page.getByRole('button',{name:'Propose plan with AI',exact:true}).click()
 await expect(page.locator('.v2-job pre')).toBeVisible()
 const displayed=JSON.parse(await page.locator('.v2-job pre').textContent())
 await page.getByRole('button',{name:'Run this typed plan',exact:true}).click()
 return displayed
}

for(const text of [reviewed.text,''])test(`reviewed plan preserves limit, cursor and filters with ${text?'text':'empty text'}`,async({page})=>{
 const proposed={...reviewed,text},f=await fixture(page,proposed)
 await page.goto('/v2/explore?q=propose')
 const displayed=await acceptPlan(page)
 await lastPlan(f.plans,displayed)
 await expect(page.getByLabel('Limit',{exact:true})).toHaveValue('7')
 await expect(page.getByLabel('Query',{exact:true})).toHaveValue(text)
 const acceptedURL=page.url()
 const beforeReload=f.plans.length
 await page.reload();await expect.poll(()=>f.plans.length).toBeGreaterThan(beforeReload);await lastPlan(f.plans,proposed)
 await expect(page.getByLabel('Limit',{exact:true})).toHaveValue('7')
 await page.getByRole('link',{name:'Next page',exact:true}).click()
 await lastPlan(f.plans,{...proposed,cursor:nextCursor})
 await page.goBack();await expect(page).toHaveURL(acceptedURL);await lastPlan(f.plans,proposed)
 await page.goForward();await lastPlan(f.plans,{...proposed,cursor:nextCursor})
 if(!text)await expect(page.getByRole('button',{name:'Propose plan with AI',exact:true})).toHaveCount(0)
 expect(f.errors).toEqual([])
})

test('opening Explore is idle; explicit empty and whitespace queries run without offering AI planning',async({page})=>{
 const f=await fixture(page)
 await page.goto('/v2/explore')
 await expect(page.getByRole('button',{name:'Run query',exact:true})).toBeVisible()
 expect(f.plans).toEqual([])
 await page.getByRole('button',{name:'Run query',exact:true}).click()
 await expect.poll(()=>f.plans.length).toBe(1)
 expect(f.plans[0]).toMatchObject({text:'',limit:50})
 await expect(page).toHaveURL(/run_query=1/)
 await page.reload();await expect.poll(()=>f.plans.length).toBe(2)
 await page.getByLabel('Query',{exact:true}).fill('   ')
 await page.getByRole('button',{name:'Run query',exact:true}).click()
 await expect.poll(()=>f.plans.at(-1)?.text).toBe('   ')
 await expect(page.getByRole('button',{name:'Propose plan with AI',exact:true})).toHaveCount(0)
 expect(f.errors).toEqual([])
})

test('an accepted empty plan without filters executes',async({page})=>{
 const proposed={...reviewed,text:'',filters:{}},f=await fixture(page,proposed)
 await page.goto('/v2/explore?q=propose')
 await acceptPlan(page);await lastPlan(f.plans,proposed)
 expect(f.errors).toEqual([])
})

test('every submitted criterion change resets only the cursor and retains literal values',async({page})=>{
 const f=await fixture(page)
 const initial={...reviewed,filters:{...reviewed.filters}}
 const query=new URLSearchParams({q:initial.text,entity_type:initial.entity,mode:initial.mode,limit:'7',cursor,...initial.filters})
 for(const [field,value,property]of [['Query','new literal  text','text'],['Source ID',nextCursor,'source_id'],['Case ID',nextCursor,'case_id'],['Type',' padded kind ','kind'],['Search in','cases','entity'],['Mode','exact','mode'],['Limit','9','limit']]){
  await page.goto(`/v2/explore?${query}`);await lastPlan(f.plans,initial)
  if(['Search in','Mode'].includes(field))await page.getByRole('combobox',{name:field,exact:true}).selectOption(value)
  else await page.getByLabel(field,{exact:true}).fill(value)
  await page.getByRole('button',{name:'Run query',exact:true}).click()
  const expected={...initial,filters:{...initial.filters}};delete expected.cursor
  if(property in expected.filters)expected.filters[property]=value;else expected[property]=property==='limit'?Number(value):value
  await lastPlan(f.plans,expected)
  expect(new URL(page.url()).searchParams.has('cursor')).toBe(false)
 }
 expect(f.errors).toEqual([])
})

for(const mode of ['exact','fulltext'])test(`legacy ${mode} URL preserves query and implicit limit 50`,async({page})=>{
 const f=await fixture(page),text='  legacy café  '
 await page.goto(`/v2/explore?${new URLSearchParams({q:text,mode})}`)
 await lastPlan(f.plans,{version:'1',operation:'search',entity:'observations',mode,text,filters:{},limit:50})
 await expect(page.getByLabel('Limit',{exact:true})).toHaveValue('50')
})

test('invalid explicit limits fail without silently executing a corrected limit',async({page})=>{
 const f=await fixture(page)
 for(const limit of ['', '1.5','0','101','abc']){
  await page.goto(`/v2/explore?${new URLSearchParams({q:'search',limit})}`)
  await expect(page.getByRole('alert')).toContainText('Limit must be a whole number from 1 to 100.')
  await expect(page.getByLabel('Limit',{exact:true})).toHaveValue(limit)
 }
 expect(f.plans).toEqual([])
 await page.goto('/v2/explore')
 await page.getByLabel('Limit',{exact:true}).fill('')
 await page.getByRole('button',{name:'Run query',exact:true}).click()
 await expect(page.getByRole('alert')).toContainText('Limit must be a whole number')
 expect(f.plans).toEqual([])
})

test('invalid cursor reaches authoritative API unchanged and its rejection remains visible',async({page})=>{
 const f=await fixture(page)
 await page.goto('/v2/explore?q=search&limit=7&cursor=invalid')
 await expect(page.getByRole('alert')).toContainText('Invalid query cursor')
 expect(f.plans).toHaveLength(1);expect(f.plans[0]).toMatchObject({limit:7,cursor:'invalid'})
 await expect(page.getByRole('link',{name:'Next page',exact:true})).toHaveCount(0)
})

for(const override of [{version:'2'},{operation:'delete'},{limit:0}])test(`unsupported proposed values fail: ${JSON.stringify(override)}`,async({page})=>{
 const f=await fixture(page,{...reviewed,...override})
 await page.goto('/v2/explore?q=propose');await expect.poll(()=>f.plans.length).toBe(1)
 await acceptPlan(page)
 await expect(page.getByRole('alert')).toContainText('Could not run proposed plan:')
 expect(f.plans).toHaveLength(1)
})
