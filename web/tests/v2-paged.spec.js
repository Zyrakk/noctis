import { test, expect } from '@playwright/test'

const meta={generated_at:'2026-11-14T00:00:00Z',coverage:'partial',degraded:false}
const proposal=name=>({id:name,endpoint:name,reason:'Synthetic proposal',revision:1,permission_status:'pending'})

test.beforeEach(async({page})=>{
  page.__errors=[]
  page.on('pageerror',error=>page.__errors.push(error.message))
  // Deliberately ignore AbortSignal: stale completions must be rejected by Paged,
  // even when cancellation cannot stop the transport or an already parsed body.
  await page.addInitScript(()=>{
    const fetch=window.fetch.bind(window)
    window.__paged={requests:[]}
    window.fetch=(input,options={})=>{
      const url=new URL(input,location.href)
      if(url.pathname!=='/api/v2/discovery')return fetch(input,options)
      return new Promise(resolve=>{
        const entry={url:url.href,signal:options.signal,consumed:false}
        entry.respond=(body,status)=>resolve({status,ok:status>=200&&status<300,json:async()=>{entry.consumed=true;return body}})
        window.__paged.requests.push(entry)
      })
    }
  })
  await page.route('**/api/v2/**',route=>{
    const path=new URL(route.request().url()).pathname
    const send=data=>route.fulfill({json:{data,meta}})
    if(path.endsWith('/auth/session'))return send({user:{username:'operator'},permissions:['read'],csrf:'synthetic'})
    if(path.endsWith('/questions'))return send([{id:'A',title:'Question A',revision:1,enabled:true,terms:[]}])
    if(path.endsWith('/today'))return send({changes:[],brief:null})
    if(['/sources','/source-imports','/telegram/candidates','/coverage'].some(suffix=>path.endsWith(suffix)))return send([])
    throw new Error(`Unexpected paged fixture request: ${path}`)
  })
})
test.afterEach(async({page})=>{expect(page.__errors).toEqual([])})

async function requestAt(page,index,{question='',cursor=null}={}){
  await expect.poll(()=>page.evaluate(()=>window.__paged.requests.length)).toBe(index+1)
  const request=await page.evaluate(index=>{
    const entry=window.__paged.requests[index],url=new URL(entry.url)
    return {question:url.searchParams.get('question_id'),cursor:url.searchParams.get('cursor'),hasSignal:!!entry.signal}
  },index)
  expect(request).toEqual({question,cursor,hasSignal:true})
}

async function respond(page,index,{names=[],cursor=null,error}={}){
  await page.evaluate(async({index,body,status})=>{
    window.__paged.requests[index].respond(body,status)
    // A render barrier, rather than a timeout, also observes ignored completions.
    await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))
  },{index,status:error?503:200,body:error?{error:{message:error}}:{data:names.map(proposal),meta:{...meta,next_cursor:cursor}}})
  expect(await page.evaluate(index=>window.__paged.requests[index].consumed,index)).toBe(true)
}

async function aborted(page,index){
  await expect.poll(()=>page.evaluate(index=>window.__paged.requests[index].signal?.aborted,index)).toBe(true)
}

function discovery(page){return page.getByRole('heading',{name:'Intelligence questions and discovery'}).locator('..')}
function rows(page){return discovery(page).locator('ul.v2-rows > li > strong')}
function more(page){return discovery(page).getByRole('button',{name:'Load more records',exact:true})}
async function open(page){
  const questions=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/v2/questions'&&response.ok())
  await page.goto('/v2/sources')
  await questions
  await expect(page.getByLabel('Question for coverage and proposal')).toBeVisible()
  await requestAt(page,0)
}
async function rapidClicks(button){await button.evaluate(element=>{element.click();element.click()})}

test('una continuación pendiente, reintento conserva filas y cursor y éxito limpia el error',async({page})=>{
  await open(page)
  await respond(page,0,{names:['First'],cursor:'next &/2'})
  await rapidClicks(more(page))
  await requestAt(page,1,{cursor:'next &/2'})
  await expect(more(page)).toBeDisabled()
  await expect(more(page)).toHaveAttribute('aria-busy','true')
  await expect(discovery(page).getByRole('status')).toHaveText('Loading more records…')
  await expect(rows(page)).toHaveText(['First'])
  await respond(page,1,{error:'Temporary continuation failure'})
  await expect(discovery(page).getByRole('alert')).toHaveText('Temporary continuation failure')
  await expect(rows(page)).toHaveText(['First'])
  await expect(more(page)).toBeEnabled()
  await rapidClicks(more(page))
  await requestAt(page,2,{cursor:'next &/2'})
  await respond(page,2,{names:['Second'],cursor:'next-3'})
  await expect(rows(page)).toHaveText(['First','Second'])
  await expect(discovery(page).getByRole('alert')).toHaveCount(0)
  await expect(discovery(page).getByRole('status')).toHaveCount(0)
  await more(page).click()
  await requestAt(page,3,{cursor:'next-3'})
  await respond(page,3,{names:['Third']})
  await expect(rows(page)).toHaveText(['First','Second','Third'])
  await expect(more(page)).toHaveCount(0)
})

for(const returnToA of [false,true])for(const failed of [false,true])for(const whileLoading of [false,true]){
  test(`carga inicial obsoleta ${failed?'fallida':'correcta'} en A→B${returnToA?'→A':''}, nueva carga ${whileLoading?'pendiente':'resuelta'}`,async({page})=>{
    await open(page)
    await page.getByLabel('Question for coverage and proposal').selectOption('A')
    await requestAt(page,1,{question:'A'})
    let current=1
    if(returnToA){
      await page.getByLabel('Question for coverage and proposal').selectOption('')
      await requestAt(page,2)
      current=2
    }
    await aborted(page,0)
    if(!whileLoading)await respond(page,current,{names:['Current'],cursor:'current-next'})
    await respond(page,0,failed?{error:'Stale initial failure'}:{names:['Stale initial'],cursor:'stale-next'})
    if(whileLoading){
      await expect(discovery(page).getByRole('status')).toHaveText('Loading data…')
      await expect(rows(page)).toHaveCount(0)
      await expect(more(page)).toHaveCount(0)
      await respond(page,current,{names:['Current'],cursor:'current-next'})
    }
    await expect(rows(page)).toHaveText(['Current'])
    await expect(discovery(page).getByRole('alert')).toHaveCount(0)
    await expect(more(page)).toBeEnabled()
    if(returnToA){
      await aborted(page,1)
      await respond(page,1,failed?{error:'Stale intermediate failure'}:{names:['Stale intermediate'],cursor:'other-next'})
      await expect(rows(page)).toHaveText(['Current'])
      await expect(discovery(page).getByRole('alert')).toHaveCount(0)
    }
    await more(page).click()
    await requestAt(page,current+1,{question:returnToA?'':'A',cursor:'current-next'})
    await respond(page,current+1,{names:['Current second']})
    await expect(rows(page)).toHaveText(['Current','Current second'])
    await expect(more(page)).toHaveCount(0)
  })
}

for(const returnToA of [false,true])for(const failed of [false,true]){
  test(`continuación obsoleta ${failed?'fallida':'correcta'} no libera la nueva en A→B${returnToA?'→A':''}`,async({page})=>{
    await open(page)
    await respond(page,0,{names:['Old first'],cursor:'old-next'})
    await more(page).click()
    await requestAt(page,1,{cursor:'old-next'})
    await page.getByLabel('Question for coverage and proposal').selectOption('A')
    await requestAt(page,2,{question:'A'})
    let current=2
    if(returnToA){
      await page.getByLabel('Question for coverage and proposal').selectOption('')
      await requestAt(page,3)
      current=3
      await respond(page,2,{names:['Old intermediate'],cursor:'intermediate-next'})
    }
    await respond(page,current,{names:['Current first'],cursor:'current-next'})
    await more(page).click()
    await requestAt(page,current+1,{question:returnToA?'':'A',cursor:'current-next'})
    await aborted(page,1)
    await respond(page,1,failed?{error:'Stale continuation failure'}:{names:['Stale page'],cursor:'stale-next'})
    await expect(rows(page)).toHaveText(['Current first'])
    await expect(discovery(page).getByRole('alert')).toHaveCount(0)
    await expect(more(page)).toBeDisabled()
    await expect(discovery(page).getByRole('status')).toHaveText('Loading more records…')
    await rapidClicks(more(page))
    await requestAt(page,current+1,{question:returnToA?'':'A',cursor:'current-next'})
    await respond(page,current+1,{names:['Current second'],cursor:'current-last'})
    await expect(rows(page)).toHaveText(['Current first','Current second'])
    await more(page).click()
    await requestAt(page,current+2,{question:returnToA?'':'A',cursor:'current-last'})
    await respond(page,current+2)
    await expect(more(page)).toHaveCount(0)
  })
}

for(const continuation of [false,true])for(const failed of [false,true]){
  test(`desmontar/remontar ignora ${continuation?'continuación':'carga inicial'} ${failed?'fallida':'correcta'} antigua`,async({page})=>{
    await open(page)
    let old=0
    if(continuation){
      await respond(page,0,{names:['Old first'],cursor:'old-next'})
      await more(page).click()
      await requestAt(page,1,{cursor:'old-next'})
      old=1
    }
    await page.getByRole('link',{name:'Today',exact:true}).click()
    await expect(page.getByRole('heading',{name:'Today',exact:true})).toBeVisible()
    await aborted(page,old)
    await page.getByRole('link',{name:'Sources',exact:true}).click()
    await requestAt(page,old+1)
    await respond(page,old+1,{names:['Remounted first'],cursor:'remounted-next'})
    await more(page).click()
    await requestAt(page,old+2,{cursor:'remounted-next'})
    await respond(page,old,failed?{error:'Unmounted failure'}:{names:['Unmounted row'],cursor:'unmounted-next'})
    await expect(rows(page)).toHaveText(['Remounted first'])
    await expect(discovery(page).getByRole('alert')).toHaveCount(0)
    await expect(more(page)).toBeDisabled()
    await expect(discovery(page).getByRole('status')).toHaveText('Loading more records…')
    await respond(page,old+2,{names:['Remounted second']})
    await expect(rows(page)).toHaveText(['Remounted first','Remounted second'])
    await expect(more(page)).toHaveCount(0)
  })
}

for(const continuation of [false,true]){
  test(`éxito antiguo de ${continuation?'continuación':'carga inicial'} conserva el error y cursor actuales`,async({page})=>{
    await open(page)
    let old=0
    if(continuation){
      await respond(page,0,{names:['Old first'],cursor:'old-next'})
      await more(page).click()
      await requestAt(page,1,{cursor:'old-next'})
      old=1
    }
    await page.getByLabel('Question for coverage and proposal').selectOption('A')
    await requestAt(page,old+1,{question:'A'})
    await respond(page,old+1,{names:['Current first'],cursor:'retry-current'})
    await more(page).click()
    await requestAt(page,old+2,{question:'A',cursor:'retry-current'})
    await respond(page,old+2,{error:'Current continuation failure'})
    await respond(page,old,{names:['Stale success'],cursor:'stale-next'})
    await expect(rows(page)).toHaveText(['Current first'])
    await expect(discovery(page).getByRole('alert')).toHaveText('Current continuation failure')
    await expect(more(page)).toBeEnabled()
    await more(page).click()
    await requestAt(page,old+3,{question:'A',cursor:'retry-current'})
    await respond(page,old+3,{names:['Current second']})
    await expect(rows(page)).toHaveText(['Current first','Current second'])
    await expect(discovery(page).getByRole('alert')).toHaveCount(0)
    await expect(more(page)).toHaveCount(0)
  })
}
