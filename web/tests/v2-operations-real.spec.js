import {test,expect} from '@playwright/test'
const base=process.env.NOCTIS_V2_E2E_URL,ids=JSON.parse(process.env.NOCTIS_V2_E2E_PRODUCT_IDS||'{}')
test.use({ignoreHTTPSErrors:true})
test.beforeEach(async({page},info)=>{test.skip(!base||(!ids.case_ops&&!info.title.startsWith('core005')),'Requiere runner HTTPS+PG --product');await page.goto(`${base}/v2/login`);await page.getByLabel('Username',{exact:true}).fill(process.env.NOCTIS_V2_E2E_USERNAME);await page.getByLabel('Password',{exact:true}).fill(process.env.NOCTIS_V2_E2E_PASSWORD);await page.getByRole('button',{name:'Sign in'}).click();await expect(page.getByRole('heading',{name:'Today',exact:true})).toBeVisible()})
async function api(page,path,body){const session=await (await page.request.get(`${base}/api/v2/auth/session`)).json();return page.request.post(`${base}/api/v2${path}`,{headers:{Origin:base,'X-CSRF-Token':session.data.csrf},data:{request_id:crypto.randomUUID(),...body}})}

test('core005 PIR actualizado activa su revisión vigente y revoke pausa la fuente creada',async({page})=>{
 const title=`PIR core005 ${crypto.randomUUID()}`
 await page.getByRole('link',{name:'Sources',exact:true}).click()
 await page.getByLabel('PIR question',{exact:true}).fill(title)
 await page.getByLabel('Monitoring term',{exact:true}).fill('OLD_CORE005')
 await page.getByRole('button',{name:'Create question and policy',exact:true}).click()
 const questionRow=page.getByRole('listitem').filter({hasText:title}).filter({has:page.getByRole('button',{name:'Update question with the form title and term'})})
 await expect(questionRow).toContainText('Revision 1')
 await page.getByLabel('Monitoring term',{exact:true}).fill('NEW_CORE005')
 await questionRow.getByRole('button',{name:'Update question with the form title and term'}).click()
 await expect(questionRow).toContainText('Revision 2')
 await expect(questionRow).toContainText('NEW_CORE005')
 await questionRow.getByRole('button',{name:'Pause question',exact:true}).click()
 await expect(questionRow).toContainText('Paused')
 await questionRow.getByRole('button',{name:'Resume question',exact:true}).click()
 await expect(questionRow).toContainText('Revision 4')
 const questions=await(await page.request.get(`${base}/api/v2/questions`)).json(),q=questions.data.find(q=>q.title===title)
 await page.getByRole('combobox',{name:'Question for coverage and proposal'}).selectOption(q.id)
 const endpoint=`https://synthetic.invalid/core005/${q.id}`
 await page.getByLabel('Proposed source URL').fill(endpoint)
 await page.getByLabel('Provenance and reason').fill('fixture sin acceso externo')
 await page.getByRole('button',{name:'Propose source',exact:true}).click()
 await expect(page.getByText(endpoint,{exact:true})).toBeVisible()
 expect((await api(page,'/permissions',{permission:'discovery_authorize',granted:true})).status()).toBe(200)
 await page.getByRole('button',{name:'Authorize with explicit policy',exact:true}).click()
 await expect(page.getByText(/Permission authorized/)).toBeVisible()
 await page.getByRole('button',{name:'Activate authorized source with PIR policy',exact:true}).click()
 await expect(page.getByRole('status').filter({hasText:'"source_id"'})).toBeVisible()
 const proposals=await(await page.request.get(`${base}/api/v2/discovery?question_id=${q.id}`)).json(),proposal=proposals.data[0]
 const sources=await(await page.request.get(`${base}/api/v2/sources`)).json(),source=sources.data.find(s=>s.id===proposal.source_id)
 expect(source.policy_version).toBe(`question:${q.id}:r4`)
 await page.getByRole('button',{name:'Revoke authorization',exact:true}).click()
 await expect(page.getByText(/Permission revoked/)).toBeVisible()
 const revoked=await(await page.request.get(`${base}/api/v2/sources`)).json()
 expect(revoked.data.find(s=>s.id===proposal.source_id).status).toBe('paused')
 await expect(page.getByRole('button',{name:'Activate authorized source with PIR policy',exact:true})).toBeDisabled()
})

test('atención CAS409 conserva contexto; visto y seguimiento no confirman; export privado expira',async({page})=>{
 await page.goto(`${base}/v2/cases/${ids.case_ops}`);await expect(page.getByRole('button',{name:'Mark as seen',exact:true})).toBeEnabled()
 const claims=await (await page.request.get(`${base}/api/v2/claims?case_id=${ids.case_ops}`)).json();expect(claims.data.every(c=>c.status==='source_claim')).toBeTruthy()
 const att=await (await page.request.get(`${base}/api/v2/cases/${ids.case_ops}/attention`)).json();expect((await api(page,`/cases/${ids.case_ops}/attention`,{expected_revision:att.data.revision,action:'seen'})).status()).toBe(200)
 await page.getByLabel('Reason or pending action').fill('Esperar evidencia independiente; conservar este contexto')
 const deadline=await page.evaluate(()=>{const d=new Date(Date.now()+3600000);d.setMinutes(d.getMinutes()-d.getTimezoneOffset());return d.toISOString().slice(0,16)});await page.getByLabel('Attention deadline').fill(deadline)
 await page.getByRole('button',{name:'Silence until change',exact:true}).click();await expect(page.getByRole('alert').filter({hasText:'Conflict:'})).toBeVisible();await expect(page.getByLabel('Reason or pending action')).toHaveValue('Esperar evidencia independiente; conservar este contexto');await expect(page.getByLabel('Attention deadline')).toHaveValue(deadline)
 await page.getByRole('button',{name:'Reload attention revision'}).click();await expect(page.getByText(/Attention revision 2/)).toBeVisible();await page.getByRole('button',{name:'Silence until change',exact:true}).click();await expect(page.getByText(/Mode: silent_until_change/)).toBeVisible()
 await page.getByRole('combobox',{name:'Case tracking'}).selectOption('archived');await expect(page.getByText(/Mode: automatic/)).toBeVisible()
 const after=await (await page.request.get(`${base}/api/v2/claims?case_id=${ids.case_ops}`)).json();expect(after.data.every(c=>c.status==='source_claim')).toBeTruthy()
 await page.getByRole('link',{name:'System',exact:true}).click();await page.getByRole('button',{name:'Grant permission for exports',exact:true}).click();await expect(page.getByRole('status').filter({hasText:'"granted":true'})).toBeVisible()
 await page.goto(`${base}/v2/cases/${ids.case_ops}`);await page.getByRole('button',{name:'Export case',exact:true}).click();const download=page.getByRole('link',{name:'Download private server export'});await expect(download).toBeVisible();const exported=await (await page.request.get(new URL(await download.getAttribute('href'),base).toString())).json();expect(exported.data.citations[0].label).toBe('original');expect(exported.data.claims.every(c=>c.status==='source_claim')).toBeTruthy()
 const expired=await page.request.get(`${base}/api/v2/exports/${ids.export_expired}`);expect(expired.status()).toBe(410)
})

test('paginación real de afirmaciones y discovery cierra pruebas vencidas o revocadas',async({page})=>{
 await page.goto(`${base}/v2/cases/${ids.case_ops}`);await expect(page.getByText(/Afirmación paginada/)).toHaveCount(50);await page.getByRole('button',{name:'Load more records',exact:true}).click();await expect(page.getByText(/Afirmación paginada/)).toHaveCount(51)
 await page.getByRole('link',{name:'Sources',exact:true}).click();await expect(page.getByRole('heading',{name:'Intelligence questions and discovery'})).toBeVisible();await page.getByRole('combobox',{name:'Question for coverage and proposal'}).selectOption(ids.question_ops)
 await expect(page.getByText(/Permission authorized/)).toBeVisible();await page.getByRole('button',{name:'Try source · 60 seconds · quota 1'}).first().click();await expect(page.getByRole('alert').filter({hasText:/source authorization required/})).toBeVisible()
 for(const id of [ids.proposal_expired,ids.proposal_revoked]){const response=await api(page,`/discovery/${id}/trial`,{expected_revision:1,ttl_seconds:60,quota:1,action:'run'});expect(response.status()).toBe(403)}
 await expect(page.getByText(/no authorized source/)).toBeVisible()
})

test('operational CAS preserves drafts and intentions across two real sessions without replay',async({page,browser})=>{
 const second=await browser.newContext({ignoreHTTPSErrors:true}),other=await second.newPage(),writes=[]
 let initialControl
 page.on('request',req=>{if(req.method()==='POST'&&/\/api\/v2\/(sources\/.*\/policy|runtime-control|retention)$/.test(new URL(req.url()).pathname))writes.push(req.postDataJSON())})
 try{
  await other.goto(`${base}/v2/login`);await other.getByLabel('Username',{exact:true}).fill(process.env.NOCTIS_V2_E2E_USERNAME);await other.getByLabel('Password',{exact:true}).fill(process.env.NOCTIS_V2_E2E_PASSWORD);await other.getByRole('button',{name:'Sign in'}).click();await expect(other.getByRole('heading',{name:'Today',exact:true})).toBeVisible()
  const source=(await(await page.request.get(`${base}/api/v2/sources`)).json()).data.find(s=>s.id===ids.source_ops)
  expect(source).toBeTruthy()
  await page.goto(`${base}/v2/sources`)
  const row=page.getByRole('listitem').filter({has:page.getByText(source.name,{exact:true})}).filter({has:page.getByText('Source policy and pause',{exact:true})})
  await row.locator('summary').click();await row.getByLabel('Collection authorized and active').uncheck()
  const changed=await api(other,`/sources/${source.id}/policy`,{expected_revision:source.policy_revision,enabled:source.enabled,policy_version:source.policy_version});expect(changed.status()).toBe(200)
  const changedSource=(await changed.json()).data
  await row.getByRole('button',{name:'Save source policy',exact:true}).click();await expect(row.getByText(/Revision conflict/)).toBeVisible()
  await row.getByRole('button',{name:'Reload current source',exact:true}).click();await expect(row.getByText(`Confirmed source revision ${changedSource.policy_revision}`,{exact:false})).toBeVisible();await expect(row.getByLabel('Collection authorized and active')).not.toBeChecked();expect(writes).toHaveLength(1)
  await row.getByRole('button',{name:'Save source policy',exact:true}).click();await expect(row.getByText(/Policy and pause saved/)).toBeVisible();await expect(row.getByText(/Status: paused/)).toBeVisible();expect(writes[1].expected_revision).toBe(changedSource.policy_revision)
  await page.goto(`${base}/v2/system`);const control=page.getByRole('region',{name:'Processing control'})
  await expect(control.getByText(/Confirmed control revision/)).toBeVisible()
  const current=(await(await other.request.get(`${base}/api/v2/runtime-control`)).json()).data,intent=current.paused?'resume':'pause';initialControl=current
  expect((await api(other,'/runtime-control',{expected_revision:current.revision,action:intent,reason:'second synthetic session'})).status()).toBe(200)
  await control.getByRole('button',{name:intent==='pause'?'Pause processing':'Resume processing',exact:true}).click();await expect(control.getByText(/Revision conflict/)).toBeVisible()
  await control.getByRole('button',{name:'Reload processing control'}).click();await expect(control.getByText(/already satisfies your requested action/)).toBeVisible();expect(writes).toHaveLength(3)
  expect((await api(other,'/permissions',{permission:'retention',granted:true})).status()).toBe(200)
  await page.getByText('Retention by source and class',{exact:true}).click();await page.getByLabel('Source UUID',{exact:true}).fill(source.id)
  const retention=page.getByRole('region',{name:'Retention policy'});await expect(retention.getByText(/Confirmed retention revision/)).toBeVisible();await retention.getByLabel('Retention in seconds',{exact:true}).fill('7200')
  const policyPath=`/retention?source_id=${source.id}&data_class=private`,policy=(await(await other.request.get(`${base}/api/v2${policyPath}`)).json()).data
  const updated=await api(other,'/retention',{source_id:source.id,data_class:'private',action:'policy',expected_revision:policy.revision,retain_seconds:3600});expect(updated.status()).toBe(200);const revision=(await updated.json()).data.revision
  await retention.getByRole('button',{name:'Save retention policy',exact:true}).click();await expect(retention.getByText(/Revision conflict/)).toBeVisible()
  await retention.getByRole('button',{name:'Reload current retention policy'}).click();await expect(retention.getByText(`Confirmed retention revision ${revision}`,{exact:false})).toBeVisible();await expect(retention.getByLabel('Retention in seconds',{exact:true})).toHaveValue('7200');expect(writes).toHaveLength(4)
  await retention.getByRole('button',{name:'Save retention policy',exact:true}).click();await expect(retention.getByText('Retention policy saved.',{exact:true})).toBeVisible();expect(writes[4].expected_revision).toBe(revision)
  expect(writes.filter(w=>w.action==='run'||w.action==='batch')).toHaveLength(0)
 }finally{
  if(initialControl){const current=(await(await other.request.get(`${base}/api/v2/runtime-control`)).json()).data;if(current.paused!==initialControl.paused)expect((await api(other,'/runtime-control',{expected_revision:current.revision,action:initialControl.paused?'pause':'resume',reason:'restore synthetic test control'})).status()).toBe(200)}
  await second.close()
 }
})
