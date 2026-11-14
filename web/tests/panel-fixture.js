// Explicit synthetic data. Never contacts a provider or a production service.
export const meta = {generated_at:'2026-10-20T12:00:00Z',coverage:'partial · synthetic fixture',degraded:false}
export const evidence = {observation_id:'9007199254740993',revision:'2',hash:'fixture-digest',representation:'original',start:0,end:8}
const ids = ['semantic.classify','semantic.relevance','semantic.claims','semantic.entities_relations','semantic.observable_roles','identity.disambiguate','vulnerability.context','case.analyze','case.summarize','brief.compose','query.plan','query.explain','evidence.translate','source.triage']
const descriptions = ['Category and intent','Explained relevance','Source-attributed claims','Proposed entities and relationships','Observable roles','Identity hypotheses','CVE context; applicability unknown','Case analysis','Case summary','Changes and coverage brief','Typed query plan','Authorized result explanation','Translation linked to the original','Source assessment proposal']
export async function panelFixture(page,{authenticated=true,changes=false}={}) {
  let logged=authenticated
  let config={revision:1,credential_available:true,daily_cap_units:0,monthly_cap_units:0,max_concurrent:1,
    functions:ids.map((id,i)=>({id,description:descriptions[i]})),
    connections:[{id:'fixture-local',provider:'Test provider',adapter:'openai-chat',url:'https://fixture.invalid/v1/chat/completions',data_classes:['public-approved'],secret_present:true,secret_action:'unchanged'}],
    bindings:ids.map(function_id=>({function_id,enabled:false,connection_id:'fixture-local',model:'synthetic-model',structured_json:true,prompt_version:'1',schema_version:'1',policy_version:'1',limits:{max_input_tokens:4096,max_output_tokens:1024,deadline_ms:30000},daily_cap_units:0,monthly_cap_units:0,max_concurrent:1,price:{version:'fixture-v1',input_units_per_token:0,output_units_per_token:0}}))}
  const writes=[]
  await page.route('**/api/v2/**',async route=>{
    const req=route.request(),url=new URL(req.url()),path=url.pathname.replace('/api/v2','')
    const send=(data,status=200)=>route.fulfill({status,json:{data,meta},headers:{ETag:'"fixture-1"'}})
    if(path==='/auth/session')return logged?send({user:{username:'operator'},permissions:['read'],csrf:'fixture-csrf'}):route.fulfill({status:401,json:{error:{message:'Not signed in'}}})
    if(path==='/auth/login'){logged=true;return send({user:{username:'operator'},permissions:['read'],csrf:'fixture-csrf'})}
    if(path==='/auth/logout'){logged=false;return send(null)}
    if(path==='/today')return send({changes:changes?[{id:'fixture-change',case_id:'fixture-case',title:'Offer reported by one source',description:'Synthetic record to verify reading and provenance. The claim remains unconfirmed.',created_at:'2026-10-20T10:00:00Z',citations:[evidence]}]:[],brief:null})
    if(path==='/system')return send({status:'operational · fixture',backlog:0,oldest_job_at:null,ai:{status:'no inference'},errors:[],progress:{}})
    if(path==='/ai/config'){
      if(req.method()==='PUT'){
        const payload=req.postDataJSON();writes.push({payload,headers:req.headers()})
        config={...config,...payload,connections:payload.connections.map(c=>({...c,api_key:undefined,secret_present:c.secret_action==='set'||c.secret_present,secret_action:'unchanged'}))}
      }
      return send(config)
    }
    if(path==='/ai/validate')return send({valid:true})
    if(path==='/runtime-control')return send({revision:1,paused:false})
    if(path.startsWith('/evidence/'))return send({text:'Evidence retained to verify the reader. A reported offer does not establish a data breach.',hash:evidence.hash,representation:'original',source:'Test source · no live collection',revision:'2',retention_status:'retained',published_at:'2026-10-20T10:00:00Z',collected_at:'2026-10-20T10:02:00Z'})
    if(path==='/sources')return send([{id:'fixture-source',name:'Test channel · synthetic fixture',status:'paused',coverage:'partial',revision:1,policy_version:'fixture-v1',last_success_at:'2026-10-20T10:00:00Z'}])
    if(path==='/cases')return send([{id:'fixture-case',title:'Reported offer',status:'reported',revision:'2',summary:'A claim awaiting verification.',citations:[evidence]}])
    if(path==='/cases/fixture-case')return send({id:'fixture-case',title:'Reported offer',status:'reported',revision:'2',summary:'A claim awaiting verification.',citations:[evidence]})
    if(['/source-imports','/source-dispositions','/questions','/discovery','/coverage','/telegram/candidates','/claims','/cases/fixture-case/timeline'].includes(path))return send([])
    throw new Error(`Unexpected synthetic panel request: ${req.method()} ${path}`)
  })
  return {writes}
}
