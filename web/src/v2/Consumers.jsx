import React,{useEffect,useRef,useState} from 'react'
import {Timestamp} from './Timestamp.jsx'
import {useAuth} from './Auth.jsx'
import {submitAIJob,executeQuery} from './ai.js'
import {useAIJob,JobPresentation,jobTerminal,jobHistoryURL} from './AIJobs.jsx'
import {validEvidenceRef} from './api.js'
import {Refs,PageLink} from './product.jsx'
import {readTypedQuery,typedQueryURL,editedTypedQueryURL} from './typed-query.js'

export function AIAction({functionID,input,label,select=()=>{},onPlan}){
 const {session}=useAuth(),[submitted,setSubmitted]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false),requestID=useRef(null),controller=useRef(null)
 const monitor=useAIJob(submitted?.id,submitted),terminal=jobTerminal(monitor.job)
 useEffect(()=>{setSubmitted(null);setError('');setBusy(false);requestID.current=null;return()=>controller.current?.abort()},[session.csrf])
 async function submit(){setBusy(true);setError('');controller.current?.abort();const abort=new AbortController();controller.current=abort;if(!requestID.current||terminal)requestID.current=crypto.randomUUID();try{const r=await submitAIJob({function_id:functionID,input,request_id:requestID.current},session.csrf,{signal:abort.signal});if(!abort.signal.aborted)setSubmitted(r.data)}catch(e){if(!abort.signal.aborted)setError(e.message)}finally{if(!abort.signal.aborted)setBusy(false)}}
 return <section className="v2-job"><div className="v2-job-command"><button disabled={busy||Boolean(submitted&&!terminal)} onClick={submit}>{label}</button><small>Optional · needs AI setup and budget</small></div><a href={jobHistoryURL(submitted?.id)}>Open AI jobs history</a>{busy&&<p role="status">Submitting request…</p>}{error&&<><p role="alert">{error}</p><p>The response may have been lost after saving the job. Check AI jobs history before submitting again.</p></>}<JobPresentation monitor={monitor} select={select} onPlan={onPlan}/></section>
}

export function TypedQuery({url,navigate,select}){
 const {session}=useAuth(),{plan,limitValue,error,started}=readTypedQuery(url),{text:q,entity,mode,filters}=plan
 const planKey=JSON.stringify(plan),[state,setState]=useState({key:planKey}),[reviewError,setReviewError]=useState(null)
 useEffect(()=>{if(!started||error)return;const abort=new AbortController();setState({key:planKey,loading:true});executeQuery(JSON.parse(planKey),session.csrf,{signal:abort.signal}).then(result=>{if(!abort.signal.aborted)setState({key:planKey,result})}).catch(error=>{if(!abort.signal.aborted)setState({key:planKey,error})});return()=>abort.abort()},[planKey,session.csrf,started,error])
 function go(next){setReviewError(null);navigate(next.pathname+next.search)}
 function reviewPlan(proposed){try{go(typedQueryURL(url,proposed))}catch(error){setReviewError({key:planKey,message:error.message})}}
 function openDossier(id){const next=new URL(url);next.searchParams.set('view','entities');next.searchParams.set('entity',id);next.searchParams.delete('cursor');next.searchParams.delete('evidence');go(next)}
 const current=state.key===planKey?state:{loading:true}
 return <section><h2>Typed query</h2><p>Exact or full-text search without AI. Natural language queries propose a plan limited to authorized operations.</p>
  <form key={`${planKey}-${limitValue}`} onSubmit={e=>{e.preventDefault();go(editedTypedQueryURL(url,Object.fromEntries(new FormData(e.currentTarget))))}}>
   <label>Query<input name="q" defaultValue={q}/></label>
   <label>Search in<select name="entity_type" defaultValue={entity}>{!['observations','cases','entities','observables'].includes(entity)&&<option value={entity}>Unsupported: {entity}</option>}{[['observations','Observations'],['cases','Cases'],['entities','Entities'],['observables','Observables']].map(([key,label])=><option key={key} value={key}>{label}</option>)}</select></label>
   <label>Mode<select name="mode" defaultValue={mode}>{!['exact','fulltext'].includes(mode)&&<option value={mode}>Unsupported: {mode}</option>}<option value="exact">Exact</option><option value="fulltext">Full text</option></select></label>
   {['source_id','case_id','kind'].map((key,i)=><label key={key}>{['Source ID','Case ID','Type'][i]}<input name={key} defaultValue={filters[key]??''}/></label>)}
   <label>Limit<input name="limit" inputMode="numeric" defaultValue={limitValue}/></label><button>Run query</button>
  </form>
  {reviewError?.key===planKey&&<p role="alert">Could not run proposed plan: {reviewError.message}</p>}
  {error?<p role="alert">Could not run query: {error}</p>:!started?<p>Enter criteria or run an empty query to search the authorized archive.</p>:<>
   {current.loading?<p role="status">Running query…</p>:current.error?<p role="alert">Could not run query: {current.error.message}</p>:current.result&&<>
    <aside className="v2-coverage">Coverage: {current.result.meta?.coverage||'unknown'} · Updated <Timestamp value={current.result.meta?.generated_at}/>{current.result.meta?.degraded&&<strong>Query degraded; results may be incomplete.</strong>}</aside>
    {!current.result.data.rows?.length?<p>No results for this query.</p>:<ul className="v2-rows">{current.result.data.rows.map((row,i)=><li key={row.id||i}><strong>{row.title||row.alias||row.value||row.id}</strong><p>{row.summary||row.text||row.kind}</p>{row.case_id&&<a href={`/v2/cases/${encodeURIComponent(row.case_id)}`} onClick={e=>{e.preventDefault();navigate(`/v2/cases/${encodeURIComponent(row.case_id)}`)}}>Open case</a>}{entity==='cases'&&<a href={`/v2/cases/${encodeURIComponent(row.id)}`} onClick={e=>{e.preventDefault();navigate(`/v2/cases/${encodeURIComponent(row.id)}`)}}>Open case</a>}{entity==='entities'&&<button onClick={()=>openDossier(row.id)}>Open dossier</button>}<Refs items={row.citations||row.refs||(validEvidenceRef(row.ref)?[row.ref]:[])} select={select}/></li>)}</ul>}
    <PageLink url={url} navigate={navigate} cursor={current.result.data.next_cursor}/><AIAction key={`explain-${current.result.data.id}`} functionID="query.explain" input={{kind:'query_result',id:current.result.data.id}} label="Explain results with AI" select={select}/>
   </>}
  </>}
  {q.trim()&&<AIAction key={`plan-${q}`} functionID="query.plan" input={{kind:'query',text:q}} label="Propose plan with AI" select={select} onPlan={reviewPlan}/>}
 </section>
}
