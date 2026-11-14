import React,{useEffect,useRef,useState} from 'react'
import {useAuth} from './Auth.jsx'
import {getAIJob,cancelAIJob,listAIJobs} from './ai.js'
import {Refs} from './product.jsx'

const terminalStates=new Set(['succeeded','failed','cancelled','dependency_blocked','budget_blocked'])
const cancellableStates=new Set(['queued','running','retry_wait'])
export const jobTerminal=job=>Boolean(job?.terminal||terminalStates.has(job?.state))
export const jobHistoryURL=id=>`/v2/system${id?`?job=${encodeURIComponent(id)}`:''}#ai-jobs`
const validationExplanations={null_collections:'The response does not include all required lists.',version_kind:'The response does not match the requested format or function.',limits:'The response exceeds the permitted limits.',labels_intent:'The labels or intent are outside the permitted set.',root_refs:'The citations do not match the authorized evidence.',claim_fields_refs:'A claim lacks valid fields or citations.',entity_fields_refs:'An entity lacks valid fields or citations.',role_fields_refs:'A role lacks valid fields or citations.',observable_extraction:'An observable could not be verified in the evidence.',plan:'The query plan does not meet the permitted contract.',identity:'The identity proposal does not meet the evidence contract.'}

// Only status reads are retried. Recovering an ID never submits or executes a plan.
export function useAIJob(id,initialJob=null){
 const {session}=useAuth(),csrf=session?.csrf,[state,setState]=useState({}),[refresh,setRefresh]=useState(0),pending=useRef(null)
 useEffect(()=>{
  if(!id||!csrf){setState({});return}
  const abort=new AbortController(),operation={abort,timer:null,version:0};pending.current=operation
  const initial=refresh===0?initialJob:null
  setState({id,csrf,job:initial,loading:!initial})
  function accept(job){setState({id,csrf,job});if(!jobTerminal(job))operation.timer=setTimeout(read,1500)}
  async function read(){const version=operation.version;try{const r=await getAIJob(id,{signal:abort.signal});if(!abort.signal.aborted&&version===operation.version)accept(r.data)}catch(error){if(!abort.signal.aborted&&version===operation.version)setState(s=>({...s,error:error.message,loading:false}))}}
  if(initial){if(!jobTerminal(initial))operation.timer=setTimeout(read,1500)}else read()
  return()=>{abort.abort();clearTimeout(operation.timer);if(pending.current===operation)pending.current=null}
 },[id,csrf,initialJob,refresh])
 async function cancel(){
  const operation=pending.current;if(!operation)return
  operation.version++;clearTimeout(operation.timer)
  setState(s=>({...s,busy:true,error:''}))
  try{const r=await cancelAIJob(id,csrf,{signal:operation.abort.signal});if(!operation.abort.signal.aborted)setState({id,csrf,job:r.data})}catch(error){if(!operation.abort.signal.aborted)setState(s=>({...s,busy:false,error:error.message}))}
 }
 const current=state.id===id&&state.csrf===csrf?state:{loading:Boolean(id)}
 return {...current,cancel,retry:()=>setRefresh(n=>n+1)}
}

export function JobPresentation({monitor,select=()=>{},onPlan}){
 const {job,loading,error,busy,cancel,retry}=monitor
 return <>{loading&&<p role="status">Loading AI job…</p>}{error&&<><p role="alert">Could not update AI job: {error}</p><button onClick={retry}>Retry status query</button></>}{job&&<><p role="status">AI status: {job.state} · Job {job.id}</p>{cancellableStates.has(job.state)&&<><button disabled={busy} onClick={cancel}>Cancel job</button><p>Cancellation prevents later publication. A call already sent may continue and still incur its cost.</p></>}{job.safe_error&&<p role="alert">{job.safe_error}</p>}{job.safe_error==='result_validation_failed'&&Object.hasOwn(validationExplanations,job.validation_reason)&&<p role="alert">{validationExplanations[job.validation_reason]}</p>}{job.result&&<><p>{job.function_id==='evidence.translate'?'Generated translation · not the original':'Generated result · does not confirm source claims'}</p><p>{job.result.text}</p>{job.result.labels?.length>0&&<p>Proposed labels: {job.result.labels.join(', ')}</p>}{job.result.claims?.map((claim,i)=><p key={i}>{claim.subject} {claim.predicate} {claim.object}<Refs items={claim.refs} select={select}/></p>)}<Refs items={job.result.refs} select={select}/>{job.result.plan&&<><pre>{JSON.stringify(job.result.plan,null,2)}</pre>{onPlan&&<button onClick={()=>onPlan(job.result.plan)}>Run this typed plan</button>}</>}</>}{[...new Set([...(job.limitations||[]),...(job.result?.limitations||[])])].map((limit,i)=><p className="v2-limit" key={i}>{limit}</p>)}</>}</>
}

function JobDetail({id,select}){
 const monitor=useAIJob(id)
 return <section aria-label="Selected AI job"><h3>Selected AI job</h3><JobPresentation monitor={monitor} select={select}/></section>
}

export default function AIJobs({url,navigate,select}){
 const {session}=useAuth(),csrf=session?.csrf,cursor=url.searchParams.get('ai_cursor')||'',id=url.searchParams.get('job')||'',[refresh,setRefresh]=useState(0),[state,setState]=useState({})
 useEffect(()=>{
  const abort=new AbortController();setState({cursor,csrf,loading:true})
  listAIJobs(cursor,{signal:abort.signal}).then(r=>{if(!abort.signal.aborted)setState({cursor,csrf,data:r.data})}).catch(e=>{if(!abort.signal.aborted)setState({cursor,csrf,error:e.message})})
  return()=>abort.abort()
 },[cursor,csrf,refresh])
 function change(values){const next=new URL(url);next.searchParams.delete('evidence');for(const [key,value]of Object.entries(values))value?next.searchParams.set(key,value):next.searchParams.delete(key);navigate(next.pathname+next.search+'#ai-jobs')}
 const current=state.cursor===cursor&&state.csrf===csrf?state:{loading:true}
 return <section id="ai-jobs" aria-label="AI jobs"><h2>AI jobs</h2><p>Your jobs across sessions. The list shows historical execution state; opening a result checks whether its evidence is still current.</p><p>If a submission response was lost, refresh this list to find a persisted job. Recovery does not send a new inference request.</p><button onClick={()=>{change({ai_cursor:''});setRefresh(n=>n+1)}}>Refresh AI jobs</button>{current.loading?<p role="status">Loading AI jobs…</p>:current.error?<p role="alert">Could not load AI jobs: {current.error}</p>:current.data&&<>{!current.data.jobs.length?<p>No AI jobs found.</p>:<ul className="v2-rows">{current.data.jobs.map(job=><li key={job.id}><a href={jobHistoryURL(job.id)} onClick={e=>{if(!e.ctrlKey&&!e.metaKey&&!e.shiftKey){e.preventDefault();change({job:job.id})}}}>{job.function_id} · {job.id}</a><p><time dateTime={job.created_at}>{job.created_at}</time> · {job.state}</p></li>)}</ul>}{current.data.next_cursor&&<button onClick={()=>change({ai_cursor:current.data.next_cursor})}>Older AI jobs</button>}{cursor&&<button onClick={()=>change({ai_cursor:''})}>Newest AI jobs</button>}</>}{id&&<><button onClick={()=>change({job:''})}>Close AI job</button><JobDetail key={`${csrf}:${id}`} id={id} select={select}/></>}</section>
}
