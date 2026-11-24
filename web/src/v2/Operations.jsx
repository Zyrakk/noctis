import React,{useEffect,useRef,useState} from 'react'
import {request} from './api.js'
import {useAuth} from './Auth.jsx'

export function Paged({path,children}){
 const[state,setState]=useState({path,loading:true,items:[]})
 const active=useRef(null)
 const current=load=>active.current===load&&!load.controller.signal.aborted
 useEffect(()=>{
  const load={path,controller:new AbortController(),cursor:null,pending:null}
  active.current=load
  setState({path,load,loading:true,items:[]})
  request(path,{signal:load.controller.signal}).then(r=>{
   if(!current(load))return
   load.cursor=r.meta?.next_cursor
   setState(s=>current(load)?{path,load,items:r.data,meta:r.meta}:s)
  }).catch(e=>{if(current(load))setState(s=>current(load)?{path,load,items:[],error:e.message}:s)})
  return()=>{if(active.current===load)active.current=null;load.controller.abort()}
 },[path])
 async function more(){
  const load=active.current
  if(!load||load.path!==path||load.pending||!load.cursor)return
  // Acquire before React renders, and retain the exact cursor for this request.
  const page={cursor:load.cursor}
  load.pending=page
  setState(s=>current(load)&&s.load===load?{...s,moreLoading:true}:s)
  try{
   const r=await request(`${path}${path.includes('?')?'&':'?'}cursor=${encodeURIComponent(page.cursor)}`,{signal:load.controller.signal})
   if(!current(load)||load.pending!==page)return
   load.cursor=r.meta?.next_cursor
   setState(s=>current(load)&&s.load===load?{...s,items:[...s.items,...r.data],meta:r.meta,error:undefined,moreLoading:false}:s)
  }catch(e){
   if(current(load)&&load.pending===page)setState(s=>current(load)&&s.load===load?{...s,error:e.message,moreLoading:false}:s)
  }finally{
   if(current(load)&&load.pending===page)load.pending=null
  }
 }
 if(state.path!==path||state.loading)return <p role="status">Loading data…</p>
 return <>{state.error&&<p role="alert">{state.error}</p>}{children(state.items,state.meta||{})}{state.meta?.next_cursor&&<button disabled={state.moreLoading} aria-busy={!!state.moreLoading} onClick={more}>Load more records</button>}{state.moreLoading&&<p role="status">Loading more records…</p>}</>
}
function useMutation(){const{session}=useAuth();return (path,body)=>request(path,{method:'POST',headers:{'X-CSRF-Token':session.csrf},body:JSON.stringify({request_id:crypto.randomUUID(),...body})})}

export function CaseActions({id,revision,onChanged}){
 const mutate=useMutation(),[attention,setAttention]=useState(null),[reason,setReason]=useState(''),[deadline,setDeadline]=useState(''),[error,setError]=useState(''),[notice,setNotice]=useState(''),[download,setDownload]=useState(null),[busy,setBusy]=useState(false)
 async function load(){try{const r=await request(`/cases/${id}/attention`);setAttention(r.data)}catch(e){setError(e.message)}}
 useEffect(()=>{load()},[id,revision])
 async function action(kind){setBusy(true);setError('');setNotice('');try{
  const r=await mutate(`/cases/${id}/attention`,{action:kind,expected_revision:attention.revision,reason,deadline:deadline?new Date(deadline).toISOString():null});setAttention(r.data);setNotice('Attention updated; claims remain unconfirmed.')
 }catch(e){setError(e.status===409?`Conflict: current revision ${e.currentRevision??'unknown'}. The reason and deadline are preserved; reload the revision before resubmitting.`:e.message)}finally{setBusy(false)}}
 async function exportCase(){setBusy(true);setError('');try{const r=await mutate(`/cases/${id}/exports`,{expected_revision:Number(revision),format:'json'});setDownload(r.data)}catch(e){setError(e.message)}finally{setBusy(false)}}
 async function lifecycle(value){setError('');try{await mutate(`/cases/${id}/lifecycle`,{expected_revision:Number(revision),action:value});onChanged?.()}catch(e){setError(e.status===409?'The case changed. Reload before updating its tracking status.':e.message)}}
 return <section aria-label="Case attention"><h2>Attention and tracking</h2><p>Marking a case as seen, resolved or archived does not confirm claims. Material changes and deadlines reopen attention.</p>{attention&&<p>Mode: {attention.mode} · Attention revision {attention.revision} · Seen through revision {attention.seen_revision}{attention.reason&&` · ${attention.reason}`}</p>}<label>Reason or pending action<textarea value={reason} onChange={e=>setReason(e.target.value)}/></label><label>Attention deadline<input type="datetime-local" value={deadline} onChange={e=>setDeadline(e.target.value)}/></label><div className="v2-actions">{[['seen','Mark as seen'],['silence','Silence until change'],['exception','Record exception'],['resume','Reopen attention']].map(([kind,label])=><button key={kind} disabled={busy||!attention} onClick={()=>action(kind)}>{label}</button>)}<button onClick={load}>Reload attention revision</button><button disabled={busy} onClick={exportCase}>Export case</button></div><label>Case tracking<select defaultValue="" onChange={e=>{if(e.target.value)lifecycle(e.target.value)}}><option value="">Change tracking status…</option><option value="following">Following</option><option value="resolved">Resolved</option><option value="archived">Archived</option></select></label>{download&&<p><a href={download.download_url}>Download private server export</a> · Expires {download.expires_at}</p>}{notice&&<p role="status">{notice}</p>}{error&&<p role="alert">{error}</p>}</section>
}

// Each editor owns its in-flight work. Unmounting a context invalidates its
// responses, including when an operator returns to the same source/class later.
function useEditor(){
 const alive=useRef(false),pending=useRef(false),[busy,setBusy]=useState(false)
 useEffect(()=>{alive.current=true;return()=>{alive.current=false}},[])
 return {alive,busy,start(){if(pending.current)return false;pending.current=true;setBusy(true);return true},finish(){pending.current=false;if(alive.current)setBusy(false)}}
}
export function SourcePolicy({item,onReload,onChanged}){
 const mutate=useMutation(),editor=useEditor(),[confirmed,setConfirmed]=useState(item),[policy,setPolicy]=useState(item.policy_version||''),[enabled,setEnabled]=useState(item.enabled??(item.status!=='paused')),[conflict,setConflict]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('')
 async function reload(){if(!editor.start())return;setError('');try{const current=await onReload();if(editor.alive.current){setConfirmed(current);onChanged(current);setConflict(false);setNotice('Current source loaded. Your draft is preserved; review the differences before saving.')}}catch(e){if(editor.alive.current)setError(e.message)}finally{editor.finish()}}
 async function save(){
  if(!editor.start())return;setError('');setNotice('')
  try{
   const r=await mutate(`/sources/${item.id}/policy`,{expected_revision:confirmed.policy_revision,enabled,policy_version:policy})
   if(!editor.alive.current)return
   setConfirmed(current=>({...current,...r.data}));setConflict(false);setNotice('Policy and pause saved. Cursors preserved.')
   try{const current=await onReload();if(editor.alive.current){setConfirmed(current);onChanged(current)}}catch(e){if(editor.alive.current){setNotice('Save confirmed. Source view pending refresh; reload to update it.');setError(e.message)}}
  }catch(e){if(editor.alive.current){setConflict(e.code==='stale_revision');setError(e.code==='stale_revision'?'The policy changed. Reload the current source; your draft is preserved.':e.message)}}finally{editor.finish()}
 }
 return <details><summary>Source policy and pause</summary><p>Confirmed source revision {confirmed.policy_revision} · Policy {confirmed.policy_version||'none'} · Collection {confirmed.enabled?'active':'paused'}</p><label>PIR policy version<input value={policy} onChange={e=>setPolicy(e.target.value)}/></label><label><input type="checkbox" checked={enabled} onChange={e=>setEnabled(e.target.checked)}/>Collection authorized and active</label><p>Draft: policy {policy||'none'} · Collection {enabled?'active':'paused'}</p><button disabled={editor.busy||conflict} onClick={save}>Save source policy</button><button disabled={editor.busy} onClick={reload}>Reload current source</button>{conflict&&<p role="alert">Revision conflict. Reload required before another save.</p>}{notice&&<p role="status">{notice}</p>}{error&&<p role="alert">{error}</p>}</details>
}

export function TelegramOnboarding(){
 const mutate=useMutation(),[refresh,setRefresh]=useState(0),[error,setError]=useState(''),[notice,setNotice]=useState('')
 async function importCandidate(item){setError('');try{await mutate('/telegram/import',{snapshot_id:item.snapshot_id,peer_id:Number(item.peer_id)});setNotice('Channel imported. Configure its PIR policy and explicitly activate it in the source list.');setRefresh(n=>n+1)}catch(e){setError(e.message)}}
 return <section aria-label="Telegram channels"><h2>Current Telegram channels</h2><p>Importing preserves the pause; collection requires a PIR policy, explicit activation and current consent. History is not imported.</p><Paged key={refresh} path="/telegram/candidates">{items=>items.length?<ul className="v2-rows">{items.map(item=><li key={`${item.snapshot_id}:${item.peer_id}`}><strong>{item.name||`Channel ${item.peer_id}`}</strong><p>ID {item.peer_id} · {item.provenance} · {item.created_at}</p><button disabled={!!item.source_id} onClick={()=>importCandidate(item)}>{item.source_id?'Imported · review its policy':'Import paused channel'}</button></li>)}</ul>:<p>No candidates. Run the protected inventory for the current session with collection stopped.</p>}</Paged>{notice&&<p role="status">{notice}</p>}{error&&<p role="alert">{error}</p>}</section>
}

export function Discovery(){
 const mutate=useMutation(),[refresh,setRefresh]=useState(0),[question,setQuestion]=useState(''),[title,setTitle]=useState(''),[term,setTerm]=useState(''),[endpoint,setEndpoint]=useState(''),[reason,setReason]=useState(''),[kind,setKind]=useState('html'),[error,setError]=useState(''),[notice,setNotice]=useState('')
 async function perform(path,body){setError('');setNotice('');try{const r=await mutate(path,body);setNotice(JSON.stringify(r.data));setRefresh(n=>n+1);return r.data}catch(e){setError(e.status===409?'The proposal changed. Reload its revisions; the form is preserved.':e.message)}}
 return <section><h2>Intelligence questions and discovery</h2><p>Proposals do not grant access. Authorization requires separate permission and an explicit policy; reading does not contact sources. Unknown coverage and independence are preserved.</p><form onSubmit={e=>{e.preventDefault();perform('/questions',{title,terms:[{type:'keyword',value:term}]})}}><label>Priority intelligence requirement<input required value={title} onChange={e=>setTitle(e.target.value)}/></label><label>Monitoring term<input required value={term} onChange={e=>setTerm(e.target.value)}/></label><button>Create question and policy</button></form><Paged key={`q${refresh}`} path="/questions">{items=><><label>Question for coverage and proposal<select value={question} onChange={e=>setQuestion(e.target.value)}><option value="">All questions</option>{items.map(q=><option key={q.id} value={q.id}>{q.title} · Policy question:{q.id}{q.revision>1?`:r${q.revision}`:''}</option>)}</select></label><ul>{items.map(q=><li key={q.id}>{q.title} · Revision {q.revision} · {q.enabled?'Active':'Paused'} · Terms {JSON.stringify(q.terms)} <button onClick={()=>perform(`/questions/${q.id}/policy`,{expected_revision:q.revision,enabled:!q.enabled})}>{q.enabled?'Pause question':'Resume question'}</button><button onClick={()=>perform(`/questions/${q.id}/policy`,{expected_revision:q.revision,enabled:q.enabled,title:title||q.title,terms:term?[{type:'keyword',value:term}]:q.terms})}>Update question with the form title and term</button></li>)}</ul></>}</Paged><form onSubmit={e=>{e.preventDefault();perform('/discovery',{question_id:question,kind,endpoint,reason,provenance:{origin:'operator',reason}})}}><label>Proposed source URL<input type="url" required value={endpoint} onChange={e=>setEndpoint(e.target.value)}/></label><label>Adapter<select value={kind} onChange={e=>setKind(e.target.value)}>{['html','paste','forum','rss','atom'].map(k=><option key={k}>{k}</option>)}</select></label><label>Provenance and reason<textarea required value={reason} onChange={e=>setReason(e.target.value)}/></label><button disabled={!question}>Propose source</button></form><Paged key={`d${refresh}`} path={`/discovery?question_id=${encodeURIComponent(question)}`}>{items=>items.length?<ul className="v2-rows">{items.map(p=><li key={p.id}><strong>{p.endpoint}</strong><p>{p.reason} · Permission {p.permission_status} · Revision {p.revision} · Expires {p.expires_at}</p><p>Independence: {p.independence}. Score: {JSON.stringify(p.score)}</p><p>Provenance: {JSON.stringify(p.provenance)}</p><button onClick={()=>perform(`/discovery/${p.id}/authorize`,{expected_revision:p.revision,policy:{allowed:true,purpose:reason||p.reason}})}>Authorize with explicit policy</button><button onClick={()=>perform(`/discovery/${p.id}/trial`,{expected_revision:p.revision,ttl_seconds:60,quota:1,action:'run'})}>Try source · 60 seconds · quota 1</button><button disabled={p.permission_status!=='authorized'||!!p.source_id} onClick={()=>perform(`/discovery/${p.id}/activate`,{expected_revision:p.revision,policy_version:p.policy_version,adapter_config:{parser_version:'web-text-v1',max_items:100}})}>Activate authorized source with PIR policy</button><button onClick={()=>perform(`/discovery/${p.id}/revoke`,{expected_revision:p.revision})}>Revoke authorization</button>{p.trial&&<p>Trial: {p.trial.state} · Usage {p.trial.used}/{p.trial.quota} · {p.trial.last_error||p.trial.coverage} · Expires {p.trial.expires_at}</p>}</li>)}</ul>:<p>No proposals for this question.</p>}</Paged><h3>Coverage by question</h3><Paged key={`c${refresh}`} path={`/coverage?question_id=${encodeURIComponent(question)}`}>{items=><ul className="v2-rows">{items.map((v,i)=><li key={i}>{v.question} · Source {v.source_id||'no authorized source'}<p>Permission {String(v.permission)} · Paused {String(v.paused)} · Coverage {v.coverage} · Independence {v.independence}</p><p>Last success {v.last_success_at||'unknown'} · Lag {v.lag_seconds??'unknown'} seconds · Error {v.error||'no recorded error'}</p></li>)}</ul>}</Paged>{notice&&<p role="status">{notice}</p>}{error&&<p role="alert">{error}</p>}</section>
}

function RuntimeControl(){
 const mutate=useMutation(),editor=useEditor(),[control,setControl]=useState(null),[intent,setIntent]=useState(null),[conflict,setConflict]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('')
 async function load(){
  if(!editor.start())return;setError('')
  try{const r=await request('/runtime-control');if(editor.alive.current){setControl(r.data);setConflict(false);setNotice(intent&&r.data.paused===(intent==='pause')?'Current state already satisfies your requested action. No write is needed.':'Current control loaded. Your requested action is preserved.')}}catch(e){if(editor.alive.current)setError(e.message)}finally{editor.finish()}
 }
 useEffect(()=>{load()},[])
 const action=intent||(control?.paused?'resume':'pause'),satisfied=!!intent&&control?.paused===(intent==='pause')
 async function save(){
  if(!control||conflict||satisfied||!editor.start())return
  setIntent(action);setError('');setNotice('')
  try{const r=await mutate('/runtime-control',{expected_revision:control.revision,action,reason:'operator product control'});if(editor.alive.current){setControl(r.data);setIntent(null);setConflict(false);setNotice('Processing control saved.')}}catch(e){if(editor.alive.current){setConflict(e.code==='stale_revision');setError(e.code==='stale_revision'?'The processing control changed. Reload before retrying your requested action.':e.message)}}finally{editor.finish()}
 }
 return <section aria-label="Processing control">{control&&<p>Confirmed control revision {control.revision} · Processing {control.paused?'paused':'active'}</p>}{intent&&<p>Requested action: {intent}</p>}<button disabled={editor.busy||!control||conflict||satisfied} onClick={save}>{action==='resume'?'Resume processing':'Pause processing'}</button><button disabled={editor.busy} onClick={load}>Reload processing control</button>{intent&&<button disabled={editor.busy} onClick={()=>{setIntent(null);setNotice('')}}>Discard requested action</button>}{conflict&&<p role="alert">Revision conflict. Reload required before another save.</p>}{notice&&<p role="status">{notice}</p>}{error&&<p role="alert">{error}</p>}</section>
}

function RetentionPolicy({source,dataClass}){
 const mutate=useMutation(),editor=useEditor(),dirty=useRef(false),[confirmed,setConfirmed]=useState(null),[seconds,setSeconds]=useState(86400),[preview,setPreview]=useState(null),[run,setRun]=useState(''),[conflict,setConflict]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('')
 function invalidate(){setPreview(null);setRun('')}
 async function load(initial=false){
  if(!source||!dataClass||!editor.start())return;setError('')
  try{
   const r=await request(`/retention?source_id=${encodeURIComponent(source)}&data_class=${encodeURIComponent(dataClass)}`)
   if(!editor.alive.current)return
   if(confirmed?.revision!==r.data.revision)invalidate()
   setConfirmed(r.data);setConflict(false)
   if(initial&&!dirty.current&&r.data.present)setSeconds(r.data.retain_seconds)
   setNotice(initial?'':'Current retention policy loaded. Your draft is preserved; review before saving.')
  }catch(e){if(editor.alive.current)setError(e.message)}finally{editor.finish()}
 }
 useEffect(()=>{load(true)},[])
 async function perform(action){
  if(!confirmed||conflict||!editor.start())return;setError('');setNotice('')
  const body={source_id:source,data_class:dataClass,expected_revision:confirmed.revision,...(action==='policy'?{action,retain_seconds:seconds}:action==='preview'?{action:'run',dry_run:true}:action==='batch'?{action,run_id:run,limit:100}:{action})}
  try{
   const r=await mutate('/retention',body)
   if(!editor.alive.current)return
   if(action==='policy'){invalidate();setConfirmed({...confirmed,present:true,revision:r.data.revision,retain_seconds:seconds});setNotice('Retention policy saved.')}
   else if(action==='preview'){
    invalidate()
    if(r.data.policy_revision!==confirmed.revision){setConflict(true);setError('The preview found a changed policy. Reload the current retention policy before continuing.')}
    else setPreview(r.data)
   }else if(action==='run'){setRun(r.data.run_id);setNotice('Purge run created. Purging requires the next explicit batch action.')}
   else setNotice(JSON.stringify(r.data))
  }catch(e){if(editor.alive.current){if(e.code==='stale_revision'){invalidate();setConflict(true)}setError(e.message)}}finally{editor.finish()}
 }
 return <section aria-label="Retention policy"><p>Retention target: {source||'choose a source'} · {dataClass||'choose a class'}</p>{confirmed&&<p>Confirmed retention revision {confirmed.revision} · {confirmed.present?`Retention ${confirmed.retain_seconds} seconds`:'No policy exists for this source and class'}</p>}<label>Retention in seconds<input type="number" min="0" value={seconds} onChange={e=>{dirty.current=true;setSeconds(Number(e.target.value))}}/></label><p>Draft retention: {seconds} seconds</p><button disabled={editor.busy||!source||!dataClass} onClick={()=>load()}>Reload current retention policy</button><button disabled={editor.busy||!confirmed||conflict} onClick={()=>perform('policy')}>Save retention policy</button><button disabled={editor.busy||!confirmed?.present||conflict} onClick={()=>perform('preview')}>Preview without purging</button><button disabled={editor.busy||!confirmed?.present||conflict} onClick={()=>perform('run')}>Create purge run</button>{preview&&<p role="status">Preview: {preview.eligible} eligible · Policy revision {preview.policy_revision}</p>}<label>Resumable run UUID<input disabled={!confirmed?.present||editor.busy||conflict} value={run} onChange={e=>setRun(e.target.value)}/></label><button disabled={editor.busy||!run||!confirmed?.present||conflict} onClick={()=>perform('batch')}>Purge next batch of 100</button>{conflict&&<p role="alert">Revision conflict. Reload required before another save or purge.</p>}{notice&&<p role="status">{notice}</p>}{error&&<p role="alert">{error}</p>}</section>
}

export function OperationsSettings(){
 const mutate=useMutation(),[error,setError]=useState(''),[notice,setNotice]=useState(''),[source,setSource]=useState(''),[dataClass,setDataClass]=useState('private')
 async function permission(permission,granted){setError('');try{const r=await mutate('/permissions',{permission,granted});setNotice(JSON.stringify(r.data))}catch(e){setError(e.message)}}
 return <section><h2>Operations and separate permissions</h2><p>Pausing stops new work from starting and preserves the inbox, cursors, jobs, outbox and ledger.</p><RuntimeControl/><p>The following permissions authorize private operations separately; they require explicit operator confirmation.</p>{[['export','exports'],['discovery_authorize','discovery authorization'],['retention','retention']].map(([value,label])=><div key={value}><button onClick={()=>permission(value,true)}>Grant permission for {label}</button><button onClick={()=>permission(value,false)}>Revoke permission for {label}</button></div>)}<details><summary>Retention by source and class</summary><label>Source UUID<input value={source} onChange={e=>setSource(e.target.value)}/></label><label>Data class<input value={dataClass} onChange={e=>setDataClass(e.target.value)}/></label><RetentionPolicy key={JSON.stringify([source,dataClass])} source={source} dataClass={dataClass}/></details>{notice&&<p role="status">{notice}</p>}{error&&<p role="alert">{error}</p>}</section>
}
