import React, { useEffect, useRef, useState } from 'react'
import { AuthProvider, useAuth } from './Auth.jsx'
import { request, evidenceParts, validEvidenceRef } from './api.js'
import { Claims, MissingActions, ExploreDomain, SourceDetails } from './product.jsx'
import { AIAction, TypedQuery } from './Consumers.jsx'
import AISettings from './AISettings.jsx'
import AIJobs from './AIJobs.jsx'
import LoginScreen from './LoginScreen.jsx'
import { Radar, SunMoon, Files, ScanSearch, Radio, Settings2, LogOut, ShieldCheck, ArrowUpRight, BookOpen } from 'lucide-react'
import './styles.css'
import './polish.css'
import {CaseActions,SourcePolicy,OperationsSettings,Paged,TelegramOnboarding} from './Operations.jsx'
import { Timestamp } from './Timestamp.jsx'

function useLocation() {
  const [url,setURL] = useState(() => new URL(window.location.href))
  useEffect(() => { const pop = () => setURL(new URL(window.location.href)); window.addEventListener('popstate',pop); return () => window.removeEventListener('popstate',pop) },[])
  function navigate(to) { window.history.pushState({},'',to); setURL(new URL(window.location.href)) }
  return [url,navigate]
}
function useResource(path) {
  const [attempt,setAttempt] = useState(0)
  const [state,setState] = useState({path,loading:true})
  useEffect(() => { const controller=new AbortController(); setState({path,loading:true}); request(path,{signal:controller.signal}).then(result => {if(!controller.signal.aborted)setState({path,result})}).catch(error => {if(!controller.signal.aborted)setState({path,error})}); return () => controller.abort() },[path,attempt])
  const current=state.path===path?state:{path,loading:true}
  return current.error?{...current,retry:()=>setAttempt(n=>n+1)}:current
}
function Link({to,navigate,children,...props}) { return <a href={to} onClick={e=>{if(!e.ctrlKey&&!e.metaKey&&!e.shiftKey){e.preventDefault();navigate(to)}}} {...props}>{children}</a> }
function Status({state,children}) {
  if(state.loading) return <p role="status">Loading data…</p>
  if(state.error) return <><p role="alert">Unable to load data: {state.error.message}</p>{state.retry&&<button type="button" onClick={state.retry}>Try again</button>}</>
  const meta=state.result.meta || {}
  return <><div className="v2-coverage"><span>Coverage: {typeof meta.coverage === 'string' ? meta.coverage : 'unknown'}</span>{meta.degraded && <strong> Degraded service · data may be out of date</strong>}<span>Updated: <Timestamp value={meta.generated_at}/></span></div>{children(state.result.data,meta)}</>
}
function Citations({items=[],select}) { return (Array.isArray(items)?items:[]).map((ref,i)=><button className="v2-citation" key={i} onClick={()=>select(ref)} aria-label={`Open evidence ${i+1}`}>[{i+1}]</button>) }
function Evidence({reference,close,select}) {
  const closeButton=useRef(null)
  const dialog=useRef(null)
  useEffect(()=>{const previous=document.activeElement;dialog.current?.showModal();closeButton.current?.focus();return()=>{dialog.current?.close();if(previous?.isConnected)previous.focus()}},[])
  const state=useResource(`/evidence/${encodeURIComponent(reference.observation_id)}?revision=${encodeURIComponent(reference.revision)}`)
  return <dialog ref={dialog} className="v2-evidence" aria-label="Evidence reader" onCancel={e=>{e.preventDefault();close()}}><button ref={closeButton} onClick={close}>Close evidence</button><h2>Exact evidence</h2><Status state={state}>{data=>{
    let parts,error
    try { if(data.hash!==reference.hash || data.representation!==reference.representation || data.revision!==reference.revision || typeof data.text!=='string') throw new Error('Evidence does not match the citation'); if(data.retention_status && data.retention_status!=='retained') throw new Error('The original text is no longer available'); parts=evidenceParts(data.text,reference.start,reference.end) } catch(e){error=e.message}
    return <><dl><dt>Source</dt><dd>{data.source || 'Unknown'}</dd><dt>Revision</dt><dd>{reference.revision}</dd><dt>Exact hash</dt><dd>{reference.hash}</dd><dt>Representation</dt><dd>{(data.representation==='original'||data.representation==='text/plain;utf8;v1')?`Original · ${data.representation}`:`${data.representation} · derived representation, not original`}</dd><dt>Published / collected</dt><dd><Timestamp value={data.published_at} fallback="Unknown"/> / <Timestamp value={data.collected_at} fallback="Unknown"/></dd><dt>Retention</dt><dd>{data.retention_status||'Not declared'}</dd></dl>{data.source_deleted&&<p role="alert">The source deleted this observation. The retained original is historical and does not confirm the current claim.</p>}{data.superseded_by&&<p role="alert">Revision superseded by {data.superseded_by}. This citation preserves the historical revision.</p>}{error?<p role="alert">{error}</p>:<><pre>{parts[0]}<mark>{parts[1]}</mark>{parts[2]}</pre>{!data.source_deleted&&!data.superseded_by&&<AIAction functionID="evidence.translate" input={{kind:'observation',id:reference.observation_id,revision:reference.revision,language:'en'}} label="Translate evidence to English" select={select}/>}</>}</>
  }}</Status></dialog>
}
function Cases({url,navigate,select,explore=false}) {
  const query=url.searchParams.get('q')||''
  const filters=new URLSearchParams(url.search);filters.delete('evidence')
  const state=useResource(`/cases?${filters}`)
  return <><h1>{explore?'Explore':'Case files'}</h1>{explore&&<p>Search case files. Typed queries and the graph are not yet available.</p>}<form onSubmit={e=>{e.preventDefault();navigate(`${url.pathname}?q=${encodeURIComponent(new FormData(e.currentTarget).get('q'))}`)}} key={query}><label>Search <input name="q" defaultValue={query}/></label><button>Search</button></form><Status state={state}>{(data,meta)=><>{data.length===0?<p>No case files match this query.</p>:<ul className="v2-rows">{data.map(item=><li key={item.id}><Link to={`/v2/cases/${encodeURIComponent(item.id)}`} navigate={navigate}>{item.title}</Link><p>{item.summary}</p><small>{item.status} · Revision {item.revision}</small><Citations items={item.citations} select={select}/></li>)}</ul>}{meta.next_cursor&&<Link to={`${url.pathname}?${new URLSearchParams({q:query,cursor:meta.next_cursor})}`} navigate={navigate}>Next page</Link>}</>}</Status></>
}
function Detail({id,select}) {
 const [refresh,setRefresh]=useState(0)
 const state=useResource(`/cases/${encodeURIComponent(id)}?refresh=${refresh}`)
 return <Status state={state}>{data=><>
  <h1>{data.title}</h1><p>{data.status} · Revision {data.revision}</p>
  <div className="v2-change">Updated: <Timestamp value={data.updated_at}/>{data.supersedes&&<span> · Supersedes revision {data.supersedes}</span>}</div>
  <p>{data.summary}<Citations items={data.citations} select={select}/></p>
  {data.local_applicability&&<p>Local applicability: {data.local_applicability} · Local exposure: {data.local_exposure||'unknown'}</p>}
  {data.priority_reason&&<p>Priority reason: {data.priority_reason}</p>}
  <AIAction key={`summary-${id}-${data.revision}`} functionID="case.summarize" input={{kind:'case',id,revision:String(data.revision)}} label="Summarize case file with AI" select={select}/>
  <AIAction key={`analyze-${id}-${data.revision}`} functionID="case.analyze" input={{kind:'case',id,revision:String(data.revision)}} label="Analyze case file with AI" select={select}/>
  <CaseActions id={id} revision={data.revision} onChanged={()=>setRefresh(n=>n+1)}/><Claims id={id} select={select}/><h2>Timeline and provenance</h2>
  <Paged path={`/cases/${id}/timeline`}>{events=>!events.length?<p>No events recorded.</p>:<ol className="v2-rows">{events.map(event=><li key={event.id}><strong>{event.title}</strong><p>{event.text||event.description}</p><small>{event.kind||'Material change'} · <Timestamp value={event.created_at}/></small>{event.invalidated&&<p role="alert">Derived content invalidated; review required</p>}<Citations items={event.citations||event.evidence} select={select}/></li>)}</ol>}</Paged>
 </>}</Status>
}
function Today({navigate,select}) {
 const state=useResource('/today')
 return <><div className="v2-page-intro"><h1>Today</h1><p>Your intelligence day, from the sources.</p></div><Status state={state}>{data=><div className="v2-today-grid"><section className="v2-changes"><div className="v2-section-heading"><h2>What changed</h2><Radio size={19} aria-hidden="true"/></div>{!data.changes?.length?<div className="v2-empty"><Radar size={38} strokeWidth={1.2} aria-hidden="true"/><h3>No material changes</h3><p>No material changes were observed in the available sources.</p><p className="v2-muted">Available coverage defines the scope of this view. Review the sources before drawing conclusions.</p><Link to="/v2/sources" navigate={navigate}>Review sources <ArrowUpRight size={15} aria-hidden="true"/></Link></div>:<ul className="v2-rows">{data.changes.map(change=><li key={change.id}><Link to={`/v2/cases/${encodeURIComponent(change.case_id)}`} navigate={navigate}>{change.title}</Link><p>{change.description}</p><small><Timestamp value={change.created_at}/></small><Citations items={change.citations} select={select}/></li>)}</ul>}</section><section className="v2-brief"><div className="v2-section-heading"><h2>Brief</h2><BookOpen size={19} aria-hidden="true"/></div>{data.brief?<><p>{data.brief.text}<Citations items={data.brief.citations} select={select}/></p>{data.brief.status&&<p>Brief status: {data.brief.status}</p>}{data.brief.invalidated&&<p role="alert">Brief invalidated: {data.brief.invalidation_reason||'revalidation required'}</p>}{data.brief.current_for_alerts===false&&<p role="alert">Brief awaiting review; not current for alerts.</p>}</>:<><p>Brief not yet available.</p><p className="v2-muted">A synthesis with citations that always lead back to the evidence.</p></>}<AIAction functionID="brief.compose" input={{kind:'brief',period:new Date().toISOString().slice(0,10)}} label="Compose brief with AI" select={select}/></section></div>}</Status><aside className="v2-reading-note"><ShieldCheck size={19} aria-hidden="true"/><p>A reported claim does not establish a confirmed incident. Each citation preserves its revision and provenance.</p></aside></>
}
function Sources({url,navigate,select}) {
 const path=`/sources?cursor=${encodeURIComponent(url.searchParams.get('source_cursor')||'')}`,state=useResource(path),[confirmed,setConfirmed]=useState({})
 async function reload(id){const result=await request(path),item=result.data.find(source=>source.id===id);if(!item)throw new Error('Source not found on the current page. Reload the source list.');return item}
 return <><h1>Sources</h1><Status state={state}>{(data,meta)=><>{!data.length?<p>No sources configured.</p>:<ul className="v2-rows">{data.map(source=>{const item=confirmed[source.id]||source;return <li key={item.id}><strong>{item.name}</strong><p>Status: {item.status} · Coverage: {item.coverage || 'unknown'}</p><p>Last capture: <Timestamp value={item.last_success_at}/></p>{item.last_error&&<p role="alert">{item.last_error}</p>}<SourcePolicy item={item} onReload={()=>reload(item.id)} onChanged={current=>setConfirmed(items=>({...items,[item.id]:current}))}/><AIAction functionID="source.triage" input={{kind:'source',id:item.id}} label="Assess source with AI" select={select}/></li>})}</ul>}{meta.next_cursor&&<button onClick={()=>navigate(`/v2/sources?source_cursor=${encodeURIComponent(meta.next_cursor)}`)}>Next page of sources</button>}</>}</Status><SourceDetails url={url} navigate={navigate}/></>
}
function System({url,navigate,select}) {
 const state=useResource('/system')
 return <><h1>System</h1><AIJobs url={url} navigate={navigate} select={select}/><Status state={state}>{data=><><p>Status: {data.status || 'unknown'}</p><p>Pending jobs: {data.backlog ?? 'unknown'}</p><p>Oldest job: <Timestamp value={data.oldest_job_at}/></p>{data.errors?.map((error,i)=><p role="alert" key={i}>{error}</p>)}<h2>Artificial intelligence</h2><p>Service status: {data.ai?.status||'unknown'}. Search and reading do not require inference.</p><AISettings/><h2>Durable progress</h2><pre>{JSON.stringify(data.progress||{},null,2)}</pre><OperationsSettings/></>}</Status></>
}
function Routes() {
  const [url,navigate]=useLocation(), auth=useAuth(); const [error,setError]=useState('')
  const referenceText=url.searchParams.get('evidence')
  let reference
  try { const candidate=referenceText?JSON.parse(referenceText):null;reference=validEvidenceRef(candidate)?candidate:null } catch { /* malformed selection is visible below */ }
  function select(ref){const next=new URL(url);next.searchParams.set('evidence',JSON.stringify(ref));navigate(next.pathname+next.search)}
  function close(){const next=new URL(url);next.searchParams.delete('evidence');navigate(next.pathname+next.search)}
  const loginDestination=(url.pathname==='/v2'||url.pathname.startsWith('/v2/'))&&url.pathname!=='/v2/login'?url.pathname+url.search+url.hash:'/v2/today'
  useEffect(() => { document.title = !auth.loading && !auth.session ? 'Sign in — Noctis' : 'Noctis — Research workspace' }, [auth.loading, auth.session])
  if(auth.loading) return <main className="v2"><p role="status">Checking session…</p></main>
  if(!auth.session) return <LoginScreen auth={auth} navigate={navigate} destination={loginDestination}/>
  let page
  if(url.pathname==='/v2' || url.pathname==='/v2/' || url.pathname==='/v2/today' || url.pathname==='/v2/login') page=<Today navigate={navigate} select={select}/>
  else if(url.pathname==='/v2/cases') page=<Cases url={url} navigate={navigate} select={select}/>
  else if(url.pathname==='/v2/explore') page=<ExploreDomain url={url} navigate={navigate} select={select} query={<TypedQuery url={url} navigate={navigate} select={select}/>}/>
  else if(url.pathname.startsWith('/v2/cases/')) { try { page=<Detail id={decodeURIComponent(url.pathname.slice(10))} select={select}/> } catch {page=<p role="alert">Invalid route.</p>} }
  else if(url.pathname==='/v2/sources') page=<><Sources url={url} navigate={navigate} select={select}/><TelegramOnboarding/></>
  else if(url.pathname==='/v2/system') page=<System url={url} navigate={navigate} select={select}/>
  else page=<h1>Page not found</h1>
return <div className="v2 v2-shell"><header className="v2-shell-header"><div className="v2-shell-brand"><Radar size={29} strokeWidth={1.4} aria-hidden="true"/><strong>Noctis<small>Private observatory</small></strong></div><span className="v2-workspace-label">Research workspace</span><span className="v2-user">{auth.session.user.username}</span><button className="v2-logout" onClick={async()=>{try{await auth.logout();navigate('/v2/login')}catch(e){setError(e.message)}}}><LogOut size={16} aria-hidden="true"/> Sign out</button></header><aside className="v2-sidebar"><nav className="v2-main-nav" aria-label="Main">{[['today','Today',SunMoon],['cases','Case files',Files],['explore','Explore',ScanSearch],['sources','Sources',Radio],['system','System',Settings2]].map(([path,label,Icon])=><Link key={path} to={`/v2/${path}`} navigate={navigate} aria-current={(url.pathname.startsWith(`/v2/${path}`)||(path==='today'&&['/v2','/v2/','/v2/login'].includes(url.pathname)))?'page':undefined}><Icon size={19} strokeWidth={1.7} aria-hidden="true"/>{label}</Link>)}</nav><div className="v2-sidebar-note"><ShieldCheck size={20} strokeWidth={1.5} aria-hidden="true"/><p>Evidence before<br/>conclusions.</p><small>Intelligence with provenance</small></div></aside><main className="v2-workspace">{error&&<p role="alert">{error}</p>}{referenceText&&!reference&&<p role="alert">Invalid evidence selection.</p>}{page}</main>{reference&&<Evidence key={referenceText} reference={reference} close={close} select={select}/>}</div>
}
export default function V2App(){return <AuthProvider><Routes/></AuthProvider>}
