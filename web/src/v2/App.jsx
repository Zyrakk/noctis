import React, { useEffect, useRef, useState } from 'react'
import { AuthProvider, useAuth } from './Auth.jsx'
import { request, evidenceParts, validEvidenceRef } from './api.js'
import { Claims, MissingActions, ExploreDomain, SourceDetails } from './product.jsx'
import { AIAction, TypedQuery } from './Consumers.jsx'
import AISettings from './AISettings.jsx'
import { Radar, SunMoon, Files, ScanSearch, Radio, Settings2, LogOut, ShieldCheck, ArrowUpRight, BookOpen } from 'lucide-react'
import './styles.css'
import './polish.css'
import {CaseActions,SourcePolicy,OperationsSettings,Paged,TelegramOnboarding} from './Operations.jsx'

function useLocation() {
  const [url,setURL] = useState(() => new URL(window.location.href))
  useEffect(() => { const pop = () => setURL(new URL(window.location.href)); window.addEventListener('popstate',pop); return () => window.removeEventListener('popstate',pop) },[])
  function navigate(to) { window.history.pushState({},'',to); setURL(new URL(window.location.href)) }
  return [url,navigate]
}
function useResource(path) {
  const [state,setState] = useState({path,loading:true})
  useEffect(() => { const controller=new AbortController(); setState({path,loading:true}); request(path,{signal:controller.signal}).then(result => {if(!controller.signal.aborted)setState({path,result})}).catch(error => {if(!controller.signal.aborted)setState({path,error})}); return () => controller.abort() },[path])
  return state.path===path?state:{path,loading:true}
}
function Link({to,navigate,children,...props}) { return <a href={to} onClick={e=>{if(!e.ctrlKey&&!e.metaKey&&!e.shiftKey){e.preventDefault();navigate(to)}}} {...props}>{children}</a> }
function Timestamp({value}) { const date=value?new Date(value):null;return date&&!Number.isNaN(date.getTime())?<time dateTime={value} title={value}>{new Intl.DateTimeFormat('es-ES',{dateStyle:'medium',timeStyle:'short'}).format(date)}</time>:<>{value||'desconocida'}</> }
function Status({state,children}) {
  if(state.loading) return <p role="status">Cargando datos…</p>
  if(state.error) return <p role="alert">No se pudieron cargar los datos: {state.error.message}</p>
  const meta=state.result.meta || {}
  return <><div className="v2-coverage"><span>Cobertura: {typeof meta.coverage === 'string' ? meta.coverage : 'desconocida'}</span>{meta.degraded && <strong> Servicio degradado · los datos pueden estar desactualizados</strong>}<span>Actualización: <Timestamp value={meta.generated_at}/></span></div>{children(state.result.data,meta)}</>
}
function Citations({items=[],select}) { return (Array.isArray(items)?items:[]).map((ref,i)=><button className="v2-citation" key={i} onClick={()=>select(ref)} aria-label={`Abrir evidencia ${i+1}`}>[{i+1}]</button>) }
function Evidence({reference,close,select}) {
  const closeButton=useRef(null)
  const dialog=useRef(null)
  useEffect(()=>{const previous=document.activeElement;dialog.current?.showModal();closeButton.current?.focus();return()=>{dialog.current?.close();if(previous?.isConnected)previous.focus()}},[])
  const state=useResource(`/evidence/${encodeURIComponent(reference.observation_id)}?revision=${encodeURIComponent(reference.revision)}`)
  return <dialog ref={dialog} className="v2-evidence" aria-label="Lector de evidencia" onCancel={e=>{e.preventDefault();close()}}><button ref={closeButton} onClick={close}>Cerrar evidencia</button><h2>Evidencia exacta</h2><Status state={state}>{data=>{
    let parts,error
    try { if(data.hash!==reference.hash || data.representation!==reference.representation || data.revision!==reference.revision || typeof data.text!=='string') throw new Error('La evidencia no coincide con la cita'); if(data.retention_status && data.retention_status!=='retained') throw new Error('El texto original ya no está disponible'); parts=evidenceParts(data.text,reference.start,reference.end) } catch(e){error=e.message}
    return <><dl><dt>Fuente</dt><dd>{data.source || 'Desconocida'}</dd><dt>Revisión</dt><dd>{reference.revision}</dd><dt>Hash exacto</dt><dd>{reference.hash}</dd><dt>Representación</dt><dd>{(data.representation==='original'||data.representation==='text/plain;utf8;v1')?`Original · ${data.representation}`:`${data.representation} · representación derivada, no original`}</dd><dt>Publicada / recogida</dt><dd>{data.published_at || 'Desconocida'} / {data.collected_at || 'Desconocida'}</dd><dt>Retención</dt><dd>{data.retention_status||'No declarada'}</dd></dl>{data.source_deleted&&<p role="alert">La fuente eliminó esta observación. El original retenido es histórico y no confirma la afirmación vigente.</p>}{data.superseded_by&&<p role="alert">Revisión sustituida por {data.superseded_by}. Esta cita conserva la revisión histórica.</p>}{error?<p role="alert">{error}</p>:<><pre>{parts[0]}<mark>{parts[1]}</mark>{parts[2]}</pre>{!data.source_deleted&&!data.superseded_by&&<AIAction functionID="evidence.translate" input={{kind:'observation',id:reference.observation_id,revision:reference.revision,language:'es'}} label="Traducir evidencia al español" select={select}/>}</>}</>
  }}</Status></dialog>
}
function Cases({url,navigate,select,explore=false}) {
  const query=url.searchParams.get('q')||''
  const filters=new URLSearchParams(url.search);filters.delete('evidence')
  const state=useResource(`/cases?${filters}`)
  return <><h1>{explore?'Explorar':'Expedientes'}</h1>{explore&&<p>Búsqueda en expedientes. Consulta tipada y grafo aún no disponibles.</p>}<form onSubmit={e=>{e.preventDefault();navigate(`${url.pathname}?q=${encodeURIComponent(new FormData(e.currentTarget).get('q'))}`)}} key={query}><label>Buscar <input name="q" defaultValue={query}/></label><button>Buscar</button></form><Status state={state}>{(data,meta)=><>{data.length===0?<p>No hay expedientes para esta consulta.</p>:<ul className="v2-rows">{data.map(item=><li key={item.id}><Link to={`/v2/cases/${encodeURIComponent(item.id)}`} navigate={navigate}>{item.title}</Link><p>{item.summary}</p><small>{item.status} · Revisión {item.revision}</small><Citations items={item.citations} select={select}/></li>)}</ul>}{meta.next_cursor&&<Link to={`${url.pathname}?${new URLSearchParams({q:query,cursor:meta.next_cursor})}`} navigate={navigate}>Siguiente página</Link>}</>}</Status></>
}
function Detail({id,select}) {
 const [refresh,setRefresh]=useState(0)
 const state=useResource(`/cases/${encodeURIComponent(id)}?refresh=${refresh}`)
 return <Status state={state}>{data=><>
  <h1>{data.title}</h1><p>{data.status} · Revisión {data.revision}</p>
  <div className="v2-change">Actualizado: {data.updated_at || 'desconocido'}{data.supersedes&&<span> · Sustituye revisión {data.supersedes}</span>}</div>
  <p>{data.summary}<Citations items={data.citations} select={select}/></p>
  {data.local_applicability&&<p>Aplicabilidad local: {data.local_applicability} · Exposición local: {data.local_exposure||'unknown'}</p>}
  {data.priority_reason&&<p>Motivo de prioridad: {data.priority_reason}</p>}
  <AIAction key={`summary-${id}-${data.revision}`} functionID="case.summarize" input={{kind:'case',id,revision:String(data.revision)}} label="Sintetizar expediente con IA" select={select}/>
  <AIAction key={`analyze-${id}-${data.revision}`} functionID="case.analyze" input={{kind:'case',id,revision:String(data.revision)}} label="Analizar expediente con IA" select={select}/>
  <CaseActions id={id} revision={data.revision} onChanged={()=>setRefresh(n=>n+1)}/><Claims id={id} select={select}/><h2>Cronología y procedencia</h2>
  <Paged path={`/cases/${id}/timeline`}>{events=>!events.length?<p>No hay eventos registrados.</p>:<ol className="v2-rows">{events.map(event=><li key={event.id}><strong>{event.title}</strong><p>{event.text||event.description}</p><small>{event.kind||'Cambio material'} · {event.created_at}</small>{event.invalidated&&<p role="alert">Derivado invalidado; requiere revisión</p>}<Citations items={event.citations||event.evidence} select={select}/></li>)}</ol>}</Paged>
 </>}</Status>
}
function Today({navigate,select}) {
 const state=useResource('/today')
 return <><div className="v2-page-intro"><h1>Hoy</h1><p>La jornada de inteligencia, desde sus fuentes.</p></div><Status state={state}>{data=><div className="v2-today-grid"><section className="v2-changes"><div className="v2-section-heading"><h2>Qué cambió</h2><Radio size={19} aria-hidden="true"/></div>{!data.changes?.length?<div className="v2-empty"><Radar size={38} strokeWidth={1.2} aria-hidden="true"/><h3>Sin cambios materiales</h3><p>No se observaron cambios materiales en las fuentes disponibles.</p><p className="v2-muted">La cobertura disponible delimita esta lectura. Consulta las fuentes antes de sacar conclusiones.</p><Link to="/v2/sources" navigate={navigate}>Revisar fuentes <ArrowUpRight size={15} aria-hidden="true"/></Link></div>:<ul className="v2-rows">{data.changes.map(change=><li key={change.id}><Link to={`/v2/cases/${encodeURIComponent(change.case_id)}`} navigate={navigate}>{change.title}</Link><p>{change.description}</p><small>{change.created_at}</small><Citations items={change.citations} select={select}/></li>)}</ul>}</section><section className="v2-brief"><div className="v2-section-heading"><h2>Brief</h2><BookOpen size={19} aria-hidden="true"/></div>{data.brief?<><p>{data.brief.text}<Citations items={data.brief.citations} select={select}/></p>{data.brief.status&&<p>Estado del brief: {data.brief.status}</p>}{data.brief.invalidated&&<p role="alert">Brief invalidado: {data.brief.invalidation_reason||'requiere revalidación'}</p>}{data.brief.current_for_alerts===false&&<p role="alert">Brief pendiente de revisión; no vigente para alertas.</p>}</>:<><p>Brief aún no disponible.</p><p className="v2-muted">Una síntesis con citas para volver siempre a la evidencia.</p></>}<AIAction functionID="brief.compose" input={{kind:'brief',period:new Date().toISOString().slice(0,10)}} label="Componer brief con IA" select={select}/></section></div>}</Status><aside className="v2-reading-note"><ShieldCheck size={19} aria-hidden="true"/><p>Una afirmación reportada no equivale a un incidente confirmado. Cada cita conserva su revisión y procedencia.</p></aside></>
}
function Sources({url,navigate,select}) {
 const state=useResource(`/sources?cursor=${encodeURIComponent(url.searchParams.get('source_cursor')||'')}`)
 return <><h1>Fuentes</h1><Status state={state}>{(data,meta)=><>{!data.length?<p>No hay fuentes configuradas.</p>:<ul className="v2-rows">{data.map(item=><li key={item.id}><strong>{item.name}</strong><p>Estado: {item.status} · Cobertura: {item.coverage || 'desconocida'}</p><p>Última captura: {item.last_success_at || 'desconocida'}</p>{item.last_error&&<p role="alert">{item.last_error}</p>}<SourcePolicy item={item}/><AIAction functionID="source.triage" input={{kind:'source',id:item.id}} label="Evaluar fuente con IA" select={select}/></li>)}</ul>}{meta.next_cursor&&<button onClick={()=>navigate(`/v2/sources?source_cursor=${encodeURIComponent(meta.next_cursor)}`)}>Siguiente página de fuentes</button>}</>}</Status><SourceDetails url={url} navigate={navigate}/></>
}
function System() {
 const state=useResource('/system')
 return <><h1>Sistema</h1><Status state={state}>{data=><><p>Estado: {data.status || 'desconocido'}</p><p>Trabajos pendientes: {data.backlog ?? 'desconocido'}</p><p>Trabajo más antiguo: {data.oldest_job_at || 'desconocido'}</p>{data.errors?.map((error,i)=><p role="alert" key={i}>{error}</p>)}<h2>Inteligencia artificial</h2><p>Estado del servicio: {data.ai?.status||'desconocido'}. La búsqueda y lectura no requieren inferencia.</p><AISettings/><h2>Progreso durable</h2><pre>{JSON.stringify(data.progress||{},null,2)}</pre><OperationsSettings/></>}</Status></>
}
function Routes() {
  const [url,navigate]=useLocation(), auth=useAuth(); const [error,setError]=useState('')
  const referenceText=url.searchParams.get('evidence')
  let reference
  try { const candidate=referenceText?JSON.parse(referenceText):null;reference=validEvidenceRef(candidate)?candidate:null } catch { /* malformed selection is visible below */ }
  function select(ref){const next=new URL(url);next.searchParams.set('evidence',JSON.stringify(ref));navigate(next.pathname+next.search)}
  function close(){const next=new URL(url);next.searchParams.delete('evidence');navigate(next.pathname+next.search)}
  const loginDestination=(url.pathname==='/v2'||url.pathname.startsWith('/v2/'))&&url.pathname!=='/v2/login'?url.pathname+url.search:'/v2/today'
  if(auth.loading) return <main className="v2"><p role="status">Comprobando sesión…</p></main>
  if(!auth.session) return <main className="v2 v2-login"><section className="v2-login-story"><Radar size={46} strokeWidth={1.25} aria-hidden="true"/><div className="v2-login-wordmark">Noctis</div><p>Del ruido a la evidencia.</p><span>Observatorio privado de inteligencia sobre amenazas</span><div className="v2-login-topics">Telegram / Vulnerabilidades / Ransomware / Filtraciones</div></section><section className="v2-login-panel"><h1>Noctis · Acceso privado</h1><p>Accede a tu mesa de investigación.</p>{auth.error&&<p role="alert">{auth.error}</p>}<form onSubmit={async e=>{e.preventDefault();const form=e.currentTarget;const values=new FormData(form);setError('');try{await auth.login(values.get('username'),values.get('password'));form.reset();navigate(loginDestination)}catch(e){setError(e.message)}}}><label>Usuario<input name="username" autoComplete="username" required/></label><label>Contraseña<input name="password" type="password" autoComplete="current-password" required/></label><button>Entrar</button>{error&&<p role="alert">{error}</p>}</form><p className="v2-login-security"><ShieldCheck size={16} aria-hidden="true"/> Sesión privada · acceso autorizado</p></section></main>
  let page
  if(url.pathname==='/v2' || url.pathname==='/v2/' || url.pathname==='/v2/today' || url.pathname==='/v2/login') page=<Today navigate={navigate} select={select}/>
  else if(url.pathname==='/v2/cases') page=<Cases url={url} navigate={navigate} select={select}/>
  else if(url.pathname==='/v2/explore') page=<ExploreDomain url={url} navigate={navigate} select={select} query={<TypedQuery url={url} navigate={navigate} select={select}/>}/>
  else if(url.pathname.startsWith('/v2/cases/')) { try { page=<Detail id={decodeURIComponent(url.pathname.slice(10))} select={select}/> } catch {page=<p role="alert">Ruta no válida.</p>} }
  else if(url.pathname==='/v2/sources') page=<><Sources url={url} navigate={navigate} select={select}/><TelegramOnboarding/></>
  else if(url.pathname==='/v2/system') page=<System/>
  else page=<h1>Página no encontrada</h1>
return <div className="v2 v2-shell"><header className="v2-shell-header"><div className="v2-shell-brand"><Radar size={29} strokeWidth={1.4} aria-hidden="true"/><strong>Noctis<small>Observatorio privado</small></strong></div><span className="v2-workspace-label">Mesa de investigación</span><span className="v2-user">{auth.session.user.username}</span><button className="v2-logout" onClick={async()=>{try{await auth.logout();navigate('/v2/login')}catch(e){setError(e.message)}}}><LogOut size={16} aria-hidden="true"/> Salir</button></header><aside className="v2-sidebar"><nav className="v2-main-nav" aria-label="Principal">{[['today','Hoy',SunMoon],['cases','Expedientes',Files],['explore','Explorar',ScanSearch],['sources','Fuentes',Radio],['system','Sistema',Settings2]].map(([path,label,Icon])=><Link key={path} to={`/v2/${path}`} navigate={navigate} aria-current={(url.pathname.startsWith(`/v2/${path}`)||(path==='today'&&['/v2','/v2/','/v2/login'].includes(url.pathname)))?'page':undefined}><Icon size={19} strokeWidth={1.7} aria-hidden="true"/>{label}</Link>)}</nav><div className="v2-sidebar-note"><ShieldCheck size={20} strokeWidth={1.5} aria-hidden="true"/><p>Evidencia antes<br/>de conclusiones.</p><small>Inteligencia con procedencia</small></div></aside><main className="v2-workspace">{error&&<p role="alert">{error}</p>}{referenceText&&!reference&&<p role="alert">Selección de evidencia no válida.</p>}{page}</main>{reference&&<Evidence key={referenceText} reference={reference} close={close} select={select}/>}</div>
}
export default function V2App(){return <AuthProvider><Routes/></AuthProvider>}
