import React, { useEffect, useRef, useState } from 'react'
import { Radar, ArrowUpLeft, ArrowUpRight, ArrowRight, ArrowDown, ChevronLeft, ChevronRight, SunMoon, Files, Network, Radio, SlidersHorizontal, Search, FileText, ShieldCheck, LockKeyhole, X, Quote, GitBranch, CircleHelp, BookOpen } from 'lucide-react'
import { stories, demoVersion } from './demo-data.js'
import './styles.css'
import './public.css'

export { demoVersion }
const views = [['today', 'Today', SunMoon], ['case', 'Case file', Files], ['explore', 'Relationships', Network], ['sources', 'Sources', Radio], ['system', 'AI controls', SlidersHorizontal]]
const statusLabels = { supported: 'Source-supported', reported: 'Reported', unresolved: 'Unresolved', contradicted: 'Contradicted' }
function readLocation() {
  const params = new URL(window.location.href).searchParams
  const story = Object.hasOwn(stories, params.get('story')) ? params.get('story') : 'B'
  const value = Number(params.get('step'))
  const step = Number.isFinite(value) ? Math.max(0, Math.min(2, Math.trunc(value))) : 0
  const area = views.some(([id]) => id === params.get('area')) ? params.get('area') : 'today'
  const available = stories[story].revisions[step].documentIds
  const requested = params.get('evidence')
  const evidence = requested === '1' ? available[0] : available.includes(requested) ? requested : null
  return { story, step, area, evidence, invalidEvidence: Boolean(requested && !evidence) }
}
function address(state) {
  const params = new URLSearchParams({ story: state.story, step: String(state.step) })
  if (state.area !== 'today') params.set('area', state.area)
  if (state.evidence) params.set('evidence', state.evidence)
  return `/demo?${params}`
}
function date(value) { return new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(new Date(value)) + ' UTC' }

function EvidenceReader({ document: record, close }) {
  const dialog = useRef(null), button = useRef(null)
  useEffect(() => {
    const element = dialog.current, previous = document.activeElement
    element.showModal(); button.current.focus()
    return () => {
      element.close()
      if (previous?.isConnected && previous !== document.body) previous.focus()
      else document.querySelector('[data-demo-heading]')?.focus()
    }
  }, [])
  const start = record.text.indexOf(record.highlight)
  return <dialog ref={dialog} className="demo-evidence" aria-label="Synthetic evidence" onCancel={event => { event.preventDefault(); close() }}>
    <header><span className="demo-overline"><FileText size={14} aria-hidden="true"/>SOURCE READER</span><button ref={button} onClick={close} className="demo-close" aria-label="Close synthetic evidence"><X size={18} aria-hidden="true"/></button></header>
    <p className="demo-synthetic-label">Authored synthetic record · No live source</p><h2>{record.title}</h2><p className="demo-reader-sub">Read the source before making the connection.</p>
    <dl><dt>Record</dt><dd>{record.id}</dd><dt>Source</dt><dd>{record.source}</dd><dt>Representation</dt><dd>Original synthetic text · Document revision {record.revision}</dd><dt>Published</dt><dd><time dateTime={record.publishedAt}>{date(record.publishedAt)}</time></dd><dt>Scenario availability</dt><dd>From revision {record.availableFrom + 1}</dd></dl>
    <div className="demo-reader-heading"><Quote size={16} aria-hidden="true"/><span>Original text</span><span>Relevant passage highlighted</span></div>
    <pre>{start < 0 ? record.text : <>{record.text.slice(0, start)}<mark>{record.highlight}</mark>{record.text.slice(start + record.highlight.length)}</>}</pre>
    <p className="demo-reader-note"><ShieldCheck size={16} aria-hidden="true"/>This is a demonstration record, not collected intelligence or a model-generated result.</p>
    <button className="demo-reader-done" onClick={close}>Return to the investigation<ArrowRight size={16} aria-hidden="true"/></button>
  </dialog>
}

export default function PublicProduct() {
  const [state, setState] = useState(readLocation)
  const [search, setSearch] = useState('')
  const story = stories[state.story], revision = story.revisions[state.step]
  const documents = story.documents.filter(document => revision.documentIds.includes(document.id) && document.availableFrom <= state.step)
  const selected = documents.find(document => document.id === state.evidence)
  useEffect(() => {
    const pop = () => setState(readLocation())
    window.addEventListener('popstate', pop)
    return () => window.removeEventListener('popstate', pop)
  }, [])
  useEffect(() => { if (window.location.pathname.startsWith('/demo')) history.replaceState({}, '', address(state)) }, [])
  function navigate(patch) {
    const next = { ...state, ...patch, invalidEvidence: false }
    if ((Object.hasOwn(patch, 'story') || Object.hasOwn(patch, 'step')) && !Object.hasOwn(patch, 'evidence')) next.evidence = null
    if (next.evidence && !stories[next.story].revisions[next.step].documentIds.includes(next.evidence)) next.evidence = null
    history.pushState({}, '', address(next)); setState(next)
  }
  const open = evidence => navigate({ evidence })
  const displayedStories = Object.values(stories).filter(item => `${item.title} ${item.category} ${item.shortTitle}`.toLowerCase().includes(search.toLowerCase()))
  return <div className="v2 v2-public n-demo" lang="en">
    <header className="demo-header"><a href="/" className="demo-brand" aria-label="Noctis, home"><Radar size={28} strokeWidth={1.35} aria-hidden="true"/><span>noctis</span></a><span className="demo-header-divider"/><span className="demo-header-caption">Interactive workspace</span><nav aria-label="Demo navigation"><a href="/" className="demo-home"><ArrowUpLeft size={14} aria-hidden="true"/>Overview</a><a className="demo-private" href="/v2/login"><LockKeyhole size={13} aria-hidden="true"/>Private access<ArrowUpRight size={14} aria-hidden="true"/></a></nav></header>
    <aside className="demo-disclosure" role="note"><span className="demo-disclosure-dot"/><strong>Synthetic data</strong><span className="demo-disclosure-detail">An authored walkthrough. No live collection, private data, or model calls.</span><span className="demo-version">{demoVersion}</span></aside>
    <div className="demo-workspace">
      <aside className="demo-sidebar" aria-label="Scenario library"><div className="demo-library-heading"><span>SCENARIO LIBRARY</span><span>03</span></div><div className="demo-search"><Search size={14} aria-hidden="true"/><input type="search" aria-label="Find a scenario" placeholder="Find a scenario" value={search} onChange={event => setSearch(event.target.value)}/></div>
        <nav className="demo-scenarios" aria-label="Synthetic scenarios">{displayedStories.map(item => <button key={item.id} aria-pressed={state.story === item.id} aria-label={`Scenario ${item.id} · ${item.title}`} onClick={() => navigate({ story: item.id, step: 0, evidence: null })}><span className="demo-scenario-letter">{item.id}</span><span><small>{item.category}</small><strong>{item.shortTitle}</strong></span><ChevronRight size={13} aria-hidden="true"/></button>)}</nav>{!displayedStories.length && <p className="demo-search-empty">No scenarios match. Try “source” or “inventory”.</p>}
        <div className="demo-sidebar-principle"><Radar size={26} strokeWidth={1} aria-hidden="true"/><p>A signal starts a question.<br/>Evidence guides the answer.</p><span>YOUR JUDGMENT FIRST</span></div><a className="demo-sidebar-link" href="/v2/login">Open your workspace<ArrowUpRight size={14} aria-hidden="true"/></a>
      </aside>
      <main className="demo-main"><div className="demo-breadcrumb"><span>Research workspace</span><ChevronRight size={11} aria-hidden="true"/><span>Case {state.story}</span><span className="demo-record-type">AUTHORED SCENARIO</span></div>
        <div className="demo-intro"><p className="demo-overline">{story.category}</p><h1 tabIndex={-1} data-demo-heading>{story.question}</h1><p>{story.title}. Follow the revisions. Inspect the original records.</p></div>
        <section className="demo-revisions" aria-label="Scenario revisions"><div className="demo-revision-top"><span>FOLLOW THE EVIDENCE</span><span>Revision {state.step + 1} of 3</span></div><ol>{story.revisions.map((snapshot, index) => <li key={index}><button aria-label={`Revision ${index + 1}`} aria-current={index === state.step ? 'step' : undefined} className={index < state.step ? 'reviewed' : ''} onClick={() => navigate({ step: index })}><span className="demo-step-number">0{index + 1}</span><span><strong>Revision {index + 1}</strong><small>{index <= state.step ? snapshot.title : 'Not reviewed yet'}</small></span>{index === state.step && <span className="demo-current-dot"/>}</button></li>)}</ol></section>
        <nav className="demo-views" aria-label="Workspace views">{views.map(([id, label, Icon]) => <button key={id} aria-pressed={state.area === id} onClick={() => navigate({ area: id })}><Icon size={15} strokeWidth={1.5} aria-hidden="true"/>{label}</button>)}</nav>
        {state.invalidEvidence && <p role="alert">This document is not available in the selected revision. <button onClick={() => navigate({ evidence: null })}>Clear selection</button></p>}
        <div className="demo-reading-grid"><div className="demo-primary-column">
          <section className="demo-change-card"><span className="demo-section-kicker"><GitBranch size={14} aria-hidden="true"/>What changed</span><h2>{revision.title}</h2><p>{revision.change}</p></section>
          {state.area === 'today' && <section className="demo-brief-card"><div className="demo-section-title"><h2>Research brief</h2><BookOpenIcon/></div><span className="demo-authored">Authored scenario summary · Not generated by a model</span><p className="demo-brief-text">{revision.summary}</p><div className="demo-takeaway"><CircleHelp size={17} aria-hidden="true"/><p>{revision.verdict}</p></div><button className="demo-text-action" onClick={() => navigate({ area: 'case' })}>Review the claims<ArrowRight size={15} aria-hidden="true"/></button></section>}
          {state.area === 'case' && <section className="demo-claims"><div className="demo-section-title"><h2>Claims under review</h2><span>{revision.claims.length} statements</span></div><p className="demo-section-description">Separate what the source says from what the evidence establishes.</p>{revision.claims.map((claim, index) => <article className="demo-claim" key={claim.id}><div className="demo-claim-top"><span className={`demo-status status-${claim.status}`}>{statusLabels[claim.status]}</span><span className="demo-claim-number">0{index + 1}</span></div><h3>{claim.title}</h3><p>{claim.detail}</p><div className="demo-claim-source"><span>Linked source</span>{claim.evidenceIds.map((id, sourceIndex) => <button className="v2-citation" key={id} aria-label={sourceIndex === 0 ? `Open synthetic evidence ${index + 1}` : `Open linked record ${id}`} onClick={() => open(id)}>[{documents.findIndex(document => document.id === id) + 1}]</button>)}</div></article>)}</section>}
          {state.area === 'explore' && <section className="demo-relations"><div className="demo-section-title"><h2>Connections, with context</h2><Network size={17} aria-hidden="true"/></div><p className="demo-section-description">A document trail, not an automatic identity or incident attribution.</p><div className="demo-document-flow">{documents.map((document, index) => <React.Fragment key={document.id}>{index > 0 && <span className="demo-flow-connector"><ArrowDown size={15} aria-hidden="true"/>{state.story === 'B' && index === 1 ? 'Dependent republications' : state.story === 'B' && index === 2 ? 'A separate, disputing statement' : 'Additional context to assess'}</span>}<button onClick={() => open(document.id)}><FileText size={20} strokeWidth={1.4} aria-hidden="true"/><span><small>{document.kind}</small><strong>{document.title}</strong></span><ArrowUpRight size={15} aria-hidden="true"/></button></React.Fragment>)}</div><div className="demo-takeaway"><CircleHelp size={17} aria-hidden="true"/><p>{revision.verdict}</p></div></section>}
          {state.area === 'sources' && <section className="demo-source-list"><div className="demo-section-title"><h2>Source records</h2><span>{documents.length} available</span></div><p className="demo-section-description">Only the records available in this revision are shown.</p>{documents.map(document => <article key={document.id}><div><span className="demo-overline">{document.kind}</span><h3>{document.title}</h3><p>{document.source}</p><blockquote>“{document.highlight}”</blockquote><time dateTime={document.publishedAt}>{date(document.publishedAt)}</time></div><button aria-label={`Inspect ${document.title}`} onClick={() => open(document.id)}><ArrowUpRight size={17} aria-hidden="true"/></button></article>)}</section>}
          {state.area === 'system' && <section className="demo-ai-controls"><div className="demo-section-title"><h2>Intelligence on your terms</h2><SlidersHorizontal size={17} aria-hidden="true"/></div><p className="demo-section-description">This walkthrough does not run models, store credentials, or contact a provider.</p><div className="demo-control-row"><span>AI in this demo</span><strong>Not running</strong></div><div className="demo-control-row"><span>Public scenario data</span><strong>Authored fixtures</strong></div><div className="demo-control-row"><span>Private API access</span><strong>None</strong></div><p className="demo-control-note">In your private workspace, AI is optional and configurable for each feature, with its own model, permissions, and limits. Search and evidence reading work without inference.</p><a className="demo-text-action" href="/v2/login">Go to private access<ArrowUpRight size={15} aria-hidden="true"/></a></section>}
        </div><aside className="demo-context" aria-label="Investigation context"><section className="demo-assessment"><span className="demo-overline">CURRENT ASSESSMENT</span><h2>What we can say</h2><p>{revision.verdict}</p><dl>{revision.facts.map(fact => <div key={fact.label}><dt>{fact.label}</dt><dd>{fact.value}</dd></div>)}</dl></section><section className="demo-evidence-index"><div className="demo-section-title"><h2>Evidence trail</h2><span>{documents.length.toString().padStart(2, '0')}</span></div>{documents.map((document, index) => <button key={document.id} aria-label={`Inspect ${document.title} from evidence trail`} onClick={() => open(document.id)}><span className="demo-document-index">0{index + 1}</span><span><strong>{document.title}</strong><small>Document revision {document.revision}</small></span><ArrowUpRight size={13} aria-hidden="true"/></button>)}<p>{revision.sourceSummary}</p></section><div className="demo-principle"><ShieldCheck size={17} strokeWidth={1.4} aria-hidden="true"/><p>{state.step === 2 ? story.limit : 'Only evidence available in this revision is shown. Later developments remain hidden.'}</p></div></aside></div>
        <div className="demo-revision-footer"><button disabled={state.step === 0} onClick={() => navigate({ step: state.step - 1 })}><ChevronLeft size={15} aria-hidden="true"/>Previous revision</button><span>Case {state.story} / revision 0{state.step + 1}</span><button disabled={state.step === 2} onClick={() => navigate({ step: state.step + 1 })}>Next revision<ChevronRight size={15} aria-hidden="true"/></button></div>
      </main>
    </div>
    <footer className="demo-footer"><span>NOCTIS / EVIDENCE BEFORE CONCLUSIONS</span><span>Synthetic research workspace · <a href="/">Back to the observatory<ArrowUpRight size={12} aria-hidden="true"/></a></span></footer>
    {selected && <EvidenceReader key={selected.id} document={selected} close={() => navigate({ evidence: null })}/>}
  </div>
}

function BookOpenIcon() { return <BookOpen size={17} strokeWidth={1.4} aria-hidden="true"/> }
